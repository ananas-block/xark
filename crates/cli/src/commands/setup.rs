//! `xark setup` — generate Groth16 proving/verifying keys for a circuit.
//!
//! Reads the `r1cs.json` produced by `xark build` and runs either the insecure
//! dev-mode setup (`--insecure-dev-mode`) or the production phase-2 setup from a
//! Powers-of-Tau transcript (`--ptau-file`, or one auto-detected under
//! `target/xark/`). Keys land next to the build output as `pk.bin` / `vk.bin`.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use ark_serialize::Compress;
use xark_backend::keys::KeyMetadata;
use xark_backend::serialization::canonical_write_to_file;
use xark_ir::Visibility;
use xark_prover::XarkCircuit;

use super::{circuit_hash, load_backend_r1cs, num_public_inputs};
use crate::xark_project::XarkProject;

#[derive(Args, Debug)]
pub struct SetupArgs {
    /// Circuit crate directory (or its `target/xark/` output dir). Defaults to
    /// the current directory; paths are inferred from `target/xark/`.
    #[arg(value_hint = clap::ValueHint::DirPath)]
    pub path: Option<PathBuf>,

    /// Path to `r1cs.json`. Inferred from `target/xark/` when omitted.
    #[arg(long, value_hint = clap::ValueHint::FilePath)]
    pub r1cs: Option<PathBuf>,
    /// Output directory for keys and metadata. Inferred as `target/xark/`.
    #[arg(long, value_hint = clap::ValueHint::DirPath)]
    pub out: Option<PathBuf>,
    /// Required to run Groth16 setup with locally generated randomness.
    /// By default, the OS RNG drives the trapdoor sampling — still unsuitable
    /// for production (no ceremony, no transcript). **Do not use the resulting
    /// parameters in production.**
    #[arg(long, default_value_t = false)]
    pub insecure_dev_mode: bool,
    /// Reproducible-randomness escape hatch for test fixtures **only**.
    /// Requires `--insecure-dev-mode`. Drives setup with
    /// `ChaCha20Rng::seed_from_u64(<seed>)` so two runs with the same seed
    /// produce byte-identical keys. This trivially leaks the Groth16 trapdoor
    /// and must never be used beyond regenerating committed test fixtures.
    #[arg(long, value_name = "SEED")]
    pub deterministic_rng: Option<u64>,
    /// Production phase-2 setup from a Powers-of-Tau (`.ptau`) transcript.
    /// Mutually exclusive with `--insecure-dev-mode`. When neither is supplied,
    /// `setup` auto-detects a `.ptau` under `target/xark/`, `target/xark/ptau/`,
    /// the crate root, or `<root>/ptau/`.
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    pub ptau_file: Option<PathBuf>,
    /// 32-byte randomness seed (hex) for the phase-2 `(γ, δ)` derivation.
    /// Optional — auto-generated via OS RNG when not supplied.
    #[arg(long, value_name = "HEX")]
    pub phase2_seed: Option<String>,
    /// Cache the minimized R1CS (`r1cs.min.wcz`, the exact circuit this key is
    /// generated from) next to the keys, so a later `xark prove` reloads it
    /// instead of re-deriving it — skipping the minimize + `validate()` (~25s on
    /// a multi-million-constraint circuit). Off by default: the cache can be large
    /// (hundreds of MB) and only pays off when you prove against this key. Best
    /// for the produce-many-proofs / production flow.
    #[arg(long, default_value_t = false)]
    pub cache: bool,

    /// Write the proving key UNCOMPRESSED (2× on disk) so `xark prove` skips the
    /// per-point square-root decompression on load — a large prove-time win (the
    /// decompress is ~half of prove). Default is compressed (smaller on disk /
    /// bandwidth). `xark prove` auto-detects which format the key is in.
    #[arg(long, default_value_t = false)]
    pub uncompressed: bool,

    /// Which R1CS form to generate the key for. Both prove with the streaming
    /// prover; they differ in where the rows come from.
    ///
    /// * `reduced` — the template-reduced circuit, streamed straight from
    ///   `circuit.xbc` (no extra artifact; setup skips the global minimize pass).
    /// * `minimized` — the boundary-minimized circuit (a few % smaller on some
    ///   circuits); setup also writes `r1cs.stream`, which prove streams.
    /// * `auto` (default) — `reduced` at or above 2^20 constraints, where the global
    ///   minimize costs GBs of setup memory for ~0% gain (Ed25519: 576 of 2.36M
    ///   rows); below that, `minimized` only if it shrinks the FFT domain or saves
    ///   ≥ 1% of rows or variables (sha256: 4.9%), else `reduced`.
    #[arg(long, value_enum, default_value_t = R1csForm::Auto)]
    pub r1cs_form: R1csForm,

    /// Shorthand for `--r1cs-form reduced`.
    #[arg(long, default_value_t = false, conflicts_with = "r1cs_form")]
    pub streamable: bool,

    /// QAP evaluation domain.
    ///
    /// * `smooth` — the smallest of `2^k`, `3·2^k`, `9·2^k` points. A circuit just
    ///   past a power of two gets a domain up to 44% smaller, so a smaller key and
    ///   a faster quotient FFT and `H` MSM (Ed25519: 4.19M → 2.36M points). The
    ///   verifier is unchanged, but only xark's provers (`xark prove`, xark-wasm)
    ///   can prove against the key — not snarkjs or rapidsnark. Dev-mode only: a
    ///   Powers-of-Tau transcript's Lagrange bases are radix-2.
    /// * `radix2` — `2^k` points, what every Groth16 prover expects.
    /// * `auto` (default) — `smooth`, except `radix2` for a Powers-of-Tau setup or
    ///   an explicit `--r1cs` program (whose proofs use the arkworks prover).
    #[arg(long, value_enum, default_value_t = QapDomain::Auto)]
    pub domain: QapDomain,
}

/// See [`SetupArgs::domain`].
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum QapDomain {
    Auto,
    Radix2,
    Smooth,
}

impl QapDomain {
    /// The concrete domain kind for a setup with/without a `.ptau` and an
    /// explicit `--r1cs` program.
    fn resolve(self, ptau: bool, explicit_r1cs: bool) -> xark_groth16::DomainKind {
        match self {
            QapDomain::Smooth => xark_groth16::DomainKind::Smooth,
            QapDomain::Auto if !ptau && !explicit_r1cs => xark_groth16::DomainKind::Smooth,
            _ => xark_groth16::DomainKind::Radix2,
        }
    }
}

/// See [`SetupArgs::r1cs_form`].
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum R1csForm {
    Auto,
    Reduced,
    Minimized,
}

/// `auto` always picks `reduced` at or above this many (template-reduced) rows.
pub const AUTO_REDUCED_ROWS: usize = 1 << 20;
/// Below it, `minimized` must save at least this fraction of rows or variables.
const AUTO_MIN_SAVING: f64 = 0.01;

/// Wrapper RNG threading `CryptoRng + RngCore` through both the OS RNG path and
/// the deterministic test-fixture path. `setup` requires `CryptoRng` (a marker
/// trait) which trait objects can't carry, so an explicit enum is simplest.
#[allow(clippy::large_enum_variant)]
enum SetupRng {
    Det(ChaCha20Rng),
    Os(OsRng),
}

impl RngCore for SetupRng {
    fn next_u32(&mut self) -> u32 {
        match self {
            SetupRng::Det(r) => r.next_u32(),
            SetupRng::Os(r) => r.next_u32(),
        }
    }
    fn next_u64(&mut self) -> u64 {
        match self {
            SetupRng::Det(r) => r.next_u64(),
            SetupRng::Os(r) => r.next_u64(),
        }
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        match self {
            SetupRng::Det(r) => r.fill_bytes(dest),
            SetupRng::Os(r) => r.fill_bytes(dest),
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        match self {
            SetupRng::Det(r) => r.try_fill_bytes(dest),
            SetupRng::Os(r) => r.try_fill_bytes(dest),
        }
    }
}

impl CryptoRng for SetupRng {}

/// Cache the minimized R1CS (tagged with the source `circuit.xbc` fingerprint)
/// next to the keys, so `xark prove` can reload it and skip re-running the
/// identical boundary-minimize + `validate()`. Best-effort: a write failure just
/// forfeits the speedup (prove falls back to recomputing).
fn write_r1cs_cache(
    out_dir: &std::path::Path,
    fingerprint: &str,
    circuit: &XarkCircuit,
    prof: bool,
) {
    let t = std::time::Instant::now();
    let bytes = match xark_ir::r1cs_cache::serialize(fingerprint, circuit.prog()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("warning: could not encode R1CS cache: {e}");
            return;
        }
    };
    let path = out_dir.join("r1cs.min.wcz");
    if let Err(e) = fs::write(&path, &bytes) {
        eprintln!(
            "warning: could not write R1CS cache {}: {e}",
            path.display()
        );
        return;
    }
    if prof {
        eprintln!(
            "SETUP_TIME: write r1cs cache      = {:.2}s ({} bytes)",
            t.elapsed().as_secs_f64(),
            bytes.len()
        );
    }
}

/// The circuit the key is generated for, the form's metadata name, and why.
/// `prog` is the template-reduced R1CS (or an explicit `--r1cs` program, which has
/// no bytecode to stream and is always minimized).
fn keyed_circuit(
    prog: &xark_ir::R1csProgram,
    form: R1csForm,
    explicit_r1cs: bool,
    kind: xark_groth16::DomainKind,
) -> (XarkCircuit, &'static str, String) {
    let domain =
        |p: &xark_ir::R1csProgram| kind.size(p.constraints.len() + num_public_inputs(p) + 1);
    let reduced = || XarkCircuit::for_setup_preminimized(prog.clone());
    match form {
        _ if explicit_r1cs => (
            XarkCircuit::for_setup(prog.clone()),
            "minimized",
            "explicit --r1cs program".into(),
        ),
        R1csForm::Reduced => (reduced(), "reduced", "requested".into()),
        R1csForm::Minimized => (
            XarkCircuit::for_setup(prog.clone()),
            "minimized",
            "requested".into(),
        ),
        R1csForm::Auto if prog.constraints.len() >= AUTO_REDUCED_ROWS => (
            reduced(),
            "reduced",
            format!(
                "{} constraints ≥ 2^20: the global minimize isn't worth its setup memory",
                prog.constraints.len()
            ),
        ),
        R1csForm::Auto => {
            let min = XarkCircuit::for_setup(prog.clone());
            let (r, m) = (prog, min.prog());
            let saved = |a: usize, b: usize| 1.0 - b as f64 / a.max(1) as f64;
            let rows = saved(r.constraints.len(), m.constraints.len());
            let vars = saved(r.variables.len(), m.variables.len());
            let smaller_domain = domain(m) < domain(r);
            let why = format!(
                "minimize saves {:.1}% rows, {:.1}% variables{}",
                rows * 100.0,
                vars * 100.0,
                if smaller_domain {
                    ", shrinks the FFT domain"
                } else {
                    ""
                }
            );
            if smaller_domain || rows.max(vars) >= AUTO_MIN_SAVING {
                (min, "minimized", why)
            } else {
                (reduced(), "reduced", why)
            }
        }
    }
}

/// Write `r1cs.stream` (the keyed circuit, row-file encoded) for a `minimized`
/// key, so prove can stream it. Best-effort, like the cache.
fn write_row_file(out_dir: &std::path::Path, fingerprint: &str, circuit: &XarkCircuit) {
    let bytes = xark_ir::r1cs_stream::encode(fingerprint, circuit.prog());
    let path = out_dir.join("r1cs.stream");
    match fs::write(&path, &bytes) {
        Ok(()) => println!("Wrote {}", path.display()),
        Err(e) => eprintln!("warning: could not write {}: {e}", path.display()),
    }
}

/// The circuit the key is generated for, as a row source.
enum Keyed {
    /// The template-reduced rows, streamed straight from `circuit.xbc`.
    Bytecode(xark_groth16::BytecodeSource),
    /// The boundary-minimized program (small circuits, or an explicit `--r1cs`).
    Program(XarkCircuit),
}

impl Keyed {
    fn with_source<T>(&self, f: impl FnOnce(&dyn xark_groth16::ConstraintSource) -> T) -> T {
        match self {
            Keyed::Bytecode(src) => f(src),
            Keyed::Program(circ) => f(&xark_groth16::ProgramSource::new(circ.prog())),
        }
    }
}

/// Decide the key form and build its row source. The bytecode's row count picks
/// `reduced` for large circuits without ever expanding them; only a candidate for
/// `minimized` (or an explicit `--r1cs` program) is materialized, for the minimize
/// pass. Returns `(source, form, reason, fingerprint, reduced rows, public inputs,
/// QAP domain kind)`.
#[allow(clippy::type_complexity)]
fn plan_keyed(
    args: &SetupArgs,
    project: &XarkProject,
    r1cs_path: &std::path::Path,
    form: R1csForm,
    ptau: bool,
) -> Result<(
    Keyed,
    &'static str,
    String,
    String,
    usize,
    usize,
    xark_groth16::DomainKind,
)> {
    let xbc = project.circuit_xbc();
    let flat = super::dbg_flag("XARK_FLAT_MINIMIZE") || super::dbg_flag("XARK_NO_MINIMIZE");
    if args.r1cs.is_none() && xbc.exists() && !flat {
        let kind = args.domain.resolve(ptau, false);
        let bytes = fs::read(&xbc).with_context(|| format!("reading {}", xbc.display()))?;
        if !super::is_function_artifact(&bytes) {
            bail!(
                "{} is not a current circuit artifact — rebuild with `xark build`",
                xbc.display()
            );
        }
        let hash = super::sha256_hex(&bytes);
        let src = xark_groth16::BytecodeSource::new(&bytes).map_err(|e| anyhow::anyhow!(e))?;
        let rows = xark_groth16::ConstraintSource::num_constraints(&src);
        let num_pi = xark_groth16::ConstraintSource::layout(&src).num_instance() - 1;
        let reduced = |why: String| {
            Ok((
                Keyed::Bytecode(src),
                "reduced",
                why,
                hash.clone(),
                rows,
                num_pi,
                kind,
            ))
        };
        return match form {
            R1csForm::Reduced => reduced("requested".into()),
            R1csForm::Auto if rows >= AUTO_REDUCED_ROWS => reduced(format!(
                "{rows} constraints ≥ 2^20: the global minimize isn't worth its setup memory"
            )),
            _ => {
                let prog = xark_ir::function_decode::expand_function_blob_reduced(&bytes)
                    .map_err(|e| anyhow::anyhow!(e))?
                    .into_r1cs();
                let (circuit, name, why) = keyed_circuit(&prog, form, false, kind);
                if name == "reduced" {
                    reduced(why)
                } else {
                    Ok((Keyed::Program(circuit), name, why, hash, rows, num_pi, kind))
                }
            }
        };
    }
    // An explicit `--r1cs` program (or a debug flat build): materialized.
    let (prog, hash) = load_backend_r1cs(&xbc, args.r1cs.as_deref(), r1cs_path)?;
    let (rows, num_pi) = (prog.constraints.len(), num_public_inputs(&prog));
    let kind = args.domain.resolve(ptau, true);
    let (circuit, name, why) = keyed_circuit(&prog, form, true, kind);
    Ok((Keyed::Program(circuit), name, why, hash, rows, num_pi, kind))
}

pub fn run(args: SetupArgs) -> Result<()> {
    let project = XarkProject::resolve(args.path.clone())?;
    let r1cs_path = args.r1cs.clone().unwrap_or_else(|| project.r1cs_json());
    let out_dir = args.out.clone().unwrap_or_else(|| project.xark_dir.clone());
    let prof = super::dbg_flag("XARK_BUILD_TIME");
    let form = if args.streamable {
        R1csForm::Reduced
    } else {
        args.r1cs_form
    };

    // Resolve the ptau path: explicit flag, or auto-detected when neither
    // --ptau-file nor --insecure-dev-mode is supplied.
    let ptau_path: Option<PathBuf> = if args.ptau_file.is_some() {
        args.ptau_file.clone()
    } else if !args.insecure_dev_mode {
        project.find_ptau()
    } else {
        None
    };
    // Only an *explicit* `--ptau-file` conflicts with `--insecure-dev-mode`
    // (auto-detection is skipped when `--insecure-dev-mode` is set, so any
    // `ptau_path` here under that flag came from `--ptau-file`).
    if ptau_path.is_some() && args.insecure_dev_mode {
        bail!(
            "--ptau-file (or auto-detected .ptau) and --insecure-dev-mode are mutually exclusive"
        );
    }
    // `--deterministic-rng` leaks the trapdoor, so require `--insecure-dev-mode`
    if ptau_path.is_some() && args.domain == QapDomain::Smooth {
        bail!(
            "--domain smooth is dev-mode only: a Powers-of-Tau transcript's Lagrange bases \
             are for 2^k domains (use --insecure-dev-mode, or --domain radix2)"
        );
    }
    if args.deterministic_rng.is_some() && !args.insecure_dev_mode {
        bail!("--deterministic-rng requires --insecure-dev-mode");
    }
    // No `.ptau` and no explicit `--insecure-dev-mode`: fall back to insecure
    // dev-mode so the common `xark build && xark setup && xark prove` loop just
    // works. A real `--ptau-file` still runs production phase-2.
    let dev_fallback = ptau_path.is_none() && !args.insecure_dev_mode;

    let t_load = std::time::Instant::now();
    let (keyed, form_name, why, hash, num_constraints, num_pi, kind) =
        plan_keyed(&args, &project, &r1cs_path, form, ptau_path.is_some())?;
    println!("R1CS form: {form_name} ({why})");
    if prof {
        eprintln!(
            "SETUP_TIME: load+plan           = {:.2}s",
            t_load.elapsed().as_secs_f64()
        );
    }

    fs::create_dir_all(&out_dir)
        .with_context(|| format!("creating output dir {}", out_dir.display()))?;
    let pk_path = out_dir.join("pk.bin");
    let vk_path = out_dir.join("vk.bin");
    let meta_path = out_dir.join("metadata.json");

    if let Keyed::Program(circuit) = &keyed {
        circuit
            .validate()
            .map_err(|e| anyhow::anyhow!("malformed circuit: {e}"))?;
        write_row_file(&out_dir, &hash, circuit);
        if args.cache {
            write_r1cs_cache(&out_dir, &hash, circuit, prof);
        }
    }
    let compress = if args.uncompressed {
        Compress::No
    } else {
        Compress::Yes
    };
    let pk_out = || -> Result<std::io::BufWriter<fs::File>> {
        let f = fs::File::create(&pk_path)
            .with_context(|| format!("creating {}", pk_path.display()))?;
        Ok(std::io::BufWriter::with_capacity(1 << 20, f))
    };
    let mut metadata = KeyMetadata::new_dev(hash, num_pi, num_constraints);
    metadata.r1cs_form = Some(form_name.to_string());
    let rows = keyed.with_source(|src| src.num_constraints() + src.layout().num_instance());
    let domain_size = kind.size(rows);
    metadata.qap_domain_size = Some(domain_size);
    if kind == xark_groth16::DomainKind::Smooth {
        let radix2 = xark_groth16::DomainKind::Radix2.size(rows);
        println!(
            "QAP domain: {domain_size} points (radix-2 would be {radix2}); only xark's provers \
             can prove against this key (`--domain radix2` for snarkjs / rapidsnark)"
        );
    }

    // Keys are generated from the streamed rows and written vector by vector:
    // neither the constraint system nor the proving key is ever held whole.
    let t_keygen = std::time::Instant::now();
    let vk = if let Some(ref ptau_file) = ptau_path {
        // Production phase-2 path.
        let phase2_seed_hex = match &args.phase2_seed {
            Some(s) => s.clone(),
            None => {
                let mut bytes = [0u8; 32];
                OsRng.fill_bytes(&mut bytes);
                hex::encode(bytes)
            }
        };
        let seed_bytes = hex::decode(phase2_seed_hex.trim_start_matches("0x"))
            .context("decoding --phase2-seed as hex")?;
        if seed_bytes.len() != 32 {
            bail!(
                "--phase2-seed must be exactly 32 bytes (got {} bytes)",
                seed_bytes.len()
            );
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed_bytes);
        let ptau_bytes =
            fs::read(ptau_file).with_context(|| format!("reading {}", ptau_file.display()))?;
        let ptau = xark_backend::ptau::parse_ptau(&ptau_bytes).context("parsing .ptau file")?;
        drop(ptau_bytes);
        let vk = keyed.with_source(|src| -> Result<_> {
            xark_backend::ptau::validate_for_circuit(
                &ptau,
                src.num_constraints(),
                src.layout().num_instance(),
            )
            .map_err(|e| anyhow::anyhow!("phase-2 setup failed: {e}"))?;
            let powers = xark_groth16::setup::PtauPowers {
                tau_g1: &ptau.tau_g1,
                tau_g2: &ptau.tau_g2,
                alpha_tau_g1: &ptau.alpha_tau_g1,
                beta_tau_g1: &ptau.beta_tau_g1,
                beta_g2: ptau.beta_g2,
            };
            xark_groth16::setup::phase2_setup(src, &powers, &seed_arr, pk_out()?, compress)
                .map_err(|e| anyhow::anyhow!("phase-2 setup failed: {e}"))
        })?;
        metadata.setup_mode = "phase2-from-ptau".into();
        metadata.production_safe = true;
        // commit to the (to-be-discarded) phase-2 seed for audit; never keep the seed
        metadata.phase2_seed_hash = Some(circuit_hash(&phase2_seed_hex));
        metadata.ptau_source = ptau_file
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string());
        vk
    } else {
        // Dev-mode path. Only explicit `--deterministic-rng <n>` makes the key
        // reproducible; the no-`.ptau` fallback uses OsRng (a fixed seed would make
        // every dev key byte-identical with a known trapdoor).
        let mut rng = match args.deterministic_rng {
            Some(seed) => {
                eprintln!(
                    "WARN: --deterministic-rng makes the Groth16 trapdoor recoverable from the \
                     seed; do not reuse the resulting keys outside test fixtures."
                );
                SetupRng::Det(ChaCha20Rng::seed_from_u64(seed))
            }
            None => SetupRng::Os(OsRng),
        };
        metadata.deterministic_rng_seed = args.deterministic_rng;
        keyed.with_source(|src| -> Result<_> {
            xark_groth16::setup::dev_setup(src, &mut rng, pk_out()?, compress, kind)
                .map_err(|e| anyhow::anyhow!("setup failed: {e}"))
        })?
    };
    if prof {
        eprintln!(
            "SETUP_TIME: keygen+write        = {:.2}s",
            t_keygen.elapsed().as_secs_f64()
        );
    }
    drop(keyed);

    canonical_write_to_file(&vk, &vk_path)?;
    fs::write(&meta_path, serde_json::to_string_pretty(&metadata)?)
        .with_context(|| format!("writing {}", meta_path.display()))?;

    println!("Wrote {}", pk_path.display());
    println!("Wrote {}", vk_path.display());
    println!("Wrote {}", meta_path.display());
    if ptau_path.is_some() {
        println!(
            "{}",
            crate::style::warn(
                "\nphase2-from-ptau setup complete — but this was a SINGLE-PARTY phase-2 \
                 contribution. Whoever holds the phase-2 seed knows the γ/δ trapdoor and can \
                 forge proofs for this circuit. For production you MUST now securely DISCARD the \
                 seed (only its hash is recorded, in metadata.phase2_seed_hash), and the .ptau \
                 must itself come from a real multi-party phase-1 ceremony. For a fully \
                 trustless phase-2, use the multi-party `xark ceremony` flow instead."
            )
        );
    } else {
        println!(
            "\n{}",
            crate::style::warn(
                "⚠️  WARNING: setup_mode = insecure-dev-mode. Do not use in production."
            )
        );
        if dev_fallback {
            println!(
                "{}",
                crate::style::warn(
                    "note: no .ptau found — generated an insecure single-party OsRng dev key; \
                     supply --ptau-file for production."
                )
            );
        }
    }
    print_next_steps(&project, &args.path, &r1cs_path);
    Ok(())
}

fn print_next_steps(project: &XarkProject, path: &Option<PathBuf>, r1cs_path: &std::path::Path) {
    // Only the *declared* inputs — never the witnesses the solver derives (e.g.
    // `to_bits` range-check bits). `circuit.xbc`'s header lists them, in order, so
    // nothing is expanded; a JSON-only build falls back to the R1CS's non-internal
    // variables (declared inputs come first and in order, so it's still usable).
    let names: Vec<String> = match fs::read(project.circuit_xbc()) {
        Ok(bytes) if super::is_function_artifact(&bytes) => {
            xark_ir::function_decode::decode_input_vars(&bytes)
                .into_iter()
                .map(|v| v.name)
                .collect()
        }
        _ => fs::read_to_string(r1cs_path)
            .ok()
            .and_then(|s| xark_ir::json::from_json(&s).ok())
            .map(|prog: xark_ir::R1csProgram| {
                let mut vars: Vec<_> = prog
                    .variables
                    .into_iter()
                    .filter(|v| v.visibility != Visibility::Internal)
                    .collect();
                vars.sort_by_key(|v| v.id);
                vars.into_iter().map(|v| v.name).collect()
            })
            .unwrap_or_default(),
    };
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let hint = super::inputs_hint(&name_refs);
    let p = super::path_arg(path);
    println!(
        "\n{}",
        crate::style::next_steps(&[(
            format!("xark prove {p} {hint}"),
            "solve the witness and produce a proof",
        )])
    );
}
