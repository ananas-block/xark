//! `xark` frontend subcommands: `init` (scaffold), `build` (Rust → wasm32 →
//! R1CS), `test` and `check` (editor-facing validation). The backend subcommands
//! (`setup`/`prove`/`verify`/`export`/`ceremony`/`inspect`) live in the
//! [`crate::commands`] module; these keep their hand-rolled argument parsing
//! (driven from the clap layer in `commands`).

use std::path::PathBuf;
use std::process::Command;

/// `xark build <crate-dir> [--out DIR] [--field F]`
///
/// Builds the circuit crate for wasm32 with `cargo` (any stable toolchain), then
/// lowers the module with `xark-frontend`.
pub fn cmd_build(args: &[String]) -> i32 {
    cmd_build_impl(args, false)
}

/// Like [`cmd_build`], but injects `--profile` so the extractor additionally
/// writes `profile.json` (per-constraint source/function/kind attribution). Used
/// by `xark profile`; a normal `xark build` never emits it.
pub fn cmd_build_profile(args: &[String]) -> i32 {
    cmd_build_impl(args, true)
}

fn cmd_build_impl(args: &[String], profile: bool) -> i32 {
    let mut crate_dir: Option<String> = None;
    let mut out: Option<String> = None;
    let mut field = "bn254".to_string();
    // `--emit-json`: also write the human-readable `circuit.json`. Off by default;
    // the prover/checker load `circuit.xbc`, so a normal build skips the (multi-GB
    // on large circuits) JSON serialization.
    let mut emit_json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = it.next().cloned(),
            "--field" => {
                if let Some(f) = it.next() {
                    field = f.clone();
                }
            }
            "--emit-json" => emit_json = true,
            _ if crate_dir.is_none() => crate_dir = Some(a.clone()),
            _ => {}
        }
    }
    let Some(crate_dir) = crate_dir else {
        eprintln!("error: `xark build <crate-dir>` requires a crate directory");
        return 2;
    };
    let crate_dir = PathBuf::from(crate_dir);
    let name = crate_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("circuit")
        .to_string();
    let cwd = std::env::current_dir().expect("cwd");
    let crate_abs = cwd.join(&crate_dir);
    // xark's artifacts live under the crate's `target/xark/`, and the wasm32 /
    // `--cfg xark` build cache under `target/xark-wasm/` — both apart from the
    // crate's normal `target/` so they don't thrash the one `cargo` and
    // rust-analyzer use. Each circuit's artifacts land in a name-scoped
    // `target/xark/<pkg-name>/`, the package name from `Cargo.toml`
    // (`[package] name`) falling back to the directory name.
    let xark_dir = crate_abs.join("target/xark");
    let pkg_name = crate::xark_project::read_pkg_name(&crate_abs).unwrap_or_else(|| name.clone());
    let out_abs = out
        .map(|o| cwd.join(o))
        .unwrap_or_else(|| xark_dir.join(&pkg_name));

    build_stable(
        &crate_abs, &crate_dir, &out_abs, &name, &field, profile, emit_json,
    )
}

/// `xark build`: `cargo` (any toolchain) builds the circuit
/// for wasm32, then `xark-frontend` runs it to lower the circuit.
fn build_stable(
    crate_abs: &std::path::Path,
    crate_dir: &std::path::Path,
    out_abs: &std::path::Path,
    name: &str,
    field: &str,
    profile: bool,
    emit_json: bool,
) -> i32 {
    eprintln!("{} building circuit `{name}`", crate::style::tag());
    // Every build carries DWARF line tables (free; see `BuildOptions`), so errors
    // and `--profile` attribution name source lines.
    let (target_dir, opts) = (
        crate_abs.join("target/xark-wasm"),
        xark_frontend::BuildOptions::default(),
    );
    let wasm = match xark_frontend::build_crate_with(crate_abs, &target_dir, &opts) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("xark: {e}");
            return 1;
        }
    };
    let mut lowered = match xark_frontend::lower_module(
        &wasm,
        xark_ir::FieldSpec::named(field),
        profile,
        emit_json,
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{} {e}", crate::style::err("error:"));
            return 1;
        }
    };
    // The R1CS digest: what the proving/verifying keys depend on, and the same
    // under every supported rustc (docs/toolchain.md).
    let digest = lowered
        .output
        .function_xbc
        .as_deref()
        .map(|x| format!("{:032x}", xark_ir::function_decode::stream_digest(x)));
    if profile {
        xark_frontend::relativize_profile(&mut lowered.output, crate_abs);
    }
    if let Err(e) =
        xark_frontend::write_outputs_in(out_abs, &lowered.output, emit_json, profile, crate_abs)
    {
        eprintln!("xark: writing {}: {e}", out_abs.display());
        return 1;
    }
    if let Some(entry) = &lowered.entry {
        let _ = std::fs::write(out_abs.join("entry"), entry);
    }
    if let Some(d) = &digest {
        let _ = std::fs::write(out_abs.join("digest"), format!("{d}\n"));
    }
    let _ = std::fs::write(
        out_abs.join("schema.json"),
        serde_json::to_string_pretty(&lowered.schema).unwrap_or_default() + "\n",
    );
    let p = &lowered.output.primitive;
    eprintln!(
        "{} {} vars, {} constraints, {} witness-gen ops",
        crate::style::tag(),
        p.vars.len(),
        lowered.output.r1cs.constraints.len(),
        p.witness_gen.len(),
    );
    if let Some(d) = &digest {
        eprintln!("{} circuit digest {d}", crate::style::tag());
    }
    eprintln!(
        "{} wrote {}",
        crate::style::tag(),
        crate::style::brand(&out_abs.display().to_string())
    );
    eprintln!(
        "\n{}",
        crate::style::next_steps(&[(
            format!("xark setup {}", crate_dir.display()),
            "generate the proving/verifying keys",
        )])
    );
    0
}

/// `xark clean` — remove **every** xark output tree under the current directory:
/// each circuit crate's `target/xark/` (emitted artifacts, keys, proofs) and
/// `target/xark-wasm/` (the wasm build cache). Takes no arguments.
pub fn cmd_clean(_args: &[String]) -> i32 {
    fn walk(dir: &std::path::Path, removed: &mut u32, errors: &mut u32) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            match path.file_name().and_then(|s| s.to_str()) {
                // Remove `target/xark{,-wasm}` here; don't descend into `target/`.
                Some("target") => {
                    for xark in [path.join("xark"), path.join("xark-wasm")] {
                        if !xark.is_dir() {
                            continue;
                        }
                        match std::fs::remove_dir_all(&xark) {
                            Ok(()) => {
                                eprintln!("xark: removed {}", xark.display());
                                *removed += 1;
                            }
                            Err(e) => {
                                eprintln!("xark: failed to remove {}: {e}", xark.display());
                                *errors += 1;
                            }
                        }
                    }
                }
                Some(".git") => {} // skip VCS noise
                _ => walk(&path, removed, errors),
            }
        }
    }
    let root = std::env::current_dir().expect("cwd");
    let (mut removed, mut errors) = (0u32, 0u32);
    walk(&root, &mut removed, &mut errors);
    if removed == 0 && errors == 0 {
        eprintln!(
            "xark: nothing to clean (no target/xark or target/xark-wasm under {})",
            root.display()
        );
    } else {
        eprintln!(
            "xark: cleaned {removed} xark target director{}",
            if removed == 1 { "y" } else { "ies" }
        );
    }
    (errors > 0) as i32
}

/// `xark test [crate-dir] [-- <cargo test args>]`
///
/// One-shot circuit testing: build the crate (`xark build`) so its
/// `target/xark/<pkg>/` artifacts exist, then run `cargo test` in the crate so
/// the in-crate `xark_prover::circuit(..).check(..)` tests can load them.
pub fn cmd_test(args: &[String]) -> i32 {
    // Split at `--`: everything before is ours (the crate dir); everything
    // after is forwarded verbatim to `cargo test`.
    let (ours, forwarded): (&[String], &[String]) = match args.iter().position(|a| a == "--") {
        Some(i) => (&args[..i], &args[i + 1..]),
        None => (args, &[]),
    };
    let crate_dir = ours
        .iter()
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| ".".to_string());
    let build_argv = vec![crate_dir.clone()];

    // Build first so the tests' artifacts are present + current. Build with
    // `--profile` (also writes `profile.json`, leaving the other artifacts
    // byte-identical): the test harness reads it to explain which source line /
    // function a failing constraint came from.
    let code = cmd_build_profile(&build_argv);
    if code != 0 {
        eprintln!("xark: build failed; skipping tests");
        return code;
    }

    // Run in `--release`: circuit tests drive a full Groth16 setup+prove+verify,
    // 10–50× slower in debug (minutes vs seconds on a large hash/EC circuit), so
    // release is the sensible default. Anything after `--` goes to `cargo test`
    // (so `xark test . -- -- --include-ignored` reaches the test binary).
    eprintln!("xark: running `cargo test --release` in {crate_dir}");
    let status = Command::new("cargo")
        .arg("test")
        .arg("--release")
        .args(forwarded)
        .current_dir(&crate_dir)
        .status();
    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("xark: failed to run cargo test: {e}");
            1
        }
    }
}

/// `xark check <crate-dir>`
///
/// Fast, artifact-free validation of a circuit crate for editor diagnostics (see
/// `check_stable`). `--message-format=json` emits JSON diagnostics on stdout, the
/// shape `rust-analyzer`'s `check.overrideCommand` consumes.
pub fn cmd_check(args: &[String]) -> i32 {
    let mut crate_dir: Option<String> = None;
    let mut json = false;
    for a in args {
        match a.as_str() {
            // Emit machine-readable JSON diagnostics (for editors / rust-analyzer).
            "--message-format=json" | "--json" => json = true,
            _ if crate_dir.is_none() => crate_dir = Some(a.clone()),
            _ => {}
        }
    }
    let Some(crate_dir) = crate_dir else {
        eprintln!("error: `xark check <crate-dir>` requires a crate directory");
        return 2;
    };
    let crate_dir = PathBuf::from(crate_dir);
    let crate_abs = std::env::current_dir().expect("cwd").join(&crate_dir);
    check_stable(&crate_abs, json)
}

/// `xark check`: build the circuit for wasm32 (with line
/// tables, so a rejection points at its source line), then lower it. Cargo's own
/// diagnostics pass through; a lowering rejection is reported like a rustc error —
/// with `--message-format=json`, as a cargo `compiler-message` on stdout (what
/// rust-analyzer's `check.overrideCommand` reads).
fn check_stable(crate_abs: &std::path::Path, json: bool) -> i32 {
    let opts = xark_frontend::BuildOptions {
        json_diagnostics: json,
        ..Default::default()
    };
    let target_dir = crate_abs.join("target/xark-wasm");
    let wasm = match xark_frontend::build_crate_with(crate_abs, &target_dir, &opts) {
        Ok(w) => w,
        // Cargo already reported why (on stdout as JSON when asked).
        Err(e) => {
            if !json {
                eprintln!("xark: {e}");
            }
            return 1;
        }
    };
    // Field-agnostic check: lower over BN254 (rejections don't depend on the field).
    match xark_frontend::lower_module(&wasm, xark_ir::FieldSpec::named("bn254"), false, false) {
        Ok(_) => {
            if !json {
                eprintln!("{} circuit ok", crate::style::tag());
            }
            0
        }
        Err(e) => {
            if json {
                println!("{}", check_diagnostic_json(crate_abs, &e));
            } else {
                eprintln!("{} {e}", crate::style::err("error:"));
            }
            1
        }
    }
}

/// A frontend rejection as a cargo `compiler-message` (rustc's JSON diagnostic
/// shape), with the primary span at the error's source line when known.
fn check_diagnostic_json(crate_abs: &std::path::Path, e: &xark_frontend::CompileError) -> String {
    let package_id = std::fs::read_to_string(crate_abs.join("Cargo.toml"))
        .ok()
        .and_then(|m| {
            m.lines()
                .skip_while(|l| l.trim() != "[package]")
                .find_map(|l| {
                    let v = l
                        .trim()
                        .strip_prefix("name")?
                        .trim_start()
                        .strip_prefix('=')?;
                    Some(v.trim().trim_matches('"').to_string())
                })
        })
        .unwrap_or_default();
    let spans: Vec<serde_json::Value> = e
        .site
        .iter()
        .filter_map(|s| s.span.as_ref())
        .map(|(file, line, col)| {
            let col = (*col).max(1);
            serde_json::json!({
                "file_name": file,
                "byte_start": 0,
                "byte_end": 0,
                "line_start": line,
                "line_end": line,
                "column_start": col,
                "column_end": col + 1,
                "is_primary": true,
                "text": [],
                "label": null,
                "suggested_replacement": null,
                "suggestion_applicability": null,
                "expansion": null,
            })
        })
        .collect();
    let children: Vec<serde_json::Value> = e
        .notes
        .iter()
        .map(|n| ("note", n))
        .chain(e.help.iter().map(|h| ("help", h)))
        .map(|(level, m)| {
            serde_json::json!({
                "message": m, "code": null, "level": level, "spans": [],
                "children": [], "rendered": null,
            })
        })
        .collect();
    serde_json::json!({
        "reason": "compiler-message",
        "package_id": package_id,
        "manifest_path": crate_abs.join("Cargo.toml").display().to_string(),
        "target": { "name": package_id, "kind": ["lib"], "src_path": crate_abs.join("src/lib.rs").display().to_string() },
        "message": {
            "message": e.message,
            "code": { "code": "xark", "explanation": null },
            "level": "error",
            "spans": spans,
            "children": children,
            "rendered": format!("error: {e}\n"),
        },
    })
    .to_string()
}

/// `xark init [name]` — scaffold a ready-to-edit circuit crate, pre-wired for
/// rust-analyzer so unsupported constructs surface inline as you type (via
/// `xark check`). With no name, initializes the current directory.
pub fn cmd_init(args: &[String]) -> i32 {
    let name_arg = args.iter().find(|a| !a.starts_with('-')).cloned();
    let cwd = std::env::current_dir().expect("cwd");
    let (dir, name) = match &name_arg {
        Some(n) => (cwd.join(n), n.clone()),
        None => (
            cwd.clone(),
            cwd.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("circuit")
                .to_string(),
        ),
    };

    // Pin the published `xark`/`xark-prover` deps to this CLI's own major.minor
    // (the whole workspace releases together), so the scaffold never suggests a
    // version older than the CLI you ran it with.
    let full = env!("CARGO_PKG_VERSION");
    let ver = full.rsplit_once('.').map_or(full, |(mm, _)| mm);
    let cargo_toml = format!(
        "[package]\n\
         name = \"{name}\"\n\
         version = \"0.1.0\"\n\
         edition = \"2021\"\n\n\
         [lib]\n\
         crate-type = [\"lib\"]\n\n\
         [dependencies]\n\
         xark = {{ version = \"{ver}\", default-features = false }}\n\
         # From git:               xark = {{ git = \"https://github.com/blueshift-gg/xark\", default-features = false }}\n\
         # From a local checkout:  xark = {{ path = \"../xark/crates/lang\", default-features = false }}\n\n\
         # `xark-prover` powers the in-crate `cargo test` circuit tests below.\n\
         [dev-dependencies]\n\
         xark-prover = \"{ver}\"\n\
         # From git:               xark-prover = {{ git = \"https://github.com/blueshift-gg/xark\" }}\n\
         # From a local checkout:  xark-prover = {{ path = \"../xark/crates/prover\" }}\n\n\
         # `xark` is set only by the circuit build; declare it so rustc's `unexpected_cfgs`\n\
         # lint (1.80+) stays quiet.\n\
         [lints.rust]\n\
         unexpected_cfgs = {{ level = \"warn\", check-cfg = ['cfg(xark)'] }}\n"
    );
    let fn_ident = ident_of(&name);
    let inputs_struct = format!("{}Inputs", pascal_of(&fn_ident));
    let lib_rs = format!(
        "{}{}",
        LIB_TEMPLATE.replace("__FN__", &fn_ident),
        tests_template(&name, &inputs_struct)
    );
    // Both files set the same rust-analyzer override: `rust-analyzer.toml` is the
    // editor-agnostic form; `.vscode/settings.json` covers VS Code specifically.
    let ra_cmd = "[\"xark\", \"check\", \".\", \"--message-format=json\"]";
    let files: [(&str, String); 5] = [
        ("Cargo.toml", cargo_toml),
        ("src/lib.rs", lib_rs),
        (
            "rust-analyzer.toml",
            format!(
                "# Run xark's subset validator on save so unsupported constructs show inline.\n\
                 # Needs `xark` on PATH. Layers on top of rustc checks.\n\
                 [check]\n\
                 overrideCommand = {ra_cmd}\n"
            ),
        ),
        (
            ".vscode/settings.json",
            format!("{{\n  \"rust-analyzer.check.overrideCommand\": {ra_cmd}\n}}\n"),
        ),
        (".gitignore", "/target\n".to_string()),
    ];

    let mut created = 0u32;
    for (rel, contents) in &files {
        let path = dir.join(rel);
        if path.exists() {
            eprintln!("xark: keeping existing {rel}");
            continue;
        }
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            eprintln!("xark: failed to create {}: {e}", parent.display());
            return 1;
        }
        if let Err(e) = std::fs::write(&path, contents) {
            eprintln!("xark: failed to write {rel}: {e}");
            return 1;
        }
        created += 1;
    }

    eprintln!(
        "xark: scaffolded circuit `{name}` ({created} files) in {}",
        dir.display()
    );
    let where_ = if name_arg.is_some() {
        name.as_str()
    } else {
        "."
    };
    eprintln!(
        "{}",
        crate::style::next_steps(&[
            (
                format!("xark build {where_}"),
                "compile the circuit to R1CS"
            ),
            (
                format!("xark setup {where_}"),
                "generate the proving/verifying keys"
            ),
            (
                format!("xark prove {where_} --inputs '{{\"secret\": 3, \"result\": 9}}'"),
                "produce your first proof",
            ),
        ])
    );
    0
}

/// Turn a crate name into a valid Rust identifier for the scaffolded entry fn
/// (`my-circuit` → `my_circuit`); falls back to `circuit`.
fn ident_of(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if s.is_empty() {
        return "circuit".to_string();
    }
    if s.starts_with(|c: char| c.is_ascii_digit()) {
        s.insert(0, '_');
    }
    s
}

/// `my_square` → `MySquare` — must match `xark-macros`' struct naming so the
/// scaffolded test references the generated `<Fn>Inputs` struct correctly.
fn pascal_of(ident: &str) -> String {
    ident
        .split('_')
        .filter(|seg| !seg.is_empty())
        .map(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// The starter circuit written by `xark init`. The `#[cfg(test)] mod tests`
/// block ([`tests_template`]) is appended with the crate's own name filled in.
///
/// `no_std` applies to the real circuit build (via `xark build`) but is dropped
/// under `cargo test` so the `xark-prover` test harness (which uses `std`) can
/// link.
const LIB_TEMPLATE: &str = "\
#![cfg_attr(xark, no_std)]
use xark::prelude::*;

#[circuit]
pub fn __FN__(secret: Private<Field>, result: Public<Field>) {
    // prove knowledge of a square root: secret * secret == result
    require_eq(secret * secret, result);
}
";

/// The `#[cfg(test)] mod tests` appended to the scaffolded `src/lib.rs`.
///
/// Inputs are the typed struct `#[circuit]` generates from the entry signature
/// (`inputs` = `<Fn>Inputs`), so they're named, not positional. These tests load
/// the built artifacts, so they need `xark build .` to have run first.
fn tests_template(name: &str, inputs: &str) -> String {
    format!(
        "\n\
         #[cfg(test)]\n\
         mod tests {{\n\
         \x20   use super::*;\n\
         \n\
         \x20   #[test]\n\
         \x20   fn accepts_valid() {{\n\
         \x20       let c = xark_prover::circuit(\"{name}\");\n\
         \x20       c.check({inputs} {{ secret: \"2\".into(), result: \"4\".into() }}).unwrap(); // 2 * 2 == 4\n\
         \x20   }}\n\
         \n\
         \x20   #[test]\n\
         \x20   fn rejects_invalid() {{\n\
         \x20       let c = xark_prover::circuit(\"{name}\");\n\
         \x20       assert!(c.check({inputs} {{ secret: \"3\".into(), result: \"4\".into() }}).is_err()); // 3 * 3 != 4\n\
         \x20   }}\n\
         }}\n"
    )
}
