//! Callable circuit build, setup, and TypeScript client generation.

mod cli;
mod commands;
mod style;
mod xark_project;

use std::path::Path;

pub use commands::setup::{QapDomain, R1csForm, SetupArgs as SetupOptions};

/// Compile a BN254 circuit crate into the supplied artifact directory.
///
/// Uses the same compiler and artifact formats as `xark build`, without parsing
/// the host process arguments or installing a global allocator or logger.
pub fn build(crate_dir: &Path, out: &Path) -> anyhow::Result<()> {
    cli::build(crate_dir, Some(out), "bn254", false, false)
}

/// Generate keys for a built circuit directory using the CLI's setup options.
/// `artifact` supplies the input path; `options.out` can redirect the keys.
pub fn setup(artifact: &Path, mut options: SetupOptions) -> anyhow::Result<()> {
    options.path = Some(artifact.to_path_buf());
    commands::setup::run(options)
}

/// Generate a TypeScript client from a built circuit directory.
/// `out` is a file or directory, as for `xark client --out`.
pub fn client(artifact: &Path, out: &Path, no_functions: bool) -> anyhow::Result<()> {
    commands::client::run(commands::client::ClientArgs {
        path: Some(artifact.to_path_buf()),
        lang: commands::client::Lang::Ts,
        out: Some(out.to_path_buf()),
        no_functions,
    })
}

/// Check that a proving key's embedded verifying key matches a validated key.
///
/// Checks both files' encoded lengths, without reading the proving key's query
/// points. This detects incomplete files and mismatched pairs; it does not
/// validate every proving-key point.
pub fn keys_match(pk: &Path, vk: &Path) -> anyhow::Result<bool> {
    use std::io::Seek;

    use ark_serialize::{CanonicalSerialize, Compress};
    use xark_groth16::PkSource;

    let verifying_key = xark_backend::keys::Groth16Keys::read_verifying_key(vk)?;
    if verifying_key.serialized_size(Compress::Yes) as u64 != std::fs::metadata(vk)?.len() {
        return Ok(false);
    }
    let mut file = std::fs::File::open(pk)?;
    let matches = {
        let proving_key = xark_groth16::SerializedPk::new(&mut file)?;
        proving_key.header().vk == verifying_key
    };
    Ok(matches && file.stream_position()? == file.metadata()?.len())
}

/// Run the standalone CLI using the process arguments, returning its exit code.
/// Embedders should call [`build`], [`setup`], and [`client`] directly.
#[doc(hidden)]
pub fn run_cli() -> anyhow::Result<i32> {
    if std::env::args_os().len() == 1 {
        print_roadmap();
        Ok(0)
    } else {
        commands::main()
    }
}

/// The zero-to-on-chain roadmap, shown when `xark` is run with no arguments.
fn print_roadmap() {
    let steps: &[(&str, &str)] = &[
        ("xark doctor", "check your toolchain is set up"),
        (
            "xark init my-circuit",
            "scaffold a circuit crate (rust-analyzer ready)",
        ),
        ("xark build .", "compile the circuit → R1CS (+ schema.json)"),
        (
            "xark client .",
            "generate a typed TypeScript client (prove + verify in JS)",
        ),
        ("xark setup .", "generate the proving/verifying keys"),
        (
            "xark prove . --inputs …",
            "produce (and self-check) a proof",
        ),
        ("xark verify .", "verify a proof locally"),
        (
            "xark export .",
            "generate the on-chain Solana verifier crate",
        ),
    ];
    // Align by display columns, not bytes (some commands contain `…`).
    let width = steps
        .iter()
        .map(|(c, _)| c.chars().count())
        .max()
        .unwrap_or(0);
    println!(
        "{}",
        style::brand("xark — write, prove & verify zero-knowledge circuits in Rust")
    );
    println!("\nThe path from zero to an on-chain proof:\n");
    for (cmd, hint) in steps {
        println!(
            "  {}{}   {}",
            style::brand(cmd),
            " ".repeat(width.saturating_sub(cmd.chars().count())),
            style::dim(hint),
        );
    }
    println!(
        "\n{}",
        style::dim(
            "Run `xark <command> --help` for details, or `xark doctor` to check your setup."
        )
    );
}
