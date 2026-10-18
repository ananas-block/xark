//! `xark doctor` — check the local machine is set up to build and prove
//! circuits, and print the exact fix for anything missing.
//!
//! The default (stable) frontend needs only a stable Rust toolchain (1.88+) and
//! its `wasm32-unknown-unknown` standard library (`xark build` adds it with
//! `rustup` on first use). The deprecated MIR frontend (`--frontend mir`) also
//! needs the `xark-rustc` driver's pinned nightly, reported as optional.

use std::process::Command;

use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct DoctorArgs {}

/// Oldest `rustc` that builds a circuit (the `xark` crate's `rust-version`).
const MIN_RUSTC: (u32, u32) = (1, 88);

pub fn run(_args: DoctorArgs) -> Result<()> {
    // The pinned toolchain, queried from the `xark-rustc` driver — which bakes it
    // at build time (`--print-toolchain`), the single source of truth. Falls back
    // to a bare `nightly` if the driver isn't installed (doctor flags that missing
    // driver separately below).
    let toolchain_owned = crate::cli::find_rustc_shim()
        .and_then(|d| Command::new(d).arg("--print-toolchain").output().ok())
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "nightly".to_string());
    let toolchain = toolchain_owned.as_str();
    let channel = channel_of(toolchain);
    let install_tc = format!(
        "rustup toolchain install {channel} --profile minimal \
         --component rust-src --component rustc-dev --component llvm-tools"
    );

    println!(
        "{}",
        crate::style::brand("xark doctor — checking your setup\n")
    );

    let mut problems = 0u32;

    // Rust toolchain (required)
    let cargo = cmd_ok("cargo", &["--version"]);
    problems += check(
        cargo.is_some(),
        "cargo",
        cargo.as_deref(),
        "install Rust from https://rustup.rs",
    );
    let rustc = cmd_ok("rustc", &["--version"]);
    let version = rustc.as_deref().and_then(|v| {
        let mut it = v.split_whitespace().nth(1)?.split('.');
        Some((
            it.next()?.parse::<u32>().ok()?,
            it.next()?.parse::<u32>().ok()?,
        ))
    });
    problems += check(
        version.is_some_and(|v| v >= MIN_RUSTC),
        &format!("rustc {}.{}+", MIN_RUSTC.0, MIN_RUSTC.1),
        rustc.as_deref(),
        "rustup update stable",
    );
    let rustup = cmd_ok("rustup", &["--version"]);
    problems += check(
        rustup.is_some(),
        "rustup",
        rustup.as_deref(),
        "install Rust from https://rustup.rs",
    );
    let targets = cmd_ok("rustup", &["target", "list", "--installed"]).unwrap_or_default();
    info(
        targets
            .lines()
            .any(|l| l.trim() == "wasm32-unknown-unknown"),
        "target wasm32-unknown-unknown",
        "installed automatically on the first `xark build`",
        "rustup target add wasm32-unknown-unknown",
    );

    // The deprecated MIR frontend's pinned nightly (informational).
    let toolchains = cmd_ok("rustup", &["toolchain", "list"]).unwrap_or_default();
    let tc_ok = toolchains
        .lines()
        .any(|l| l.starts_with(toolchain) || l.starts_with(channel.as_str()));
    let comps = if tc_ok {
        cmd_ok(
            "rustup",
            &["component", "list", "--toolchain", toolchain, "--installed"],
        )
        .unwrap_or_default()
    } else {
        String::new()
    };
    let comps_ok = ["rustc-dev", "rust-src", "llvm-tools"].iter().all(|comp| {
        comps
            .lines()
            .any(|l| l.trim() == *comp || l.trim().starts_with(&format!("{comp}-")))
    });
    info(
        tc_ok && comps_ok && crate::cli::find_rustc_shim().is_some(),
        &format!("toolchain {channel} + xark-rustc"),
        "only for the deprecated `--frontend mir`",
        &install_tc,
    );

    // Optional (informational — never a hard failure).
    let onpath = cmd_ok("xark", &["--version"]);
    info(
        onpath.is_some(),
        "xark on PATH",
        "needed for `xark init` and rust-analyzer diagnostics",
        "cargo install xark-cli",
    );
    let node = cmd_ok("node", &["--version"]);
    info(
        node.is_some(),
        "node",
        "optional — only for the `xark client` TypeScript output",
        "install Node.js from https://nodejs.org",
    );

    println!();
    if problems == 0 {
        println!(
            "{}",
            crate::style::brand("✅ All required checks passed — you're ready to `xark init`.")
        );
    } else {
        println!(
            "{}",
            crate::style::err(&format!(
                "❌ {problems} issue(s) above — fix the ❌ lines, then re-run `xark doctor`."
            ))
        );
        std::process::exit(1);
    }
    Ok(())
}

/// Run `bin args…`; return trimmed stdout on success, `None` on any failure
/// (including the binary not being found).
fn cmd_ok(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Print a required-check line; return `1` if it FAILED (for the problem count).
fn check(ok: bool, label: &str, detail: Option<&str>, fix: &str) -> u32 {
    if ok {
        let d = detail
            .map(|d| format!("  {}", crate::style::dim(d)))
            .unwrap_or_default();
        println!("  {} {label}{d}", crate::style::brand("✅"));
        0
    } else {
        println!("  {} {label}", crate::style::err("❌"));
        println!("       {}", crate::style::dim(&format!("fix: {fix}")));
        1
    }
}

/// Print an optional/informational line — a present ✅ or an amber bullet, but
/// never counted as a failure.
fn info(ok: bool, label: &str, note: &str, fix: &str) {
    if ok {
        println!(
            "  {} {label}  {}",
            crate::style::brand("✅"),
            crate::style::dim(note)
        );
    } else {
        println!(
            "  {} {label}  {}",
            crate::style::warn("•"),
            crate::style::dim(note)
        );
        println!("       {}", crate::style::dim(&format!("fix: {fix}")));
    }
}

/// Reduce a full toolchain name to its rustup channel:
/// `nightly-2026-05-03-aarch64-apple-darwin` → `nightly-2026-05-03`.
fn channel_of(tc: &str) -> String {
    let parts: Vec<&str> = tc.split('-').collect();
    if parts.len() >= 4
        && parts[0] == "nightly"
        && parts[1].len() == 4
        && parts[1].bytes().all(|b| b.is_ascii_digit())
    {
        format!("nightly-{}-{}-{}", parts[1], parts[2], parts[3])
    } else {
        tc.to_string()
    }
}
