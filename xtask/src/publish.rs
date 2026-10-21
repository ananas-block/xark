//! `cargo xtask publish`: every publishable crate, dependencies first.
//!
//! * `--plan`: check every crate can publish, and print the order (CI runs this);
//! * `--dry-run`: package every crate and build each from its own `.crate`, as
//!   crates.io will see it, uploading nothing;
//! * `--execute`: the real release (needs `cargo login`). `cargo publish` waits for
//!   each crate to index before the next, so its dependencies are always there.
//!
//! A crate is publishable unless its manifest says `publish = false`. Every
//! dependency of a publishable crate on another local crate (dev-dependencies
//! included, since crates.io resolves them too) must itself be publishable and carry
//! a `version`: a mistake fails here, not halfway through a release.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// `xark` (crates/lang) is its own workspace: published from its directory.
const SEPARATE: &str = "crates/lang";

#[derive(clap::Args)]
#[group(required = true, multiple = false)]
pub struct Args {
    /// Check every crate can publish, and print the order.
    #[arg(long)]
    plan: bool,
    /// Package and build every crate from its `.crate`; upload nothing.
    #[arg(long)]
    dry_run: bool,
    /// Publish every crate to crates.io.
    #[arg(long)]
    execute: bool,
}

pub fn run(args: Args) -> Result<()> {
    let order = plan()?;
    if args.plan {
        println!("{} crates, in publish order:", order.len());
        for (name, _) in &order {
            println!("  {name}");
        }
    } else if args.dry_run {
        dry_run()?;
    } else {
        for (name, dir) in &order {
            println!(">>> publishing {name}");
            let mut cmd = Command::new("cargo");
            match dir {
                Some(dir) => cmd.arg("publish").current_dir(dir),
                None => cmd.args(["publish", "-p", name]).current_dir(crate::root()),
            };
            if !cmd.status()?.success() {
                bail!("publishing {name} failed");
            }
        }
        println!("All {} crates published.", order.len());
    }
    Ok(())
}

/// The publishable crates in dependency order, each with its directory when it
/// publishes from there (its own workspace).
fn plan() -> Result<Vec<(String, Option<PathBuf>)>> {
    let root = crate::root();
    let mut pkgs: BTreeMap<String, Value> = BTreeMap::new();
    for dir in [root.clone(), root.join(SEPARATE)] {
        for p in metadata(&dir)? {
            if p["manifest_path"]
                .as_str()
                .is_some_and(|m| Path::new(m).starts_with(&root))
            {
                pkgs.insert(p["name"].as_str().unwrap_or_default().to_string(), p);
            }
        }
    }
    let publishable: BTreeSet<&str> = pkgs
        .iter()
        .filter(|(_, p)| p["publish"] != serde_json::json!([]))
        .map(|(n, _)| n.as_str())
        .collect();
    let mut errors = Vec::new();
    let mut deps: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for &n in &publishable {
        let mine = deps.entry(n).or_default();
        for d in pkgs[n]["dependencies"].as_array().into_iter().flatten() {
            let (dep, req) = (
                d["name"].as_str().unwrap_or_default(),
                d["req"].as_str().unwrap_or("*"),
            );
            if !pkgs.contains_key(dep) || d["path"].is_null() || dep == n {
                continue;
            }
            if d["kind"] == "dev" && req == "*" {
                continue; // a path-only dev-dependency: cargo drops it on publish
            }
            if req == "*" {
                errors.push(format!("{n} -> {dep}: a path dependency without a version"));
            }
            if !publishable.contains(dep) {
                errors.push(format!("{n} -> {dep}: depends on an unpublished crate"));
            }
            mine.insert(pkgs.get_key_value(dep).unwrap().0.as_str());
        }
    }
    if !errors.is_empty() {
        bail!("cannot publish:\n  {}", errors.join("\n  "));
    }
    // Leaves first; ties alphabetical, so the order is stable.
    let mut order: Vec<&str> = Vec::new();
    while order.len() < deps.len() {
        let ready: Vec<&str> = deps
            .iter()
            .filter(|(n, d)| !order.contains(n) && d.iter().all(|x| order.contains(x)))
            .map(|(n, _)| *n)
            .collect();
        if ready.is_empty() {
            let rest: Vec<&str> = deps
                .keys()
                .filter(|n| !order.contains(n))
                .copied()
                .collect();
            bail!("dependency cycle among: {}", rest.join(" "));
        }
        order.extend(ready);
    }
    let separate = root.join(SEPARATE);
    Ok(order
        .into_iter()
        .map(|n| {
            let dir = Path::new(pkgs[n]["manifest_path"].as_str().unwrap_or_default()).parent();
            let own = dir.filter(|d| *d == separate).map(Path::to_path_buf);
            (n.to_string(), own)
        })
        .collect())
}

/// `cargo metadata --no-deps` for the workspace at `dir`: its packages.
fn metadata(dir: &Path) -> Result<Vec<Value>> {
    let out = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(dir)
        .output()
        .context("running cargo metadata")?;
    if !out.status.success() {
        bail!(
            "cargo metadata in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let v: Value = serde_json::from_slice(&out.stdout)?;
    Ok(v["packages"].as_array().cloned().unwrap_or_default())
}

/// Package every crate and build each from its `.crate`. A plain `cargo publish
/// --dry-run -p <crate>` can't, before a release: it resolves the crate's xark
/// dependencies at the new version from crates.io, where they aren't yet. `cargo
/// package --workspace` resolves them from the other local packages instead, but
/// `xark` is its own workspace, so this runs in a copy of HEAD where it is a member.
/// Uncommitted changes are not included.
fn dry_run() -> Result<()> {
    let root = crate::root();
    let copy = crate::target_dir().join("publish-dry");
    let _ = std::fs::remove_dir_all(&copy);
    std::fs::create_dir_all(&copy)?;
    let mut archive = Command::new("git")
        .args(["archive", "HEAD"])
        .current_dir(&root)
        .stdout(Stdio::piped())
        .spawn()?;
    let tar = Command::new("tar")
        .args(["-x", "-C"])
        .arg(&copy)
        .stdin(archive.stdout.take().unwrap())
        .status()?;
    if !archive.wait()?.success() || !tar.success() {
        bail!("extracting HEAD into {}", copy.display());
    }
    // `crates/lang` joins the copy's workspace: out of `exclude`, into `members`.
    let manifest = copy.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)?;
    let lang = format!("    \"{SEPARATE}\",\n");
    let (members, rest) = text
        .split_once("members = [\n")
        .context("no `members = [` in Cargo.toml")?;
    let rest = rest.replacen(&lang, "", 1);
    std::fs::write(&manifest, format!("{members}members = [\n{lang}{rest}"))?;
    let _ = std::fs::remove_file(copy.join(SEPARATE).join("Cargo.lock"));

    let mut cmd = Command::new("cargo");
    cmd.args(["package", "--workspace"])
        .current_dir(&copy)
        .env("CARGO_TARGET_DIR", crate::target_dir());
    for p in metadata(&copy)? {
        if p["publish"] == serde_json::json!([]) {
            cmd.args(["--exclude", p["name"].as_str().unwrap_or_default()]);
        }
    }
    if !cmd.status()?.success() {
        bail!("cargo package failed");
    }
    println!("Dry run complete: every crate packages and builds from its tarball.");
    Ok(())
}
