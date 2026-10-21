//! Commands that build first reuse a build while no source of the circuit has
//! changed since, and a command that uses the build rebuilds once one has.

mod common;
use common::{tempdir, xark_bin};
use std::path::{Path, PathBuf};
use std::process::Command;

/// `xark <args>` in `dir`: success, and stderr.
fn xark(dir: &Path, args: &[&str]) -> (bool, String) {
    let o = Command::new(xark_bin())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("invoke xark");
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// A copy of `examples/cube` in `tmp`.
fn cube(tmp: &Path) -> PathBuf {
    let dir = tmp.join("cube");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/cube");
    let crates = src.join("../../crates").canonicalize().unwrap();
    for f in ["Cargo.toml", "src/lib.rs"] {
        let text = std::fs::read_to_string(src.join(f)).unwrap();
        std::fs::create_dir_all(dir.join(f).parent().unwrap()).unwrap();
        std::fs::write(
            dir.join(f),
            text.replace("../../crates", crates.to_str().unwrap()),
        )
        .unwrap();
    }
    dir
}

/// Rewrite `src/lib.rs`, newer than any build (file times can be a second coarse).
fn edit(dir: &Path, from: &str, to: &str) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let lib = dir.join("src/lib.rs");
    let text = std::fs::read_to_string(&lib).unwrap();
    assert!(text.contains(from));
    std::fs::write(&lib, text.replace(from, to)).unwrap();
}

#[test]
fn profile_rebuilds_only_after_a_change() {
    let tmp = tempdir();
    let dir = cube(tmp.path());
    let (ok, err) = xark(&dir, &["profile"]);
    assert!(ok && err.contains("building circuit"), "{err}");
    let (ok, err) = xark(&dir, &["profile"]);
    assert!(
        ok && err.contains("not rebuilding") && !err.contains("building circuit"),
        "{err}"
    );
    edit(&dir, "pub fn cube", "// edited\npub fn cube");
    let (ok, err) = xark(&dir, &["profile"]);
    assert!(ok && err.contains("building circuit"), "{err}");
}

#[test]
fn check_reuses_a_current_build() {
    let tmp = tempdir();
    let dir = cube(tmp.path());
    let inputs = r#"{"secret": 3, "result": 27}"#;
    let (ok, err) = xark(&dir, &["check", ".", "--inputs", inputs]);
    assert!(ok && err.contains("building circuit"), "{err}");
    let (ok, err) = xark(&dir, &["check", ".", "--inputs", inputs]);
    assert!(ok && !err.contains("building circuit"), "{err}");
}

#[test]
fn prove_rebuilds_a_stale_circuit_and_asks_for_new_keys() {
    let tmp = tempdir();
    let dir = cube(tmp.path());
    for args in [&["build", "."][..], &["setup", ".", "--insecure-dev-mode"]] {
        let (ok, err) = xark(&dir, args);
        assert!(ok, "{err}");
    }
    edit(&dir, "secret.pow(3)", "secret.pow(3) + secret");
    // The proof would be of the circuit as it was: rebuilt, the old key is refused.
    let (ok, err) = xark(
        &dir,
        &["prove", ".", "--inputs", r#"{"secret": 3, "result": 30}"#],
    );
    assert!(!ok, "{err}");
    assert!(
        err.contains("src/lib.rs changed since it was built"),
        "{err}"
    );
    assert!(err.contains("run `xark setup` again"), "{err}");
    let (ok, err) = xark(&dir, &["setup", ".", "--insecure-dev-mode"]);
    assert!(ok && !err.contains("changed since"), "{err}");
    let (ok, err) = xark(
        &dir,
        &["prove", ".", "--inputs", r#"{"secret": 3, "result": 30}"#],
    );
    assert!(ok, "{err}");
}
