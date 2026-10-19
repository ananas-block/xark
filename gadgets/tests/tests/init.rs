//! `xark init` scaffolds a crate whose own tests pass under `xark test` — the
//! first thing a new user runs.

mod common;
use common::{run, tempdir};
use std::path::Path;

#[test]
fn init_then_test() {
    let tmp = tempdir();
    let dir = tmp.path().join("demo");
    let dir_s = dir.to_str().unwrap();
    let (ok, _, err) = run(&["init", dir_s]);
    assert!(ok, "init failed: {err}");

    // The scaffold depends on the published crates; point it at this checkout.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = root.canonicalize().unwrap();
    let manifest = dir.join("Cargo.toml");
    let toml = std::fs::read_to_string(&manifest).unwrap();
    // The scaffold pins major.minor.
    let ver = env!("CARGO_PKG_VERSION").rsplit_once('.').unwrap().0;
    let patched = toml
        .replace(
            &format!("xark = {{ version = \"{ver}\","),
            &format!(
                "xark = {{ path = \"{}\",",
                root.join("crates/lang").display()
            ),
        )
        .replace(
            &format!("xark-prover = \"{ver}\""),
            &format!(
                "xark-prover = {{ path = \"{}\" }}",
                root.join("crates/prover").display()
            ),
        );
    assert!(
        toml.contains("name = \"demo\""),
        "crate not named after the directory:\n{toml}"
    );
    assert_ne!(
        toml, patched,
        "the scaffold's dependencies changed shape:\n{toml}"
    );
    std::fs::write(&manifest, patched).unwrap();

    // A target shared across runs: the prover's dependencies build once.
    let target = root.join("target/init-test");
    let xark = |args: &[&str]| {
        let o = std::process::Command::new(common::xark_bin())
            .args(args)
            .env("CARGO_TARGET_DIR", &target)
            .output()
            .expect("invoke xark");
        let out =
            String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
        assert!(o.status.success(), "xark {args:?} failed:\n{out}");
        out
    };

    let out = xark(&["test", dir_s]);
    assert!(
        out.contains("2 passed"),
        "expected the scaffold's 2 tests:\n{out}"
    );
    // Arguments after `--` reach the test binary.
    let out = xark(&["test", dir_s, "--", "--list"]);
    assert!(
        out.contains("tests::accepts_valid: test"),
        "--list didn't reach the tests:\n{out}"
    );
}
