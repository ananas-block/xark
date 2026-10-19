//! `xark export` writes a Solana verifier crate whose own `cargo test` verifies
//! the bundled proof against the embedded key.

mod common;
use common::{run, tempdir, xark_build, xark_prove, xark_setup};
use std::path::Path;

#[test]
fn exported_verifier_passes_its_own_test() {
    let tmp = tempdir();
    let out = tmp.path().join("out");
    let (ok, err) = xark_build("arithmetic_square", &out, &tmp.path().join("target"));
    assert!(ok, "build failed: {err}");
    let (ok, err) = xark_setup(&out);
    assert!(ok, "setup failed: {err}");
    let (ok, err) = xark_prove(&out, &[("x", "3"), ("y", "9")]);
    assert!(ok, "prove failed: {err}");

    // A dev key is refused unless asked for.
    let out_s = out.to_str().unwrap();
    let verifier = tmp.path().join("verifier");
    let verifier_s = verifier.to_str().unwrap();
    let (ok, _, err) = run(&["export", out_s, "--out", verifier_s]);
    assert!(
        !ok && err.contains("--allow-insecure"),
        "exported a dev key: {err}"
    );
    let (ok, _, err) = run(&["export", out_s, "--out", verifier_s, "--allow-insecure"]);
    assert!(ok, "export failed: {err}");

    // The crate pins the published `xark-verifier`; use this checkout's.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let manifest = verifier.join("Cargo.toml");
    let mut toml = std::fs::read_to_string(&manifest).unwrap();
    toml += &format!(
        "\n[patch.crates-io]\nxark-verifier = {{ path = \"{}\" }}\n",
        root.join("crates/verifier").display()
    );
    std::fs::write(&manifest, toml).unwrap();

    let o = std::process::Command::new("cargo")
        .args(["test", "--quiet"])
        .current_dir(&verifier)
        // A target shared across runs: the verifier's dependencies build once.
        .env("CARGO_TARGET_DIR", root.join("target/export-test"))
        .output()
        .expect("invoke cargo");
    let log = String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
    assert!(
        o.status.success(),
        "the exported crate's tests failed:\n{log}"
    );
    assert!(
        log.contains("1 passed"),
        "expected the bundled-proof test:\n{log}"
    );
}
