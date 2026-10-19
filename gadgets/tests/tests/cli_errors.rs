//! The CLI's answers to common mistakes: a mistyped path, a name `cargo` would
//! refuse, a corrupt artifact. Each must stop with an error that names the
//! problem, never fall back to something else.

mod common;
use common::{run, tempdir, xark_bin, xark_build, xark_prove, xark_setup};
use std::process::Command;

/// `xark <args>` in `dir`, returning `(success, stdout + stderr)`.
fn run_in(dir: &std::path::Path, args: &[&str]) -> (bool, String) {
    let o = Command::new(xark_bin())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("invoke xark");
    let out = String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
    (o.status.success(), out)
}

#[test]
fn init_refuses_names_cargo_would() {
    let tmp = tempdir();
    for (name, why, suggest) in [
        ("type", "keyword", "type_circuit"),
        ("self", "keyword", "self_circuit"),
        ("1st", "starts with a digit", "circuit_1st"),
        ("a b", "only letters", "a_b"),
    ] {
        let (ok, out) = run_in(tmp.path(), &["init", name]);
        assert!(!ok, "`xark init {name}` succeeded:\n{out}");
        assert!(
            out.contains(why) && out.contains(&format!("xark init {suggest}")),
            "`xark init {name}`:\n{out}"
        );
        assert!(!tmp.path().join(name).exists(), "`{name}` was scaffolded");
    }
}

#[test]
fn missing_paths_are_reported() {
    let tmp = tempdir();
    let missing = tmp.path().join("nope");
    let missing = missing.to_str().unwrap();
    for cmd in ["prove", "setup", "inspect", "verify", "client", "export"] {
        let (ok, _, err) = run(&[cmd, missing]);
        assert!(
            !ok && err.contains("no such directory"),
            "`xark {cmd}` on a missing path:\n{err}"
        );
    }
    for cmd in ["build", "test", "profile"] {
        let (ok, out) = run_in(tmp.path(), &[cmd, "./nope"]);
        assert!(
            !ok && out.contains("no such directory: ./nope"),
            "`xark {cmd}` on a missing path:\n{out}"
        );
    }
    // A directory that isn't a crate.
    let (ok, out) = run_in(tmp.path(), &["build"]);
    assert!(!ok && out.contains("no Cargo.toml in ."), "{out}");
}

#[test]
fn build_names_the_package() {
    let tmp = tempdir();
    let dir = common::circuit_crate("arithmetic_square");
    let o = Command::new(xark_bin())
        .args(["build", "--out"])
        .arg(tmp.path().join("out"))
        .current_dir(&dir)
        .env("CARGO_TARGET_DIR", tmp.path().join("target"))
        .output()
        .expect("invoke xark");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "build failed:\n{err}");
    assert!(
        err.contains("building circuit `arithmetic_square`"),
        "build of `.` misnamed:\n{err}"
    );
}

#[test]
fn corrupt_public_inputs_get_no_prove_hint() {
    let tmp = tempdir();
    let out = tmp.path().join("out");
    let (ok, err) = xark_build("arithmetic_square", &out, &tmp.path().join("target"));
    assert!(ok, "build failed: {err}");
    let (ok, err) = xark_setup(&out);
    assert!(ok, "setup failed: {err}");
    let (ok, err) = xark_prove(&out, &[("x", "3"), ("y", "9")]);
    assert!(ok, "prove failed: {err}");

    let out_s = out.to_str().unwrap();
    let pi = out.join("public_inputs.bin");
    std::fs::write(&pi, [1, 2, 3]).unwrap();
    let (ok, _, err) = run(&["verify", out_s]);
    assert!(!ok && !err.contains("run `xark prove` first"), "{err}");

    std::fs::remove_file(&pi).unwrap();
    let (ok, _, err) = run(&["verify", out_s]);
    assert!(!ok && err.contains("run `xark prove` first"), "{err}");
}
