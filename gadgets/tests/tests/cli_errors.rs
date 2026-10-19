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

/// `xark clean` removes build output under the current directory only: never
/// through a symlink, which can lead anywhere.
#[cfg(unix)]
#[test]
fn clean_does_not_follow_symlinks() {
    let tmp = tempdir();
    let (inside, outside) = (tmp.path().join("in"), tmp.path().join("out"));
    for d in [inside.join("a/target/xark"), outside.join("b/target/xark")] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::os::unix::fs::symlink(&outside, inside.join("link")).unwrap();
    let (ok, out) = run_in(&inside, &["clean"]);
    assert!(ok, "{out}");
    assert!(
        !inside.join("a/target/xark").exists(),
        "not cleaned:\n{out}"
    );
    assert!(
        outside.join("b/target/xark").exists(),
        "cleaned through a symlink:\n{out}"
    );
}

/// A proving key made for an earlier build is named as stale, not left to fail
/// the proof's self-verification.
#[test]
fn stale_proving_key_is_named() {
    let tmp = tempdir();
    let out = tmp.path().join("out");
    let (ok, err) = xark_build("arithmetic_square", &out, &tmp.path().join("target"));
    assert!(ok, "build failed: {err}");
    let (ok, err) = xark_setup(&out);
    assert!(ok, "setup failed: {err}");
    // As if the circuit had been rebuilt with a change since setup.
    let meta = out.join("metadata.json");
    let mut m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta).unwrap()).unwrap();
    m["circuit_hash"] = "00".repeat(32).into();
    std::fs::write(&meta, m.to_string()).unwrap();
    let (ok, err) = xark_prove(&out, &[("x", "3"), ("y", "9")]);
    assert!(
        !ok && err.contains("different build of the circuit"),
        "{err}"
    );
}

/// Like cargo, the commands find the crate from a directory inside it (`xark
/// build` from `src/`); a directory named explicitly is taken as given.
#[test]
fn commands_find_the_crate_from_a_subdirectory() {
    let tmp = tempdir();
    let src = common::circuit_crate("arithmetic_square").join("src");
    let out = tmp.path().join("out");
    let o = Command::new(xark_bin())
        .args(["build", "--out"])
        .arg(&out)
        .current_dir(&src)
        .env("CARGO_TARGET_DIR", tmp.path().join("target"))
        .output()
        .expect("invoke xark");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "build from src/ failed:\n{err}");
    assert!(
        err.contains("building circuit `arithmetic_square`"),
        "{err}"
    );
    let (ok, out_log) = run_in(&src, &["check"]);
    assert!(ok, "check from src/ failed:\n{out_log}");

    // Named, a non-crate directory is an error, not a walk up.
    let (ok, out_log) = run_in(&src.join(".."), &["build", "src"]);
    assert!(!ok && out_log.contains("no Cargo.toml in src"), "{out_log}");
}

/// A failed setup leaves the previous keys and metadata as they were (never a
/// new key beside old metadata), and no temporary files.
#[test]
fn failed_setup_keeps_the_previous_keys() {
    let tmp = tempdir();
    let out = tmp.path().join("out");
    let (ok, err) = xark_build("arithmetic_square", &out, &tmp.path().join("target"));
    assert!(ok, "build failed: {err}");
    let (ok, err) = xark_setup(&out);
    assert!(ok, "setup failed: {err}");
    let read = |f: &str| std::fs::read(out.join(f)).unwrap();
    let before = (read("pk.bin"), read("vk.bin"), read("metadata.json"));

    // A transcript too small for any circuit: setup fails partway.
    let ptau = tmp.path().join("tiny.ptau");
    std::fs::write(&ptau, common::build_valid_ptau(1)).unwrap();
    let (ok, _, err) = run(&[
        "setup",
        out.to_str().unwrap(),
        "--ptau-file",
        ptau.to_str().unwrap(),
    ]);
    assert!(!ok, "setup with a 2-point transcript succeeded");
    assert_eq!(
        (read("pk.bin"), read("vk.bin"), read("metadata.json")),
        before,
        "a failed setup changed the keys: {err}"
    );
    let stray: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(stray.is_empty(), "{stray:?}");
}
