//! `xark profile` reuses the last `profile.json` while no source of the circuit has
//! changed since, and rebuilds once one has.

mod common;
use common::{tempdir, xark_bin};
use std::path::Path;
use std::process::Command;

/// `xark profile` in `dir`: success, and stderr.
fn profile(dir: &Path) -> (bool, String) {
    let o = Command::new(xark_bin())
        .arg("profile")
        .current_dir(dir)
        .output()
        .expect("invoke xark");
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn profile_rebuilds_only_after_a_change() {
    let tmp = tempdir();
    let dir = tmp.path().join("square");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/arithmetic_square");
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
    let (ok, err) = profile(&dir);
    assert!(ok && err.contains("building circuit"), "{err}");
    let (ok, err) = profile(&dir);
    assert!(
        ok && err.contains("not rebuilding") && !err.contains("building circuit"),
        "{err}"
    );
    // An edit (a newer source) makes the profile stale.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let lib = dir.join("src/lib.rs");
    std::fs::write(&lib, std::fs::read_to_string(&lib).unwrap() + "\n").unwrap();
    let (ok, err) = profile(&dir);
    assert!(ok && err.contains("building circuit"), "{err}");
}
