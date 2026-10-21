//! `#[input]` on an `impl` block makes its methods client functions, from any crate:
//! a gadget's functions reach the client of every circuit whose inputs use its
//! types, and nothing else.

mod common;
use common::{tempdir, xark_bin};
use std::path::Path;
use std::process::Command;

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// `xark <args>` in `dir`: success, and stdout + stderr.
fn xark(dir: &Path, args: &[&str]) -> (bool, String) {
    let o = Command::new(xark_bin())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("invoke xark");
    let out = String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
    (o.status.success(), out)
}

#[test]
fn a_gadgets_functions_reach_the_client() {
    let tmp = tempdir();
    let lang = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/lang");
    let lang = lang.canonicalize().unwrap();
    let lints = "[lints.rust]\nunexpected_cfgs = { level = \"warn\", check-cfg = ['cfg(xark)'] }\n";
    // A third-party gadget: an input type with its own functions, and a helper
    // for a type no circuit below takes.
    write(
        &tmp.path().join("gadget/Cargo.toml"),
        &format!(
            "[package]\nname = \"gadget\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             [dependencies]\nxark = {{ path = {:?} }}\n{lints}",
            lang.display().to_string()
        ),
    );
    write(
        &tmp.path().join("gadget/src/lib.rs"),
        "#![cfg_attr(xark, no_std)]\nuse xark::prelude::*;\n\
         /// A range of positions.\n\
         #[input]\npub struct Span { pub lo: u32, pub hi: u32 }\n\
         #[input]\nimpl Span {\n\
         /// `lo..hi`, checked.\n\
         pub fn new(lo: u32, hi: u32) -> Span { assert!(lo <= hi, \"lo above hi\"); Span { lo, hi } }\n\
         /// How many positions.\n\
         pub fn len(&self) -> u32 { self.hi - self.lo }\n}\n\
         #[input]\npub struct Unused { pub x: Field }\n\
         #[input]\nimpl Unused {\npub fn zero() -> Unused { Unused { x: Field::zero() } }\n}\n",
    );
    write(
        &tmp.path().join("circ/Cargo.toml"),
        &format!(
            "[package]\nname = \"circ\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             [dependencies]\nxark = {{ path = {:?} }}\n\
             gadget = {{ path = \"../gadget\" }}\n[workspace]\n{lints}",
            lang.display().to_string()
        ),
    );
    write(
        &tmp.path().join("circ/src/lib.rs"),
        "#![cfg_attr(xark, no_std)]\nuse xark::prelude::*;\nuse gadget::Span;\n\
         #[circuit]\npub fn circ(s: Private<Span>, n: Public<u32>) {\n\
         require_eq(Field::from(s.hi) - Field::from(s.lo), Field::from(n));\n}\n",
    );
    let circ = tmp.path().join("circ");
    let (ok, out) = xark(&circ, &["build"]);
    assert!(ok, "build failed:\n{out}");
    let (ok, out) = xark(&circ, &["client"]);
    assert!(ok, "client failed:\n{out}");
    assert!(out.contains("skipping `Unused::zero`"), "{out}");
    let dir = circ.join("target/xark/circ");
    assert!(dir.join("client.wasm").exists());
    let ts = std::fs::read_to_string(dir.join("circ.ts")).unwrap();
    for want in [
        "export const Span = {",
        "   * `lo..hi`, checked.",
        "  new(lo: number, hi: number): SpanValue & SpanMethods {",
        "  len(span: Span): number {",
        "export interface SpanMethods {",
    ] {
        assert!(ts.contains(want), "missing {want:?} in:\n{ts}");
    }
    assert!(!ts.contains("Unused"), "{ts}");
}

/// A circuit with no client functions gets no `client.wasm` (nor its loader).
#[test]
fn no_functions_no_module() {
    let tmp = tempdir();
    let dir = tmp.path().join("square");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/arithmetic_square");
    for f in ["Cargo.toml", "src/lib.rs"] {
        let text = std::fs::read_to_string(src.join(f)).unwrap();
        // The copy's path dependencies, absolute.
        let abs = src.join("../../crates").canonicalize().unwrap();
        write(
            &dir.join(f),
            &text.replace("../../crates", abs.to_str().unwrap()),
        );
    }
    let (ok, out) = xark(&dir, &["build"]);
    assert!(ok, "build failed:\n{out}");
    let (ok, out) = xark(&dir, &["client"]);
    assert!(ok, "client failed:\n{out}");
    let out_dir = dir.join("target/xark/arithmetic_square");
    assert!(!out_dir.join("client.wasm").exists());
    let ts = std::fs::read_to_string(out_dir.join("arithmetic_square.ts")).unwrap();
    assert!(ts.contains("  client: false,") && !ts.contains(".call("));
}
