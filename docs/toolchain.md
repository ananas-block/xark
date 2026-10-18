# Toolchains

`xark build` needs **only stable Rust, 1.88 or newer** (the `xark` crate's
`rust-version`; it uses let-chains). Installing the CLI itself needs 1.89 (the
workspace `rust-version`, set by its dependencies). The circuit crate is compiled by the ambient
`cargo`/`rustc` for `wasm32-unknown-unknown` (added with `rustup` on first use), and
`crates/frontend` runs the module to lower it. Every circuit operation is an opaque
wasm import, so the constraint system doesn't depend on the compiler version:
`scripts/stable-digests.sh --check` rebuilds every example and compares its R1CS
digest with `tests/stable-digests.txt`, and CI runs it on 1.88, stable and beta.
(All 70 examples were identical on 1.88, 1.89, 1.93, 1.96, 1.98 and a 2026-10
nightly when this was introduced.) See `crates/frontend/README.md` for the design.

`build`, `check` (editor diagnostics, `--message-format=json` included), `profile`
and `test` all share one cache (`target/xark-wasm`). Builds carry DWARF line tables
(`debug = "line-tables-only"`) so constraints and rejections are attributed to source
lines; they don't change the circuit or the lowering time, and compile time is the
same within noise (only the `.wasm` grows).

Nothing in the repository needs nightly. (Earlier releases had a second frontend,
`xark-rustc`, that read MIR through `rustc_private` on a pinned nightly. It was
removed once the stable frontend matched or beat it on every example: setup-minimized
circuits within +0.3% everywhere and up to 7% smaller, the same accept/reject verdict
on every example's test inputs, and faster, smaller builds.)

## When a circuit digest changes

`scripts/stable-digests.sh --check` failing means one of two things:

- **A toolchain changed a circuit** — rustc lowered some witness operation
  differently (LLVM rewriting integer ops). That is a bug: report it with the
  toolchain and example, and pin the operation through an intrinsic.
- **The lowering changed on purpose** — run `scripts/stable-digests.sh --update`,
  review the diff, re-check the snapshot suite (`cd crates/lang && cargo test
  --release --test snapshot -- --include-ignored`) and the Lean-model bridges, and
  regenerate any keys built from the old circuits.
