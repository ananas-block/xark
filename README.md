# xark — write, compile, prove and verify zero-knowledge circuits in Rust

[![CI](https://github.com/blueshift-gg/xark/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/xark/actions/workflows/ci.yml)

xark takes a circuit written as ordinary Rust all the way to an on-chain proof.
You write the circuit in Rust; xark compiles it with your stable `rustc` (to
wasm32), lowers the module to R1CS, and proves it with Groth16 over BN254 — with a verifier that runs on Solana. There is no
separate circuit DSL: **gadgets are ordinary Rust libraries** that lower to a
small primitive constraint set, so the backend stays lean and the frontend
stays expressive.

## Installation

xark needs only stable Rust: 1.89 or newer to install the CLI, 1.88 or newer to
build circuits:

```bash
cargo install xark-cli
xark doctor        # checks your setup
```

`xark build` compiles your circuit crate with the toolchain you already have (to
`wasm32-unknown-unknown`, which it adds with `rustup` on first use). To build from source instead, append `--git https://github.com/blueshift-gg/xark`.

## As a language (library)

Write a circuit as a `#![no_std]` function over `Field` values, using the `xark`
prelude. `require_eq` emits a circuit equality constraint (not a native `bool`);
`Private<T>` / `Public<T>` mark input visibility; `Field` supports `+ - *`,
`.pow(n)` for exponentiation by a constant, and `^` as boolean XOR.

```rust
#![no_std]
use xark::prelude::*;

/// Prove knowledge of a cube root: `secret^3 == result`.
pub fn circuit(secret: Private<Field>, result: Public<Field>) {
    require_eq(secret.pow(3), result);
}
```

## As a toolchain (CLI)

```bash
# Scaffold a new circuit crate, pre-wired for rust-analyzer diagnostics.
xark init my-circuit

# Compile: Rust → wasm → xark-IR → R1CS. All output (artifacts + an isolated
# cargo target) lives under the crate's target/xark/.
xark build examples/cube
# → writes examples/cube/target/xark/cube/ (circuit.xbc + schema.json)

# Generate a typed TypeScript client from schema.json: no setup or proof needed.
xark codegen ts examples/cube
# → examples/cube/target/xark/cube/cube.ts

# Generate Groth16 keys. With no .ptau this produces an INSECURE dev key
# (single-party OsRng); pass --ptau-file (or run `xark ceremony`) for production.
xark setup examples/cube

# Solve the witness from your inputs, then produce AND verify a Groth16 proof.
xark prove examples/cube --input secret=3 --input result=27
# → ✅ Proof produced and self-checked (1 public input).

# Validate a circuit WITHOUT emitting artifacts — subset violations as rustc
# diagnostics with source spans (great for editors / CI).
xark check examples/cube
```

### Typed clients

`xark build` also writes `schema.json`: every input's name, visibility, and type
(`Field`, `uN` widths, arrays, tuples, and `#[derive(CircuitInput)]` structs), plus the
public inputs in proof order. `xark codegen ts` turns it into one dependency-free `.ts`
file with an interface per struct and typed `prove` / `verify` over the `xark-wasm`
module you pass in:

```ts
import * as wasm from "xark-wasm";
import { TypedKyc } from "./typed_kyc.ts";

const kyc = new TypedKyc(wasm, { circuit, provingKey, verifyingKey });
const { proof, publicInputs } = kyc.prove({
  id: { document: bytes, born: 19940312, netWorth: 2_400_000n, salt },
  policy: { bornBefore: 20081015, minNetWorth: 1_000_000 },
  commitment,
});
kyc.verify(proof, publicInputs); // true
```

Fields are camelCased; values are range- and length-checked against their Rust types
before proving, with errors that name the field (`id.born: 4294967296 is outside u32`).

## Editor diagnostics (rust-analyzer)

`xark check <crate-dir>` runs the full `rustc` frontend *and* the xark subset
validator, surfacing every rejection as a **real `rustc` diagnostic with a source
span**. With `--message-format=json` it emits the same JSON stream as `cargo
check`, so an editor shows live rejections on save. `xark init` writes this
wiring; to add it to an existing crate, point `rust-analyzer`'s check command at
`xark` (which must be on `PATH`):

```toml
# rust-analyzer.toml
[check]
overrideCommand = ["xark", "check", ".", "--message-format=json"]
```

```jsonc
// .vscode/settings.json (VS Code equivalent)
{
  "rust-analyzer.check.overrideCommand": ["xark", "check", ".", "--message-format=json"]
}
```

Replace `.` with the crate directory (e.g. `examples/cube`) when the editor is
opened above the circuit crate. A violation then appears inline, e.g.:

```text
error: witness-dependent control flow is not supported
 --> src/lib.rs:7:5
note: branch conditions must be compile-time constants (e.g. loop bounds)
```

## The pipeline

```text
Rust source  →  rustc (stable, wasm32)  →  xark-IR  →  R1CS  →  Groth16 (BN254)  →  Solana verifier
```

`xark build` runs `cargo` on your circuit crate for `wasm32-unknown-unknown` with
`--cfg xark`, where every circuit operation (`Field` arithmetic, comparisons,
hints, `require_eq`, input binding) is a call to an `xark.*` wasm import. rustc
does the hard work — parse, type-check, borrow-check, monomorphize, optimize — and
xark then runs the module with those imports implemented as the circuit builder:
loops and calls with known values simply execute (that *is* the unrolling), and
witness values flow into constraints. The circuit is the same under every stable
rustc (CI checks every example on 1.88, stable and beta), and constraint-reducing
rewrites are proven exact in Lean (`formal/Formal/Rewrites.lean`). Details:
[`crates/frontend/README.md`](crates/frontend/README.md).

## snarkjs compatibility

`xark setup` and `xark prove` emit snarkjs-compatible JSON alongside the native
binary artifacts: `snarkjs-verification_key.json` (from `xark setup`),
`snarkjs-proof.json` and `snarkjs-public.json` (from `xark prove`). Verify
directly with snarkjs (enabling verification in JS/browser/Node environments):

```bash
snarkjs groth16 verify \
  target/xark/<name>/snarkjs-verification_key.json \
  target/xark/<name>/snarkjs-public.json \
  target/xark/<name>/snarkjs-proof.json
```

## Crates and gadgets

* **`xark`** (`crates/lang`, `#![no_std]`, stable) — the language library; its
  `prelude` provides the marker primitives (`Field`, `require_eq`,
  `Private`/`Public`). The CLI is the **`xark`** binary (stable; published as the
  `xark-cli` crate); **`xark-frontend`** turns a circuit's wasm into R1CS.
* **Backend** — `xark-backend` (Groth16 setup/prove/verify, trusted setup,
  serialization) and `xark-verifier` (the `no_std` on-chain Solana verifier).
  Both are frontend-agnostic.

Gadgets are **separate crates you add only when you need them**, all under
**`gadgets/`** — kept apart from the core toolchain so they're easy to fork or
use standalone. Shared circuit libraries: `xark-bits` (booleanity /
bit-decomposition), `xark-bignum` (non-native arithmetic, used by the EC
gadgets), `xark-curve` (curve macros), `xark-hash` (`Hash`/`Digest` types). Leaf
gadgets: `xark-poseidon`, `xark-poseidon2`, `xark-sha256`, `xark-keccak`,
`xark-mimc`, `xark-blake3`, `xark-blake2s`, `xark-aes`, `xark-pedersen`,
`xark-grumpkin`, `xark-secp256k1`, `xark-secp256r1`, `xark-ed25519`.

Adding a gadget is just a Cargo dependency:

```toml
# examples/poseidon/Cargo.toml
[dependencies]
xark = { path = "../../crates/lang" }
xark-poseidon = { path = "../../gadgets/xark-poseidon" }
```

```rust
#![no_std]
use xark::prelude::*;
use xark_poseidon::hash;
// ... call `hash(..)` inside `circuit` and `require_eq` the result.
```

## Examples

`examples/` holds runnable circuits. The simple ones (`cube`,
`difference_of_squares`, `linear`, `inverse`) depend only on `xark`; the rest
pull in the gadget crates they exercise. Build any with `xark build
examples/<name>`.

## Status

> **Experimental.** Do not use generated Groth16 parameters or proofs in
> production until the lowering, serialization, and setup process have been
> independently audited. For real deployments run a multi-party phase-2 trusted
> setup (`xark`'s ceremony path); never ship a key produced in insecure dev mode.

* **Trusted setup** — `.ptau` phase-1 parsing with admissibility checks, phase-2
  setup derived from a `.ptau`, and a multi-contributor phase-2 MPC ceremony with
  Schnorr proofs of knowledge and δ-consistency pairing checks. See
  [`docs/trusted-setup.md`](docs/trusted-setup.md).
* **Verifier** — `xark-verifier` verifies proofs on Solana via the `alt_bn128`
  syscalls.

No external audit has been performed; see [`docs/audit-status.md`](docs/audit-status.md).

## Development

```bash
# Install the CLI (puts `xark` on PATH):
cargo install --path crates/cli

cargo test --workspace --release
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# `crates/lang` is its own workspace, so its suites run separately:
cd crates/lang && cargo test --release --test snapshot --test semantics_fuzz
cd crates/lang && cargo test --release --test snapshot -- --include-ignored  # + heavy KATs
XARK_FUZZ_CASES=400 cargo test --release --test semantics_fuzz  # wider fuzzing

scripts/stable-digests.sh --check   # every example's circuit, unchanged
```

Toolchains and circuit reproducibility: [`docs/toolchain.md`](docs/toolchain.md).
Writing circuits — the supported subset and rejections: [`docs/subset.md`](docs/subset.md).
Architecture: [`docs/architecture.md`](docs/architecture.md).
Security walkthrough: [`docs/security.md`](docs/security.md).
