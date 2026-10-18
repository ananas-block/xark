# Changelog

Before 1.0, a release that changes any circuit bumps the minor version, and each
such circuit is listed under "Circuits that changed": its keys must be made
again. See the toolchain policy in [docs/toolchain.md](docs/toolchain.md#toolchain-policy).

## 0.3.0

### Circuits that changed

**Every circuit.** 0.3 compiles circuits with a new frontend (below), so every
circuit built with 0.2 changes. Rebuild, run `xark build --pin`, and make new
keys. Beyond that, these gadgets now check more:

- `xark-ed25519` and `xark-secp256k1`: points must have canonical coordinates
  (each `< p`), so a point can't be given in two forms. About +1,000 constraints
  for an EdDSA verify and +560 for an ECDSA verify.
- `xark-secp256r1`: the same check, +3 constraints.
- `xark-bignum`: `mod_neg` gave a wrong result for some inputs at full 256-bit
  width; `mod_add` could overflow; `mod_neg(0)` is fixed.

### Changed

- **Stable Rust only.** Circuits are compiled to wasm by any stable Rust from
  1.88 on and lowered by `xark-frontend`. The pinned-nightly MIR compiler
  (`xark-rustc`) is removed, along with `--frontend`, `XARK_FRONTEND`,
  `XARK_TEST_FRONTEND` and `XARK_MIR_COMPAT`. A circuit is identical on every
  supported Rust version. Installing the CLI needs Rust 1.89.
- **What compiles** is documented from the new frontend in
  [docs/subset.md](docs/subset.md). Branches on witness values, small witness
  indices and short witness-bounded loops now work. Constructs the frontend can't
  compile soundly (a witness-sized `memory.grow`, a circuit input declared inside
  a witness branch, a loop whose length depends on a witness and isn't provably
  short) are refused with a message naming the source line.
- **Groth16 prover**: `xark prove` uses `xark-groth16`, a streaming prover that
  never holds the whole constraint system or proving key in memory. Keys and
  proofs are compatible with the arkworks path (byte-identical for the same
  randomness).
- `xark clean` also removes the wasm build cache (`target/xark-wasm`).
- **snarkjs output removed.** `xark setup` no longer writes
  `snarkjs-verification_key.json`, `xark prove` no longer writes
  `snarkjs-proof.json` / `snarkjs-public.json`, and xark-wasm drops
  `proof_to_snarkjs` (`public_inputs_to_snarkjs` becomes `decode_public_inputs`).
  Verify in JavaScript with xark-wasm's `verify`. The proof bundle
  (`<name>-<hash>.proof.json`) now carries `proof_bin` / `public_inputs_bin` (the
  bytes `verify` takes) and `public_inputs` (decimals) instead of the snarkjs
  proof and `public_signals`.
- **xark-client 0.2.0** verifies through xark-wasm: `new XarkClient(wasm, vkBytes)`,
  and `verify` returns a `boolean` (it was a `Promise`). `xark client` scaffolds
  against `vk.bin`.

### Added

- `xark build` prints the circuit digest and writes it to
  `target/xark/<name>/digest`; `xark build --pin` records it in `xark.digest`, and
  every later build refuses a circuit that doesn't match.
- `xark codegen ts`: a typed TypeScript client from `schema.json`.
- `xark_prover::Circuit::check_constrained(inputs)`: `check`, plus a search for
  witness variables the inputs leave free (the "forgot to constrain a hint" bug).
- Generated clients for `cube`, `zk_kyc`, `sha256` and `merkle` are committed in
  `examples/<name>/client/` with tests that prove and verify through xark-wasm;
  `scripts/codegen-check.sh` (in CI) keeps them current.
- Exhaustive witness search (`xark_ir::witness_search`) and
  `scripts/difftest-examples.sh`, which check that each example accepts exactly
  the inputs it should, with exactly one witness.
- `xark-groth16` is published.

### Fixed

- Soundness fixes in the new frontend before release: facts learned inside
  witness-only code are no longer reused by real constraints; copies, overlapping
  stores and sign-extending loads through witness-selected pointers; indirect
  calls check the callee's signature.
- Loading a circuit to solve it (`xark test`, `xark prove`) multiplied out every
  `A·B = C` row, so a row with two 500-term sides became 250,000 terms: a
  12k-constraint Grumpkin circuit took 27 GB and 80 s. Such rows are now factored
  through a helper variable (0.7 GB, about 2 s).
