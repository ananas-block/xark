# Changelog

Before 1.0, a release that changes any circuit bumps the minor version, and each
such circuit is listed under "Circuits that changed": its keys must be made
again. See the toolchain policy in [docs/toolchain.md](docs/toolchain.md#toolchain-policy).

## 0.3.0

### Circuits that changed

**Every circuit.** 0.3 compiles circuits with a new frontend (below), so every
circuit built with 0.2 changes: rebuild and make new keys. Beyond that, these
gadgets now check more:

- `xark-ed25519` and `xark-secp256k1`: points must have canonical coordinates
  (each `< p`), so a point can't be given in two forms. About +1,000 constraints
  for an EdDSA verify and +560 for an ECDSA verify.
- `xark-secp256r1`: the same check, +3 constraints.
- `xark-bignum`: `mod_neg` gave a wrong result for some inputs at full 256-bit
  width; `mod_add` could overflow; `mod_neg(0)` is fixed.

### Changed

- **Stable Rust only.** Circuits are compiled to wasm by any stable Rust from
  1.89 on and lowered by `xark-frontend`. The pinned-nightly MIR compiler
  (`xark-rustc`) is removed, along with `--frontend`, `XARK_FRONTEND`,
  `XARK_TEST_FRONTEND` and `XARK_MIR_COMPAT`. A circuit is identical on every
  supported Rust version. The minimum Rust is 1.89, for both the CLI and
  circuits.
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
- **One proving path.** `xark prove` always uses the streaming prover from
  `circuit.xbc`, and tells a key's row form from its metadata or, failing that,
  its size. Removed: `--r1cs` / `--circuit` (reading `r1cs.json` / `circuit.json`)
  from `prove`, `setup`, `verify`, `inspect` and `ceremony init`; `prove
  --stream` (always streams now); `setup --cache` and the `r1cs.min.wcz` cache
  (`r1cs.stream` replaces it). `xark build --emit-json` still writes the JSON as
  a debugging view.
- **arkworks' Groth16 removed.** `xark-groth16` now owns the whole Groth16 stack:
  key generation, the prover, verification, and the `Proof` / `VerifyingKey` /
  `ProvingKey` types, which serialize byte-for-byte like `ark-groth16`'s, so
  existing key and proof files still load. arkworks is only the BN254 arithmetic
  (`ark-bn254` / `ark-ff` / `ark-ec`); `ark-groth16`, `ark-relations` and
  `ark-snark` are test-only, as an independent reference. API changes:
  `xark_backend::{setup, prove, stream_prove}` are gone;
  `xark_backend::ptau::setup_from_ptau` takes a constraint source;
  `xark_prover::XarkCircuit` no longer implements arkworks' circuit trait; and
  verification rejects a wrong number of public inputs instead of ignoring the
  difference.
- **snarkjs output removed.** `xark setup` no longer writes
  `snarkjs-verification_key.json`, `xark prove` no longer writes
  `snarkjs-proof.json` / `snarkjs-public.json`, and xark-wasm drops
  `proof_to_snarkjs` (`public_inputs_to_snarkjs` becomes `decode_public_inputs`).
  Verify in JavaScript with xark-wasm's `verify`.
- **No proof bundle.** `xark prove` no longer writes `<name>-<hash>.proof.json`
  (it duplicated `proof.bin` / `public_inputs.bin`) or prints the proof's
  on-chain bytes; it prints the proof's SHA-256 fingerprint. The Solana
  verifier from `xark export` builds its own instruction data.
- **`xark client` generates a typed TypeScript client** from `schema.json` (typed
  `prove` / `verify` through xark-wasm, no setup needed). It replaces the old
  starter scaffold, and the `xark-client` npm package (snarkjs verify) is removed:
  prove and verify with xark-wasm or the generated client.

### Added

- `xark build` prints the circuit digest (a fingerprint of the R1CS) and writes it
  to `target/xark/<name>/digest`.
- Proving from Rust: `xark_prover::circuit("name").prove(inputs)` proves with the
  built circuit and its `pk.bin` and returns the proof and public-input bytes
  (`CircuitProof`, the same bytes `xark prove` writes); `prove_with_key` takes
  another key. The throwaway-keys round trip it used to do is now `prove_dev`.
- `xark_prover::Circuit::check_constrained(inputs)`: `check`, plus a search for
  witness variables the inputs leave free (the "forgot to constrain a hint" bug).
- Generated clients for `cube`, `zk_kyc`, `sha256` and `merkle` are committed in
  `examples/<name>/client/` with tests that prove and verify through xark-wasm;
  `scripts/client-check.sh` (in CI) keeps them current.
- Exhaustive witness search (`xark_ir::witness_search`) and
  `scripts/difftest-examples.sh` (daily in CI), which check that each example
  accepts exactly the inputs it should, with exactly one witness. It covers every
  example except the two ECDSA circuits, including the whole ed25519 verify
  circuit; the ECDSA ones are searched block by block.
- `xark-groth16` is published.

### Fixed

- Witness search skips rows it provably can't learn from, so wide circuits decide
  in seconds instead of timing out (a Grumpkin IPA search: 107 s → 4 s).
- `xark ceremony init` reads the build's `circuit.xbc` like every other command
  (it required an `r1cs.json`, which `xark build` no longer writes by default),
  and the ceremony has a CLI end-to-end test again.

- Soundness fixes in the new frontend before release: facts learned inside
  witness-only code are no longer reused by real constraints; copies, overlapping
  stores and sign-extending loads through witness-selected pointers; indirect
  calls check the callee's signature.
- Loading a circuit to solve it (`xark test`, `xark prove`) multiplied out every
  `A·B = C` row, so a row with two 500-term sides became 250,000 terms: a
  12k-constraint Grumpkin circuit took 27 GB and 80 s. Such rows are now factored
  through a helper variable (0.7 GB, about 2 s).
