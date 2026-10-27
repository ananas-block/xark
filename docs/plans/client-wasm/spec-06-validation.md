# spec-06: Validate behavior and accept the final route

Status: complete; 14/14 browser tests and native/build checks pass. See build-results.md.

## Goal

Demonstrate correctness and practical build benefit before removing an old output
path. Make the comparison against the current one-bridge baseline explicit.

## Behavioral coverage

Use existing browser/native escrow and withdraw fixtures, round-trip proofs,
independent verification, state decoding, malformed input/error cases, checksum
validation, input-only loading, and randomness tests. Keep fixture commitments,
circuit bytecode digests, keys, field order, ArrayVec padding, transaction/proof
formats, and serialization unchanged.

Compare logical transactions/commitments; encrypted bytes may differ when they
use fresh entropy. Verify decryptability where the native tests cover encryption.
Preserve current large-integer/byte semantics; add targeted coverage only where
composition/binding ownership creates a new concern. Do not introduce a new DTO
serialization layer as part of this work.

For combined output, test dependency exports/classes, initialization, all four
worker kernels, generated client injection, Node/web formats, and input-only
feature exclusion. Test no-pool/single-threaded mode independently from automatic
pool fallback, so a failed worker path cannot masquerade as a passing parallel test.

## Suggested checks

Run appropriate consumer `cargo check`/native transaction tests, then build its
WASM test package and run declaration checks and its existing Playwright suite.
Run focused Xark binding/runtime tests only if Xark source changed, along with:

```sh
cargo test -p xark-tests --test client_functions --release
cargo test -p xark-cli -p xark-frontend --release
```

Build the reusable runtime for the target needed by its existing `npm test` in
`crates/wasm`. Run `npm ci && npm test` in `clients/check` if public runtime
composition behavior or generated-client integration changed. No circuit
implementation changes are expected; if circuit-facing dependencies or ArrayVec
encoding change accidentally, stop and run digest checks rather than regenerate
trusted outputs. `cargo xtask digests --check` is the compatibility check when
that concern exists.

## Build comparison

Record cold, unchanged, and helper-edit build/codegen/link counts and timings
under the same configuration as spec-01. Report artifact transfer/compressed size,
module startup, per-worker memory, and runtime packaging costs. Separate compile,
bindgen, link, and wasm-opt work. A single CLI command alone is not evidence of
less compilation. A combined output may improve clean builds while making edits
or worker startup slower; record that tradeoff rather than declaring success from
only one metric.

## Acceptance criteria

- Existing native/browser transaction and proof behavior passes unchanged.
- Parallel tests prove pool jobs actually execute; input-only mode remains small.
- No trusted fixture/hash changes were needed to mask encoding drift.
- Build comparison uses the real baseline and states gains or regressions plainly.
- The chosen route uses only public APIs and normal Cargo/wasm-bindgen behavior.
- Xark production changes are absent or limited to the demonstrated general gap.
- Obsolete glue is removed only after its replacement passes; if composition adds
  complexity without practical benefit, retain the cached two-module route.

Flow: parity checks + measured build/runtime tradeoffs -> accept route -> remove obsolete glue.
