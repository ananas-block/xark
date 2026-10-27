# spec-03: Add only a demonstrated public API gap

Status: conditional draft. Depends on a specific public API gap from spec-02.
Skip the production change entirely if standard composition already works.

## Goal

Make a small, general Xark API improvement when a consumer otherwise cannot
compose the existing runtime cleanly. Keep application bindings and orchestration
in the consumer.

## Candidate files

- `crates/wasm/src/lib.rs`: root re-exports if actually required.
- `crates/wasm` tests: a minimal external-crate binding-generation/load fixture.
- WASM README/API documentation explaining the supported composition interface.

## Known candidate, to verify first

The worker pool calls `kernel_decompress`; it is pub inside streaming.rs but is
not included in lib.rs's root `pub use streaming::{...}` list. The same applies
to `begin_key_transcode` and `KeyTranscoder`. Their wasm-bindgen exports may
already survive dependency linking, so missing root re-exports alone are not
proof of a problem. Expose only the items needed for a clean downstream call.

## Procedure

1. Record the missing API, public consumer call, and why existing exports cannot
   express it. Keep the repro independent of Zolana protocol types.
2. Prefer adding a root pub use for an already-public implementation item.
   Preserve existing names, signatures, classes, and standalone runtime output.
3. Add the smallest downstream cdylib fixture that fails before and works after
   the change, then run normal binding generation and load it in Node/web.
4. Confirm worker-pool URL selection uses existing `createPool({ wasm })`; do not
   add another option or change worker imports for an already-supported case.
5. If fixing the gap requires substantial serialization, type metadata, allocator,
   or compiler machinery, return to the supported two-module route.

## Test cases and expected outcomes

- External Rust crate references the newly public item: compiles normally.
- Downstream generated binding invokes the operation: correct result without a
  second compiled runtime or copied implementation.
- Stock standalone runtime build: public exports and behavior remain compatible.

## Acceptance criteria

- Every added production line addresses the documented public consumer gap.
- No Zolana-specific dependency, DTO, cfg, naming, or build protocol enters Xark.
- Root APIs and standalone WASM retain their existing behavior.
- The downstream composition regression test proves the use case.
- Existing region/proof-randomness fixes remain separate baseline changes.

Flow: demonstrated missing boundary -> minimal public API -> regression proof.
