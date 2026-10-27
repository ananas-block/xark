# spec-02: Prove standard rlib composition

Status: draft. Depends on spec-01 selecting a composition probe.

## Goal

Produce one final application WASM module by linking the existing Xark runtime
and existing SDK bindings with ordinary Cargo and wasm-bindgen. No new Xark type,
export metadata, allocator, RNG, or build protocol is introduced.

## Files

Use the existing application cdylib in the consumer worktree as the preferred
root. Add an optional dependency on Xark's `crates/wasm` through the SDK or app
and retain its existing WASM bindings. The transaction bindings are in private
Rust modules, so a separate wrapper is only appropriate if a narrow public SDK
binding interface is exposed. Reuse current escrow/withdraw fixtures, key
artifacts, and normal wasm-pack tooling. After the approach works,
place a generic downstream-linking regression test in Xark only if there is an
upstream code change to protect.

## Procedure

1. Align local Xark sources through ordinary Cargo path dependencies/patches,
   including the consumer and generated standalone circuit manifests. Match
   wasm-bindgen versions and inspect features; do not accidentally enable
   arkworks parallel execution inside a single-threaded WASM instance.
2. Link the runtime into the existing application root using normal public Rust
   references and re-exports. Inspect
   the final generated JS/TypeScript and raw WASM exports; do not assume all
   dependency bindings survive linking merely because the dependency is an rlib.
3. Verify SDK exports such as escrowTransaction/state decoding alongside
   preloadStreaming/proveStreamingPreloaded/verify. Verify exported classes used
   by generated clients and streaming proofs, not only free functions.
4. If public forwarding is needed, add thin ordinary wasm-bindgen wrappers over
   public functions in the consumer fixture. Check for duplicate JS export names
   and use one clear owner for each binding. No link_section tricks, custom
   linker flags to retain internals, private paths, or copied upstream sources.
5. Verify the upstream wasm-bindgen start hook runs correctly; avoid a second
   start hook or double initialization. Retain standard platform randomness
   through the existing wasm-bindgen/getrandom integration.
6. Build and load both web and Node targets as supported by existing tooling.
   Compare behavior before moving the application build to the combined module.

## Test cases and expected outcomes

- Web module initializes and prepares a transaction: same SDK shape, bytes,
  commitments, and errors as the current bridge.
- Combined module proves and verifies an existing circuit: no changed circuit
  bytecode, keys, or proof ABI.
- Class-returning streaming call survives final binding generation: returned
  object has the existing methods and lifetime/free semantics.
- Native source tree contains both path/git copies of Xark: source alignment
  removes the accidental duplicate, with versions that must differ documented.
- A missing public item is identified by exact API and calling use case: spec-03
  may add that public boundary; unsupported retention behavior ends the probe.

## Acceptance criteria

- A real linked module works using standard Cargo/wasm-bindgen behavior.
- Existing records, serde conversions, and RNG paths work without conversion hacks.
- Required SDK/prover functions and binding classes are present exactly once.
- Module initialization and public Rust interfaces are sufficient.
- The fixture records whether any Xark change is actually needed.
- If clean composition fails, keep the two-module route rather than add a new
  general client framework to force a combined binary.

Flow: two existing rlibs -> normal final cdylib -> generated bindings -> parity probe.
