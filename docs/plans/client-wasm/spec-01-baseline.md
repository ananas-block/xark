# spec-01: Establish the actual build baseline

Status: complete; see build-results.md. Dependencies: existing working artifacts.

## Goal

Identify avoidable compilation and packaging work before changing an API. Record
separate costs for the native compiler, circuit frontend, application helpers,
and reusable prover runtime.

## Files and tools

Read Zolana's `tools/xark/build.sh`, `sdk-libs/program/src/build/{mod,options}.rs`,
its WASM test package scripts and worker/server, and Xark's WASM manifest/xtask.
Use Cargo build messages/timings, feature trees, final WASM export/import lists,
artifact sizes, and dependency source IDs. Put observations in a development note
in the implementation worktree. Do not benchmark in or clean the original checkout.

## Procedure

1. Reproduce the existing escrow/withdraw flow using the patched runtime and
   existing keys. Confirm which outputs are already present and where they load.
2. Count real application codegen/link operations. Confirm that `xark client`
   currently skips host-helper compilation under `target/zk/...`.
3. Record a cold build using an isolated target/output directory, an unchanged
   rebuild, and a helper-only implementation edit. Use the same Rust toolchain,
   features, optimization, and wasm-opt setting in later comparisons.
4. Inspect duplicated versions/sources of Xark, arkworks, and wasm-bindgen. Distinct
   required arkworks versions are not automatically a bug; duplicate source IDs
   of the same pinned Xark crate are avoidable.
5. Compare a cached/prebuilt stock runtime with local runtime rebuilds. Keep time
   spent building the native compiler separate from application build time.
6. If cached runtime plus current bridge already meets the goal, choose the
   two-module route and proceed to spec-05 without inventing an upstream feature.
   Otherwise perform the bounded composition probe in spec-02. No speedup
   threshold is invented: record clean and edit-cycle results and the reason for
   the choice.

## Test cases and expected outcomes

- Existing build: one application bridge compilation, plus separately accounted
  circuit/runtime work; do not manufacture a second helper build in the baseline.
- Unchanged rebuild: identify Cargo-fresh units and any repeated wasm-bindgen or
  wasm-opt work instead of inferring recompilation from a command being invoked.
- Helper-only edit: identify whether circuit bytecode/keys actually change; record
  preexisting excess work before claiming that a new route fixes it.

## Acceptance criteria

- All four build components have separate counts and timing/size observations.
- The current behavioral tests pass before making an architecture comparison.
- Dependency source/feature and module export/import evidence is saved.
- Runtime availability is distinguishable from compiling it on every app build.
- The chosen next route and its expected benefit are stated with evidence.

Flow: current build -> measured component costs -> choose caching or composition.
