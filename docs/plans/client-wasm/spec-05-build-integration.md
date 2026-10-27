# spec-05: Integrate the selected route in the consumer build

Status: draft. Depends on spec-01; the combined route also requires specs 02-04.

## Goal

Provide one normal user-facing build command and reuse outputs correctly. Keep
Xark changes limited to a proven public API gap, if any.

## Consumer files

`sdk-libs/program/src/build/{mod,options}.rs`, program WASM feature/manifests,
`cli/src/zk.rs` option wiring, WASM test scripts/server, and runtime availability
helper. Xark's client metadata and helper compiler do not change for this task.

## Procedure

1. Keep `zk compile` as the entrypoint, with circuit build/setup reuse accounted
   independently. Preserve package discovery and existing verifier generation.
2. For the two-module route, resolve a compatible prebuilt/cached runtime and build
   the existing SDK module once. Build the patched runtime locally only when the
   chosen artifact is absent or its revision/patch/configuration differs.
3. For the combined route, enable an optional runtime feature in the SDK/app and
   invoke normal wasm-pack once on the existing program crate. Keep that crate as
   the WASM root so private generated SDK binding modules retain their normal
   ownership. Use a separate composition crate only if spec-02 proves it works
   through a narrow public SDK interface. No source is copied or injected into
   Xark, and there is no separate stock-runtime compilation in this route.
4. Use normal Cargo caching and consistent source IDs. Include effective features,
   profile, toolchain, target, SIMD/optimization flags, and pinned Xark source in
   the configuration. Avoid per-circuit application crates with separate target
   caches and do not treat a circuit digest as proof that client code is fresh.
5. Ensure each generated standalone circuit manifest receives the same local path
   overrides during development. Check version/revision validation against the
   selected local CLI without removing production revision checks wholesale.
6. Preserve the existing input-only build: it can omit xark-wasm and stay small.
   Threading options select the existing worker pool behavior, and verifier flags
   select the documented helper surface. Do not leave accepted flags ignored.
7. Produce a complete output in a temporary sibling directory and replace it as a
   generation, or use a content-addressed generation plus one manifest pointer.
   Do not claim two independent file renames atomically replace JS and WASM.
8. Keep the existing two-module output until validation passes. Remove only code
   rendered obsolete by the chosen route; the SDK's typed serialization/bindings
   remain useful in both routes. Do not run Xark's plain client compiler on native
   transaction helpers just to avoid saying the SDK still owns its own bindings.

## Test cases and expected outcomes

- Two circuits in one program package: one application compilation/output.
- Unchanged second build: Cargo artifacts remain fresh; avoid unnecessary binding
  generation/optimization when the actual build outputs are unchanged.
- Helper-only edit: selected application module rebuilds and changed behavior is
  visible; unchanged circuit/key artifacts retain their hashes.
- Feature/source/toolchain edit: correct output invalidation, no stale runtime.
- Failed build: old complete output remains available, not a mixed generation.
- Input-only mode: transaction helpers work without loading proving keys/runtime.

## Acceptance criteria

- One application build invocation owns all package helper exports.
- Pinned source/configuration is explicit and shared where appropriate.
- Application changes and circuit/key changes invalidate the right artifacts.
- Existing supported CLI modes perform their documented actions.
- Packaging uses a consistent complete JS/WASM generation.
- Xark receives no new build framework merely for consumer orchestration.

Flow: one SDK command -> reuse circuit/key work -> chosen app build -> complete output.
