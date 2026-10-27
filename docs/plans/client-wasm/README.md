# Application WASM builds with minimal Xark changes

Status: detailed implementation plan; no source implementation started.
Date: 2026-10-27.
Branch: `feat/client-wasm`.
Worktree: `/Users/jorrit/dev/experiments/xark-client-wasm`.
Base: `b443d83ea8ec7f2253610887e9690623ad048aef`.

## Goal and controlling constraint

Reduce application build work and integration overhead while preserving the
existing circuit, transaction, and proof behavior. Prefer supported Xark APIs and
standard Cargo/wasm-bindgen composition. Avoid Xark source changes when possible,
and make a small general API change when that is cleaner than a workaround.

The earlier broad proposal for a new ClientValue trait, derives, client metadata,
RNG ABI, and client-build command is superseded as the default implementation.
None of those features is required merely to link two Rust libraries into one
application WASM module. Moving ArrayVec into Xark is also deferred: the existing
Input implementation already works and moving it does not reduce compilation.

This is a plan, including branch/worktree setup and planning documents only.
Implementation should follow the gates below; source code has not been changed.

## What the current code actually does

| Component | Current build/use | Consequence |
| --- | --- | --- |
| Native Xark CLI | `tools/xark/build.sh` applies two fixes and builds `xark-cli` | Compiler build is independent of browser WASM |
| Circuit frontend | `xark build` builds circuit Rust under `cfg(xark)` | This is needed regardless of client packaging |
| Application bridge | `bridge()` runs wasm-pack on the program crate | Currently one application WASM compilation |
| Xark runtime | Built separately; loaded by the proving worker | Can be cached/prebuilt and reused across applications |
| `xark client` helpers | Current Zolana artifact paths fail `crate_dir()` inference | Does not currently add a second application-helper build |

There is no demonstrated second application compilation to remove. Compare the
real current baseline with each candidate. One final module may remove duplicate
compilation of shared dependencies across the two WASM builds, but it also ties
prover linking/optimization to application changes. Ordinary incremental Cargo
caching may already avoid most Rust recompilation. Report measured tradeoffs.

## Candidate designs and decision rule

1. **Existing two modules with cached/prebuilt Xark runtime:** zero Xark feature
   changes, preserve normal SDK bindings, automate runtime availability and output
   packaging in the consumer. Choose this when it already meets the build goal or
   composition has worse practical costs.
2. **Standard composition in the application crate:** add an optional
   `xark-wasm` rlib dependency through the SDK/application and use the existing
   application cdylib as the WASM root. Keep its existing bindings in place.
   A small separate wrapper crate is an alternative only if both libraries expose
   the required Rust binding functions normally. Try composition if baseline
   measurements still justify consolidating the builds.
3. **Small Xark public API improvement:** only if candidate 2 demonstrates a
   specific missing public boundary. Add a public re-export or focused helper,
   document it, and test downstream composition. Do not introduce a new generic
   serialization or build framework to solve an application-specific problem.

There is no arbitrary LOC cap for a correct fix, but expected Xark production diff
for this revised route is zero, or a few to tens of lines if a public re-export is
needed. A downstream-linking regression fixture may add roughly 100-300 test lines.
These are estimates, not a measured diff. The earlier 2,000-3,500 production LOC
estimate applied to the superseded general client framework.

## Existing extension points

- `crates/wasm/Cargo.toml` already declares `crate-type = ["cdylib", "rlib"]`.
- `crates/wasm/src/lib.rs` publicly exposes proving, verification, typed binding
  classes, and most streaming/kernel functions.
- `createPool({ wasm })` already accepts a custom browser glue-module URL or Node
  glue-module path; `pool-worker.mjs` forwards it to import/require. No source
  rewrite is needed to point pool workers at a composition module.
- The root re-exports omit `kernel_decompress`, `begin_key_transcode`, and
  `KeyTranscoder`, although streaming.rs defines them. Test normal dependency
  export retention first. If downstream forwarding is actually needed, expose
  the specific public item at the crate root instead of accessing private modules.
- The runtime's `Circuit.prover/verifier` accepts an initialized `options.wasm`.
  It need not hardcode the stock runtime when the caller supplies a combined one.
- Upstream already has a wasm-bindgen start hook. Preserve its initialization and
  avoid adding a conflicting wrapper start hook.
- The SDK's generated transaction bindings live inside private Rust modules.
  Keeping the application as the WASM root retains their existing ownership;
  a separate wrapper cannot simply call those private functions. If a wrapper is
  chosen, expose a narrow public SDK function rather than bypass Rust visibility.

A Rust re-export is not proof that wasm-bindgen dependency exports/classes survive
final linking. spec-02 must build and load a real module before accepting this route.

## Repository and branch ownership

The original Xark checkout stays on `remove-nightly-compiler` with its uncommitted
region-index and proof-randomness patches untouched. The feature worktree starts
at the committed base and currently contains only these planning documents.

Before implementation needs the patched tool/runtime, import the two existing
fixes into this worktree as a separate baseline commit and record their source.
Compare with Zolana's `tools/xark/{input-region-indices,proof-randomness}.patch`.
Do not reset, stash, or commit changes in the original checkout. Baseline bug
fixes are accounted separately from the feature's Xark diff.

Composition, build orchestration, loading, and SDK tests belong in a separate local
Zolana worktree/branch, proposed name `feat/xark-wasm-composition`. This plan does
not create that branch or edit consumer code. This Xark branch will hold only a
necessary general API change and its tests if spec-03 establishes one. A valid
outcome is no feature implementation in Xark at all.

No pushing, publishing, release changes, new trusted setup, or key regeneration
is needed. Preserve the existing production proof-randomness policy.

## Ordered work packages

| Spec | Deliverable | Dependencies |
| --- | --- | --- |
| [01](spec-01-baseline.md) | Measured current build and route comparison | Existing working artifacts/tool |
| [02](spec-02-composition.md) | Standard Cargo composition feasibility fixture | 01 selects a composition probe |
| [03](spec-03-public-api.md) | Optional, minimal Xark API fix and regression test | 02 demonstrates an actual gap |
| [04](spec-04-workers-and-packaging.md) | Existing worker/runtime integration and packaging | 02, and 03 only if needed |
| [05](spec-05-build-integration.md) | Consumer build integration, source alignment, caching | 01; 02-04 for combined route |
| [06](spec-06-validation.md) | Behavioral parity, build comparison, route acceptance | Chosen route implemented |

Implement one package at a time: confirm its contract, add focused tests,
implement, verify, review, fix, then commit the completed unit in its owning
repository. After spec-01, select the route based on measurements. After spec-02,
review whether composition uses only normal public interfaces. After spec-06,
choose the final route and remove only obsolete glue. These are engineering
checkpoints, not requirements to pause and ask permission for routine choices.

## Compatibility boundaries

Preserve circuit schemas, input order, ArrayVec padding, circuit digests, proving
keys, proof formats, transaction commitments, state encodings, and application
error behavior. Keep current SDK serde/tsify bindings and native application
records during the probe; do not replace them with fixed-size buffers or opaque
JSON strings just to fit Xark's circuit-input helper interface.

No copying upstream Rust sources into the SDK, include!-based source injection,
private-module access, exported-symbol/linker retention tricks, handwritten
wasm-bindgen metadata, custom getrandom backends, or changes to trusted fixture
hashes to hide encoding drift. Small forwarding functions over public Rust APIs
are acceptable when necessary; duplicating Xark implementation is not.

The browser may instantiate the same combined binary in the main thread, proving
worker, and pool workers. One compiled artifact is not one runtime instance.
Measure transfer/startup/memory costs of that arrangement before choosing it over
a small SDK module plus a prebuilt prover runtime.

## Completion

A completed implementation provides one normal application build entrypoint,
reuses circuit/key outputs correctly, preserves transaction/proof tests, and
includes measured clean/incremental results against the current baseline. It
needs no new general Xark type system and no unsupported integration mechanisms.
If the existing two-module route performs better, keep it and document why.
