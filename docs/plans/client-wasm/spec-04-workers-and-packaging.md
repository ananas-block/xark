# spec-04: Connect the existing workers to the chosen module

Status: complete for the combined route. Depends on spec-02.
The stock-runtime route keeps the existing worker imports and packaging layout.

## Goal

Use Xark's existing worker pool and loading APIs with the chosen application
artifact, without modifying upstream worker sources or creating a custom RNG ABI.

## Consumer files

`sdk-libs/program/tests/wasm/web/{app,worker}.js`, server mounts, build output
packaging, and generated-client initialization. Reuse upstream
`crates/wasm/js/{pool,pool-worker,client}.mjs` unchanged unless a separate actual
bug is found.

## Procedure

1. Point main/application and proving-worker imports at the combined generated JS
   module. Each context initializes its own instance; the shared binary does not
   imply a shared heap or thread-safe access to one instance.
2. Call `createPool({ threads, wasm: absoluteGlueUrl })` in browsers and pass the
   supported nodejs glue path in Node. The current pool worker uses dynamic import
   for web and require for Node; supply the correct format, not arbitrary ESM to a
   CommonJS loader. Do not rewrite pool-worker.mjs's relative default.
3. Verify all worker kernels are present: kernel_cols, kernel_rows, kernel_msm,
   and kernel_decompress. Exercise jobs so a missing binding does not hide behind
   successful pool initialization.
4. Pass the initialized combined module via `options.wasm` where generated
   Circuit clients are used, preventing their stock-runtime import from loading a
   second binary. Keep current low-level proving code where it already works.
5. Package generated JS/WASM/types and the unmodified upstream pool scripts with
   their required relative layout, or use the dependency's normal package paths.
   Reference one emitted WASM binary; do not copy sources to manufacture exports.
6. Preserve cross-origin-isolation headers, worker-only Atomics.wait behavior,
   explicit no-pool/single-thread mode, entropy failures, and existing fallback
   behavior. Measure the cost of instantiating the larger binary in every context.

## Test cases and expected outcomes

- Browser proof with more than one pool worker: kernels execute and proof verifies.
- Node pool using supported glue path: workers initialize and perform a kernel.
- No pool / no cross-origin isolation: supported single-threaded proving works.
- Generated client supplied the combined module: no second stock runtime request.
- Missing entropy: transaction encryption/proof generation fails as it does now.

## Acceptance criteria

- Existing pool URL injection is used; no duplicate upstream configuration API.
- Correct export names and classes survive real worker operations.
- Only the chosen artifact is fetched; per-context instances are accounted for.
- The app retains platform RNG bindings and current failure behavior.
- Startup, transfer size, memory, and repeated worker instantiation costs are saved
  alongside build timings for the final route decision.

Flow: chosen module URL -> existing pool loader -> existing kernels -> valid proof.
