# WASM build measurements

Measured 2026-10-27 on the development host. This section records spec-01 before
composition changes; later route measurements should be appended separately.

## Baseline scope and reproducibility

The consumer source was the original, clean checkout at
`b1f8433814cd4ed0b7ad62adc189fe4de0713eae`. It was read only. All build outputs,
Cargo caches, copied browser harnesses, and the helper-edit source snapshot are
under `/tmp/zolana-wasm-baseline-20261027`. The original Xark checkout at
`b443d83ea8ec7f2253610887e9690623ad048aef` supplied its existing CLI and patched
runtime. Its two existing fixes are represented separately by baseline commit
`8af9f5a` in this feature worktree. Neither original checkout was edited or cleaned.

Application command, from the original consumer root:

```sh
SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk \
CARGO_INCREMENTAL=0 \
CARGO_TARGET_DIR=/tmp/zolana-wasm-baseline-20261027/target \
wasm-pack build sdk-libs/program/tests/wasm/program \
  --release --target web --no-pack --no-opt \
  --out-dir /tmp/zolana-wasm-baseline-20261027/pkg \
  --features wasm --locked --timings -vv
```

Rust was `1.98.1 (48a229cea 2026-09-01)`, wasm-pack `0.15.0`, Node `26.0.0`.
The installed CLT linker cannot parse the default MacOSX27.0 SDK's `.tbd`
architecture list. A failed first attempt took 1.89 seconds; explicitly selecting
the installed MacOSX26.5 SDK fixed the link. That attempt had already produced
some host intermediates, so the successful application measurement is **cold-ish**,
with thirteen fresh Cargo status entries. Registry/Git caches and the matching
application wasm-bindgen CLI were already installed. No OS cache flush was used.

The standalone runtime was also measured with `RUSTUP_TOOLCHAIN=1.98.1`, the same
SDK, release/web/no-opt, and a separate empty `runtime-target-1.98.1`. Its workspace
release profile uses thin LTO and one codegen unit; the consumer keeps its existing
release profile. These existing profiles were not changed to create a speedup.

## Component costs and real compilation counts

| Component / operation | Wall seconds | Cargo seconds | Rustc invocations | Final application/root links |
| --- | ---: | ---: | ---: | ---: |
| Application bridge, cold-ish | 38.060 | 37.08 | 221 total; 101 wasm target | 1 application |
| Application bridge, unchanged | 0.940 | 0.26 | 0; 183 fresh status entries | 0 |
| Application helper implementation edit | 1.724 | 0.93 | 1; 182 fresh status entries | 1 application |
| Standalone runtime, empty target, Rust 1.98.1 | 40.970 | 40.23 | 95 total; 43 wasm target | 1 runtime |
| Standalone runtime, unchanged, Rust 1.98.1 | 1.009 | 0.16 | 0; 78 fresh status entries | 0 |
| Escrow circuit frontend, isolated edited snapshot | 35.217 | not separately instrumented | frontend invokes Cargo once | 1 circuit frontend root |
| Native Xark compiler | reused existing binary | no rebuild | 0 in these measurements | 0 |

Every wasm-pack command still performs its wasm-bindgen/package steps on an
unchanged build. A command invocation is therefore not evidence of recompilation.
The application bridge emits a cdylib and rlib in one root rustc invocation; it is
one application compilation, not two independent helper roots. wasm-opt was off
throughout the comparable application/runtime measurements.

The native compiler is `xark 0.3.0 (b443d83ea8ec)` and its existing executable is
approximately 7.4 MiB. Rebuilding it is unnecessary for an app/helper change and
was not timed again. The SDK's complete compile command also runs native metadata
export tests before the bridge; the table isolates the bridge and does not claim
to time that full orchestration or trusted setup. Existing circuit/key outputs
were reused; no setup or key regeneration ran.

Two actual default `xark client` commands, on copies retaining the
`target/zk/zolana-program-wasm-test-program/{escrow,withdraw}` layout, took 0.117
and 0.052 seconds. They generated TypeScript, produced no `client.wasm`, and ran
no helper compilation. `crates/cli/src/commands/client/mod.rs::crate_dir` recognizes
`<crate>/target/xark/<name>`; the extra Zolana package/entry nesting does not meet
that condition. The ordinary consumer loop therefore means two TypeScript
packaging commands and one application bridge, not three application builds.

## Helper-only edit and circuit stability

A tracked-source snapshot was made under `edit-source`; an unchanged snapshot
warmup took 0.914 seconds with all 183 status entries fresh. Only
`escrow_authority()` was then changed to bind its seed array to a local variable
before calling `ProgramOwner::find`. This function is excluded under `cfg(xark)`
and `cfg(xark_client)`. The edit recompiled only `wasm_test_program`; its library
dependencies and the runtime were fresh. This is a real implementation edit,
without changing a circuit, input representation, or program behavior.

An escrow entry compiled against that edited snapshot produced byte-identical
`circuit.xbc`, `digest`, and `schema.json` to the original artifacts. Circuit
SHA-256 remained
`dde93001df23603d5479193ca498ad8f040157b6e4e2cd889eb11e3306c2199d`.
The entire original escrow/withdraw circuit, digest, proving-key, and verifying-key
hash set remained unchanged after all measurements. This shows that the existing
bridge already permits a helper-only rebuild without a new circuit or keys.

## Sources, features, and final modules

The selected application tree has one Git source ID for all of `xark`,
`xark-groth16`, `xark-ir`, `xark-macros`, `xark-prover`, and `xark-schema`:

```text
git+https://github.com/blueshift-gg/xark?rev=b443d83ea8ec7f2253610887e9690623ad048aef#b443d83ea8ec7f2253610887e9690623ad048aef
```

The selected app graph uses arkworks 0.5 for existing Zolana hashing/circuit
consumers and 0.6 for Xark and native client/proof conversion. Those distinct
versions are required by the current consumers. The whole workspace metadata
also contains 0.4 through unrelated/dev consumers; that is not evidence that all
three versions are linked into this application. App wasm-bindgen is 0.2.128;
standalone Xark's existing lockfile selects 0.2.126. Independent modules permit
that difference. A composition probe must align source IDs and the single final
wasm-bindgen dependency normally through Cargo.

| Final binary | Raw bytes | Raw exports | Raw imports |
| --- | ---: | ---: | ---: |
| Fresh baseline application, Rust 1.98.1/no-opt | 2,948,290 | 140 | 65 |
| Existing patched stock runtime, web | 1,869,215 | 63 | 64 |
| Existing patched stock runtime, node | 1,869,215 | 63 | 64 |
| Standalone runtime rebuilt, Rust 1.98.1/no-opt | 2,940,217 | 63 | 64 |

The fresh application has `escrowTransaction`, `withdrawTransaction`, state
bindings, proof conversion bindings, memory/bindgen support, and numerous
`groth16_solana_vk_setup_*` exports. It does not own the runtime's proving API.
Its imports are in `./wasm_test_program_bg.js`. The runtime imports are in
`./xark_wasm_bg.js`; its exports include `prove`, `proveStreamingPreloaded`,
`schema_new`, `kernel_decompress`, `beginKeyTranscode`, and the session, streaming,
and key-transcoder class methods. Full import/export inventories were captured
using `WebAssembly.Module.imports/exports` rather than inferred from Rust exports.

The deployable stock-runtime + fresh-bridge total is 4,817,505 raw WASM bytes.
The same-toolchain/no-opt two-module comparison is 5,888,507 bytes. Do not compare
a no-opt composition only with the smaller prebuilt optimized/older-toolchain
runtime and attribute the entire difference to composition. These are raw module
sizes, not compressed transfer sizes or aggregate instance memory.

A separate standalone build using Xark's default installed stable Rust 1.95.0
had Cargo time 53.89 seconds and 107.636 seconds end-to-end because wasm-pack
installed its missing wasm-bindgen-cli 0.2.126. Its unchanged run was 1.513
seconds. The pinned Rust 1.98.1 run above reused that tool installation. The
one-time CLI installation is a tool-availability cost, not recurring app work.
The default-toolchain no-opt runtime was 2,215,112 bytes; this illustrates why
recording the toolchain matters for size comparisons.

## Behavioral baseline and existing caller defects

The browser harness was copied to `/tmp`; it loaded the fresh baseline bridge,
original patched runtime, and original escrow/withdraw artifacts and fixtures.
The first five focused tests had one pass and four failures before proving:
the worker passed natural program inputs directly to the low-level solver.

The copied harness then received only these existing integration corrections:

1. Encode inputs with public `new xark.Schema(schemaJson).encodeInputs(JSON.stringify(inputs))`.
2. Copy `ProofBundle.proof` and `.publicInputs` into plain result properties before
   structured cloning the worker response, and free the WASM bundle afterward.
3. Compare encrypted output hashes with the real output prefix, and explicitly
   assert that remaining finalized output slots are zero padded. The withdraw
   native transaction already contains the padded slot; fixture bytes stay intact.

With those changes, **5/5 Chromium tests passed in 6.6 seconds**: public entry
points, both streaming/resident parity cases including independent snarkjs
verification, and both native-transaction/proof round trips. The native transaction
JSON, public commitments, original key checksums, and fixture files were unchanged.
These caller/test defects are baseline fixes, not benefits of module composition.
This was a focused parity suite, not the entire browser suite.

## Route decision supported by this baseline

The current cached-runtime route already has a sub-two-second helper edit and
less-than-one-second unchanged bridge build on this host. There is no duplicate
application-helper compilation to remove. Keep cached/prebuilt runtime support
as the control route. A bounded standard-composition probe is justified only to
measure distribution/integration simplicity and shared dependency linking; it
must beat or acceptably trade against the observed edit cycle. It cannot claim
eliminating a second helper compilation. No Xark source/API change is justified
by these baseline measurements alone.

## Local evidence inventory

All detailed evidence remains under `/tmp/zolana-wasm-baseline-20261027`:

- `command.json`, `runtime-1.98-command.json`, `*-result.json`, and `build-counts.json`.
- `cold.log`, `unchanged.log`, `helper-edit.log`, `runtime-1.98-*.log`, and Cargo
  HTML timing reports in each isolated target's `cargo-timings` directory.
- `features.txt`, `duplicates.txt`, `metadata.txt`, and `dependency-sources.json`.
- `baseline-app-module.json`, `stock-runtime-{web,node}-module.json`, and
  `runtime-built-1.98-module.json` with full raw export/import lists.
- `helper-only.diff`, `circuit-helper-comparison.json`, `keys-before.json`, and
  `keys-after-check.json`.
- `browser.log`, `browser-fixed.log`, `browser-fixed2.log`,
  `browser-corrected.log`, retained failure traces, and corrected test results.
- `clients-result.json`, `client-{escrow,withdraw}.log`, and generated TypeScript.

Temporary evidence paths are host-local and may be removed by normal temporary
file cleanup. The measurements and key conclusions above are the durable record.

## Implemented composition and comparison

The selected route links optional `xark-wasm` into the existing application crate.
A normal `pub use xark_wasm as runtime` retains the proving functions, all six
binding classes, and all four worker kernels. No composition-specific production
change in Xark is necessary. The existing region/randomness fixes remain a
separate baseline commit. No source injection, private APIs, custom linker
retention, or replacement serialization/RNG layer was used.

The SDK default build now produces one complete package with transaction and
proving bindings, generated circuit clients, unmodified public client/pool scripts,
and runtime options. Input-only output excludes the runtime; JS workers load the
combined module through the existing `createPool({ wasm })` API. Generated-client
callers supply `{ wasm: initializedApplicationModule }`, using the existing public
option. Native and circuit builds do not activate the browser runtime dependency.

| Application operation | Baseline seconds | Combined seconds | Combined Rust work |
| --- | ---: | ---: | --- |
| Initial feasibility compilation | 38.060 cold-ish bridge only | 39.19 cold-ish combined | One application root; not a controlled cold benchmark |
| Unchanged direct WASM build | 0.940 | 0.950 | Zero rustc invocations; Cargo 0.18 s |
| Same helper-only implementation edit | 1.724 | 1.439 | One application rustc/link; Cargo 0.69 s |

The standalone baseline runtime separately took 40.970 seconds from its empty
Cargo target. The initial feasibility timings had partially warmed host units
from SDK failures, so these figures do not establish a cold-build speedup ratio.
The small helper-edit difference is not a statistically established performance
improvement. Both designs already have a cheap incremental edit cycle. wasm-bindgen
packaging still runs on unchanged wasm-pack invocations.

| Matching toolchain/no-opt output | Raw WASM bytes | gzip bytes |
| --- | ---: | ---: |
| Baseline bridge | 2,948,290 | 1,081,999 |
| Standalone runtime | 2,940,217 | 659,694 |
| Two-module sum | 5,888,507 | 1,741,693 |
| Combined module | 6,332,202 | 1,680,899 |

Compression used Python gzip with fixed mtime. The combined module is about 7.5%
larger raw and 3.5% smaller than the sum of the separately gzipped modules. The
existing workspace profiles remain different (standalone thin LTO versus the
consumer profile); this is a comparison of the actual supported builds, not a
claim about equal compiler profiles. Input-only output is approximately 2.9 MB
raw. The smaller historical prebuilt runtime remains a useful control, but its
optimization/toolchain differs and is not the no-opt comparison above.

A combined binary is instantiated in the main context, proving coordinator, and
pool workers; it does not share a heap. The browser tests use two pool workers.
The probe records output sizes and functional startup, but does not establish an
aggregate per-worker peak-memory advantage. Applications prioritizing a small
transaction-only module can retain `--no-prover` and a separately cached runtime.

The route was selected because it gives one ordinary source build and a
self-contained output with no new upstream API and no material observed helper-edit
penalty. It is not advertised as faster than reusing an already-built runtime.

Public build API checks passed with tracked local Cargo overrides removed:
combined/default, input-only, single-thread metadata, unpatched-source rejection,
explicit/alias/default prover-feature conflicts, and failed-build preservation.
The last failure-preservation check retained all 15 old files byte-for-byte and
left no staging directory. The application/circuit manifests use generated local
Cargo overrides during development; portable lock identities are retained for the
committed consumer. All eight existing circuit/key/digest artifacts compared by
the orchestration probe remain byte-identical.

Node probes verified escrow and withdraw transaction hashes, proofs and
VerifyingKey, ProvingSession, streamed proof lifecycle, class freeing, pooled
key transcoding, and fresh/seeded randomness policy. Two real pooled proofs
performed 8 FFT calls and 10 MSM calls; key transcoding exercised decompression
five times. Browser coverage also checks actual FFT/MSM counter increases rather
than only pool initialization.

The original browser callers needed Schema encoding and plain ProofBundle
transport/freeing; these are recorded as pre-existing integration fixes. The
consumer's `docs/xark-wasm-preexisting-issues.md` records all encountered baseline
issues, including known open declaration/native-test/setup-policy defects.
The existing declaration checker still fails the baseline SDK's JsValue/any
signatures and has not been weakened to conceal that failure.

Additional host-local evidence:

- Consumer `target/composition-probe-evidence.md` and `/tmp/probe-composition.cjs`.
- `/tmp/zolana-wasm-orchestration-20261027/` public API commands/logs, conflict tests,
  source-override graph, key comparison, and output-preservation results.
- `/tmp/zolana-wasm-composed-measure-20261027/` unchanged/helper-edit commands,
  counts/timings, and exact source-restoration hash.

## Final verification

- Full Chromium correctness suite: **14/14 passed in 21.8 seconds**. This includes
  natural-input encoding, ordinary worker proof transport, native transaction
  parity, independent snarkjs verification, mutation rejection, fresh randomness,
  missing/zero/seed rejection, input-only output, real two-worker FFT/MSM execution,
  explicit no-pool mode, and public Circuit API injection of the combined module.
- SDK native build-feature checks passed; final portable
  `cargo check -p zolana-program --features wasm-prover --locked --offline` passed
  after restoring pinned Git identities. The runtime stays wasm32-only.
- The inherited frontend region-parent regression passed on the Xark branch.
- Public build API generated web, input-only, single-thread metadata, and nodejs
  packages. Node output under the consumer's type:module ancestry loads through
  CommonJS and its injected two-worker pool initializes and terminates normally.
- Source-patch rejection, explicit/transitive/default no-prover conflict checks,
  and preservation of all old output files on intentional build failure passed.
- Existing trusted fixtures, circuit/key hashes, and original checkouts stayed
  unchanged. The temporary helper edit was restored byte-for-byte.
- Original `check:dts` remains a documented pre-existing failure; the obsolete
  native conversion test and unrelated setup/SBF/dependency findings are also
  recorded as open in the requested issue file.

The SDK public build API was exercised by a disposable ordinary Rust driver, so
its complete compile path ran without rebuilding the unrelated full CLI dependency
graph. The consumer CLI forwards the existing SDK option types, and its help changes
were reviewed. This record does not claim an unrelated full consumer CLI, SBF,
or local-validator test run.

## Local branch handoff

Consumer implementation is committed as `76d892261` on
`feat/xark-wasm-composition`, in
`/Users/jorrit/orca/workspaces/zolana4/zolana-wasm-composition`.
The requested issue record is committed at
`docs/xark-wasm-preexisting-issues.md` in that branch.

The updated consumer `tools/xark/build.sh` successfully built this feature
checkout with the compatible host SDK and stable Rust in 35.02 seconds. Its local
executable is `target/release/xark`, reporting `xark 0.3.0 (8af9f5ad080a)`; the
following documentation-only commit does not change its implementation. Set
`XARK_SOURCE=/Users/jorrit/dev/experiments/xark-client-wasm` to use it in the
consumer. Original checkout sources and their uncommitted patches remain untouched.
