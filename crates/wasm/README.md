# xark-wasm

Generate and verify **Groth16 (BN254) zero knowledge proofs** in the browser
or other JavaScript environments with [xark](https://github.com/blueshift-gg/xark).

```js
import init, { prove, verify } from "@blueshift-gg/xark-wasm";

await init();

const [circuit, pk, vk] = await Promise.all([
  fetch("/circuit/circuit.xbc").then((r) => r.arrayBuffer()),
  fetch("/circuit/pk.bin").then((r) => r.arrayBuffer()),
  fetch("/circuit/vk.bin").then((r) => r.arrayBuffer()),
]);

const { proof, publicInputs } = prove(circuit, pk, { secret: "3", result: "27" });
verify(vk, proof, publicInputs); // true
```

Runs anywhere with Web Crypto: **browsers**, **Node 20+**, **Cloudflare Workers**,
**Vercel Edge**, **Deno**. The circuit, proving/verifying keys, proof, and public
inputs are all **binary** — only the witness inputs (a tiny `name → value` map)
cross the boundary as a plain object. Every binary argument accepts a
`Uint8Array` **or** an `ArrayBuffer`, so the result of `response.arrayBuffer()`
(or a Node `Buffer`) can be passed straight in — no `new Uint8Array(...)` wrap.

## Producing circuit artifacts

Before proving, you need the circuit bytecode and proving/verifying keys.
Produce them with the `xark` CLI:

```sh
xark build    # → target/xark/<name>/circuit.xbc   (binary, self-contained)
xark setup    # → target/xark/<name>/{pk.bin, vk.bin}
```

`circuit.xbc` is the single self-contained build artifact: it encodes both the
solver view (witness generation) and the backend view (the minimized R1CS the
proving key is keyed to)

## Usage

### Browser

```js
import init, { prove, verify } from "@blueshift-gg/xark-wasm";

await init();

const [circuit, pk, vk] = await Promise.all([
  fetch("/circuit/circuit.xbc").then((r) => r.arrayBuffer()),
  fetch("/circuit/pk.bin").then((r) => r.arrayBuffer()),
  fetch("/circuit/vk.bin").then((r) => r.arrayBuffer()),
]);

const { proof, publicInputs } = prove(circuit, pk, { secret: "3", result: "27" });

console.log(verify(vk, proof, publicInputs)); // true
```

### Node.js

The Node build does not require a separate `init()` step.

```js
import { readFileSync } from "node:fs";
import { prove, verify } from "@blueshift-gg/xark-wasm";

// `readFileSync` returns a Buffer, which is a Uint8Array — pass it straight in.
const xbc = readFileSync("examples/cube/target/xark/cube/circuit.xbc");
const pk  = readFileSync("examples/cube/target/xark/cube/pk.bin");
const vk  = readFileSync("examples/cube/target/xark/cube/vk.bin");

const { proof, publicInputs } = prove(xbc, pk, { secret: "3", result: "27" });

console.log(verify(vk, proof, publicInputs)); // true
```

### Performance optimization (preloading)

`prove` re-expands the `.xbc` and re-minimizes the R1CS on every call. For
repeated proofs against the same circuit + key, parse them once with `preload`
and call `prove_preloaded`:

```js
preload(circuit, pk);
const a = prove_preloaded({ secret: "3", result: "27" });
const b = prove_preloaded({ secret: "2", result: "8" });
```

### Large circuits: the streaming prover

Every API proves with the streaming prover: rows are evaluated window by window,
the witness is solved by streaming the hint program, and the proving key is read
one chunk of points at a time, so neither the constraint system nor the decoded
key is ever held whole (Ed25519 verification proves in about 0.5–0.9 GB). Its
proofs are byte-identical to the host prover's for the same randomness. `prove`
needs the whole key as bytes; the APIs below add streaming the key itself as it
downloads, worker threads, and resident keys.

**Which key.** `xark setup` records the key's R1CS form in `metadata.json`
(`r1cs_form`):

* `reduced` — rows stream from `circuit.xbc` alone. Pass nothing extra.
* `minimized` — setup also wrote `r1cs.stream`; pass it as `options.r1cs`.

By default setup picks `reduced` for large circuits (≥ 2²⁰ constraints) and
`minimized` only where the global minimize pass actually helps (sha256: −4.9%);
`--r1cs-form` overrides. A key/circuit mismatch is an error, never a bad proof.

**Stream the key while it downloads** — no SharedArrayBuffer needed, works on the
main thread, and the key is never buffered anywhere:

```js
import * as xark from "@blueshift-gg/xark-wasm";
import { proveFromStream } from "@blueshift-gg/xark-wasm/stream";

const { proof, publicInputs } = await proveFromStream(
  xark, circuit, fetch("/circuit/pk.bin"), inputs,
  { r1cs, onProgress: (bytes) => bar.update(bytes) },   // r1cs only for a `minimized` key
);
```

The witness and quotient polynomial are computed before the first key byte is
needed, so proving overlaps the download. (`beginStreamingProof` → `push(chunk)` →
`finish()` is the underlying API.)

**Decode the key once per device.** A compressed key (the default) costs a field
square root per point every time it is read — ~95% of the witness MSMs in WASM.
`transcodeKey` re-encodes it with uncompressed points (2× the size); store the
result and prove from it on later visits (Ed25519 with 16 workers: 3.5× faster):

```js
import { transcodeKey } from "@blueshift-gg/xark-wasm/stream";

const root = await navigator.storage.getDirectory();
const file = await root.getFileHandle("pk.decoded.bin", { create: true });
await transcodeKey(xark, fetch("/circuit/pk.bin"), { pool }).pipeTo(await file.createWritable());
// later:
const out = await proveFromStream(xark, circuit, (await file.getFile()).stream(), inputs, { pool });
```

**Key already in memory:**

```js
proveStreaming(circuit, pk, inputs, { r1cs });            // one-off

preloadStreaming(circuit, pk, { r1cs, residentKey: true }); // many proofs
proveStreamingPreloaded(inputs);
```

`residentKey` decodes the key once (≈2.2× its compressed size in wasm memory) so
repeat proofs skip point decompression — ZK-KYC proves in the same time as
`prove_preloaded`; sha256 3.6× faster than streamed. Leave it off with a worker
pool, whose workers decompress their chunks in parallel.

**Threads (optional).**

```js
const { createPool, parallelSupported } = await import("@blueshift-gg/xark-wasm/pool");
const pool = parallelSupported() ? await createPool({ threads: 8 }) : undefined;
proveStreaming(circuit, pk, inputs, { pool });   // also accepted by proveFromStream
await pool?.terminate();
```

The blocked FFT's sweeps and every MSM chunk run across workers (each its own wasm
instance) via a `SharedArrayBuffer`. That needs a cross-origin-isolated page
(`Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Embedder-Policy:
require-corp`), and the proving call must run in a Web Worker (it blocks with
`Atomics.wait`). Without isolation `parallelSupported()` is false and the same
prover runs single-threaded with the same memory profile. `tests/browser/run.py`
checks both cases, `proveFromStream(fetch(...))` and smooth-domain keys in headless
Chrome, Firefox and WebKit (Safari's engine) — all proofs byte-identical across
engines.

**Smooth-domain keys** (`xark setup`'s default for dev keys: a QAP domain up to
44% smaller) prove through every API. The key's header states its domain, so `proveFromStream` computes
`h` as soon as the first bytes arrive, overlapping the rest of the download.

**Near the 4 GB limit:** `{ spill: true }` keeps one quotient vector in wasm memory
and parks the other in a JS buffer.

## API

### `prove(circuitXbc, pkBytes, inputs)`

Generates a Groth16 proof, streaming the constraint rows and reading the key a
chunk at a time. For a `minimized` key it rebuilds that circuit from `circuitXbc`
itself, so no `r1cs.stream` is needed.

| argument     | type                          | description                                           |
|--------------|-------------------------------|-------------------------------------------------------|
| `circuitXbc` | `Uint8Array` \| `ArrayBuffer` | `circuit.xbc` (binary, self-contained build artifact) |
| `pkBytes`    | `Uint8Array` \| `ArrayBuffer` | Proving key (`pk.bin`, binary)                        |
| `inputs`     | `object`                      | Witness values; see [Inputs](#inputs)                 |

Returns a `ProofBundle`:

| field             | type         |
|-------------------|--------------|
| `proof`           | `Uint8Array` |
| `publicInputs`    | `Uint8Array` |
| `numPublicInputs` | `number`     |

Throws on a malformed `.xbc`, unknown input, unsatisfiable witness, or malformed key.

#### Inputs

`inputs` is resolved exactly like `xark prove --inputs` (one shared resolver), so the
same values work in the CLI and here. Keys are the circuit's input names; values may be
nested to mirror the input's Rust type:

```js
prove(xbc, pk, {
  id: { dob: 19940312, net_worth: 2400000n, tag: new Uint8Array([1, 2]) }, // field names as in Rust
  path: ["12", "0x0d"],                // an array: element i → path[i]
  msg: "0x616263",                     // a [u8; 3] as one hex string
  ok: true,                            // booleans are 1 / 0
});
```

Scalars may be decimal strings, `0x`-hex strings (reduced mod p), safe-integer numbers,
or bigints. A number outside JavaScript's safe-integer range is rejected rather than
rounded; pass it as a bigint or a string. Flat leaf names (`"id.dob"`, `"path[0]"`)
still work and can be mixed with nested values.

`proof` and `publicInputs` are the canonical compressed bytes (identical to the
host's `proof.bin` / `public_inputs.bin`) — pass them straight to `verify`. For
snarkjs interop, convert them on demand (see `proof_to_snarkjs` below).

> `prove` checks the proof against the key's verifying key before returning it;
> an unsatisfiable witness is reported as an error, never returned as a proof.

### `preload(circuitXbc, pkBytes)`

Parse + cache the `.xbc` and proving key once (replaces prior cached state). The key
is decoded into wasm memory (about 2.2× its compressed size) so repeat proofs skip
point decompression; for the largest circuits use `preloadStreaming`.

### `prove_preloaded(inputs)`

Like `prove` but reuses the artifacts cached by `preload`. Throws if `preload`
hasn't been called.

### `verify(vkBytes, proofBytes, publicInputsBytes)`

| argument            | type                          |
|---------------------|-------------------------------|
| `vkBytes`           | `Uint8Array` \| `ArrayBuffer` |
| `proofBytes`        | `Uint8Array` \| `ArrayBuffer` |
| `publicInputsBytes` | `Uint8Array` \| `ArrayBuffer` |

Returns `true` if valid, `false` if well-formed but not verifying. Throws on
deserialization errors.

### `proof_to_snarkjs(proofBytes)` → `object`

Converts the `proof` `Uint8Array` from `prove()` into the snarkjs proof object.

### `public_inputs_to_snarkjs(publicInputsBytes)` → `string[]`

Converts the `publicInputs` `Uint8Array` from `prove()` into the snarkjs
`public.json` array of decimal strings.

```js
const { proof, publicInputs } = prove(xbc, pk, { secret: "3", result: "27" });
const snarkjsProof  = proof_to_snarkjs(proof);
const snarkjsPublic = public_inputs_to_snarkjs(publicInputs);
```

## Security

Prover randomness comes from the platform CSPRNG (`crypto.getRandomValues`).

## Build

```sh
cargo install wasm-pack
rustup target add wasm32-unknown-unknown
./build.sh                 # default target: bundler (webpack, vite, …)
./build.sh web             # or: nodejs | bundler | module
```

The `module` target (Cloudflare Workers / `workerd`) is built with
`wasm-bindgen` directly, since wasm-pack can't emit `--target module`. A
`release` build of the `module` target will **also rebuild `dist/bundler/`**
and copies its optimized wasm (the raw wasm is byte-identical across targets —
only the JS glue differs).
