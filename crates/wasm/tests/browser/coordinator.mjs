// Runs in a module Web Worker (proveStreaming blocks with Atomics.wait, which a
// browser main thread may not do). Proves sha256("abc") single-threaded and — if
// this page is cross-origin isolated — again with a worker pool, then reports.
// With a `pk_smooth.bin`/`vk_smooth.bin` fixture (a `--domain smooth` key) it also
// proves against that, exercising the mixed-radix FFT on the same paths.
import init, { proveStreaming, verify, wasmMemoryBytes } from "../../dist/web/xark_wasm.js";
import * as xark from "../../dist/web/xark_wasm.js";
import { createPool, parallelSupported } from "../../js/pool.mjs";
import { proveFromStream } from "../../js/stream.mjs";

const INPUTS = {
  "msg[0]": "97", "msg[1]": "98", "msg[2]": "99",
  "digest.hi": "247859944228867399418143717509236138531",
  "digest.lo": "233961684503093977937504818427099878829",
};
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
const bytes = async (p) => new Uint8Array(await (await fetch(p)).arrayBuffer());

self.onmessage = async () => {
  const out = { crossOriginIsolated: self.crossOriginIsolated, supported: parallelSupported() };
  try {
    await init();
    const [xbc, pk, vk] = await Promise.all(["circuit.xbc", "pk.bin", "vk.bin"].map((f) => bytes(`/fixtures/${f}`)));
    let t = performance.now();
    const single = proveStreaming(xbc, pk, INPUTS, { seed: 5 });
    out.singleMs = Math.round(performance.now() - t);
    out.singleProof = hex(single.proof);
    out.singleVerifies = verify(vk, single.proof, single.publicInputs);
    // The key streamed straight from fetch(), never buffered.
    t = performance.now();
    const fromFetch = await proveFromStream(xark, xbc, fetch("/fixtures/pk.bin"), INPUTS, { seed: 5 });
    out.fetchStreamMs = Math.round(performance.now() - t);
    out.fetchStreamProof = hex(fromFetch.proof);
    const smooth = await fetch("/fixtures/pk_smooth.bin");
    let smoothPk = null;
    if (smooth.ok) {
      smoothPk = new Uint8Array(await smooth.arrayBuffer());
      const svk = await bytes("/fixtures/vk_smooth.bin");
      const s = proveStreaming(xbc, smoothPk, INPUTS, { seed: 5 });
      out.smoothSingleProof = hex(s.proof);
      out.smoothSingleVerifies = verify(svk, s.proof, s.publicInputs);
      // Streamed: with the domain hint, and without (h is recomputed).
      for (const [k, opts] of [["smoothFetchHinted", { domainSize: 36864 }], ["smoothFetchUnhinted", {}]]) {
        const r = await proveFromStream(xark, xbc, fetch("/fixtures/pk_smooth.bin"), INPUTS, { seed: 5, ...opts });
        out[k] = hex(r.proof);
      }
      out.smoothVk = svk;
    }
    if (out.supported) {
      const pool = await createPool({ threads: 4 });
      if (smoothPk) {
        const s = proveStreaming(xbc, smoothPk, INPUTS, { seed: 5, pool });
        out.smoothPoolProof = hex(s.proof);
        out.smoothPoolVerifies = verify(out.smoothVk, s.proof, s.publicInputs);
      }
      t = performance.now();
      const par = proveStreaming(xbc, pk, INPUTS, { seed: 5, pool });
      out.poolMs = Math.round(performance.now() - t);
      out.poolProof = hex(par.proof);
      out.poolVerifies = verify(vk, par.proof, par.publicInputs);
      out.poolStats = pool.stats;
      await pool.terminate();
    } else {
      try {
        await createPool();
        out.createPool = "created";
      } catch (e) {
        out.createPool = `refused: ${e.message}`;
      }
    }
    delete out.smoothVk;
    out.wasmMemoryMB = wasmMemoryBytes() / 2 ** 20;
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  self.postMessage(out);
};
