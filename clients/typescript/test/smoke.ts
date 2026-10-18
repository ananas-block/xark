// Smoke test: verify a real cube proof through the library (with xark-wasm) and
// confirm tampered proofs are rejected.
//
//   wasm-pack build ../../crates/wasm --target nodejs --out-dir dist/node
//   npm install && npm test
//
// Fixtures (`cube.vk.bin`, `cube.proof.json`) are produced by the xark CLI:
//   xark setup examples/cube && xark prove examples/cube --inputs '{"secret": "3", "result": "27"}'

import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as wasm from "@blueshift-gg/xark-wasm";
import { XarkClient, type ProofBundle } from "../src/index";
import bundle from "./cube.proof.json";

const vk = readFileSync(join(__dirname, "cube.vk.bin"));
const client = new XarkClient(wasm, vk);

const ok = client.verify(bundle as ProofBundle);
console.log(`verify(valid) = ${ok}`);

// A different public input (27 → 28) under the same proof.
const pi = bundle.public_inputs_bin;
const tampered = { ...bundle, public_inputs_bin: pi.slice(0, 18) + "1c" + pi.slice(20) };
const bad = client.verify(tampered as ProofBundle);
console.log(`verify(tampered) = ${bad}`);

if (!ok || bad || client.calldata(bundle as ProofBundle).length !== 256 + 32) {
  console.error("❌ SMOKE FAILED");
  process.exit(1);
}
console.log("✅ xark-client smoke passed");
