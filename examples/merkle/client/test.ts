// Node test for the generated `merkle` client (`xark client`): prove with typed
// inputs through xark-wasm, verify, and check rejections. Run by
// scripts/client-check.sh, which regenerates `merkle.ts` and builds the keys.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { Merkle } from "./merkle";

const dir = join(__dirname, "..", "target", "xark", "merkle");
const read = (f: string) => new Uint8Array(readFileSync(join(dir, f)));
const circuit = new Merkle(wasm, {
  circuit: read("circuit.xbc"),
  provingKey: read("pk.bin"),
  verifyingKey: read("vk.bin"),
});
function check(ok: boolean, what: string) {
  if (!ok) throw new Error(`merkle: ${what}`);
}
function throws(f: () => unknown): boolean {
  try {
    f();
    return false;
  } catch {
    return true;
  }
}


const inputs = {
  leaf: 7,
  siblings: [11, 22, 33, 44],
  indexBits: [1, 0, 1, 0],
  root: "19217897426496189115890594488318047711322540293288184119629031241572428947159",
};

const { proof, publicInputs } = circuit.prove(inputs);
check(circuit.verify(proof, publicInputs), "the proof verifies");
check(String(publicInputs.root) === inputs.root, "the root decodes");
check(!circuit.verify(proof, { root: 12345 }), "a wrong root is rejected");
check(throws(() => circuit.prove({ ...inputs, leaf: 8 })), "a non-member leaf is refused");
console.log("✅ merkle client");
