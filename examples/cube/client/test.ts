// Node test for the generated `cube` client (`xark client`): prove with typed
// inputs through xark-wasm, verify, and check rejections. Run by
// scripts/client-check.sh, which regenerates `cube.ts` and builds the keys.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { Cube } from "./cube";

const dir = join(__dirname, "..", "target", "xark", "cube");
const read = (f: string) => new Uint8Array(readFileSync(join(dir, f)));
const circuit = new Cube(wasm, {
  circuit: read("circuit.xbc"),
  provingKey: read("pk.bin"),
  verifyingKey: read("vk.bin"),
});
function check(ok: boolean, what: string) {
  if (!ok) throw new Error(`cube: ${what}`);
}
function throws(f: () => unknown): boolean {
  try {
    f();
    return false;
  } catch {
    return true;
  }
}


const { proof, publicInputs } = circuit.prove({ secret: 3, result: 27 });
check(circuit.verify(proof, publicInputs), "the proof verifies");
check(String(publicInputs.result) === "27", "the public input decodes");
check(!circuit.verify(proof, { result: 28 }), "a wrong public input is rejected");
check(throws(() => circuit.prove({ secret: 3, result: 28 })), "unsatisfiable inputs are refused");
console.log("✅ cube client");
