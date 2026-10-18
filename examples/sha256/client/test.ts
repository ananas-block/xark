// Node test for the generated `sha256` client (`xark codegen ts`): prove with typed
// inputs through xark-wasm, verify, and check rejections. Run by
// scripts/codegen-check.sh, which regenerates `sha256.ts` and builds the keys.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { Sha256 } from "./sha256";

const dir = join(__dirname, "..", "target", "xark", "sha256");
const read = (f: string) => new Uint8Array(readFileSync(join(dir, f)));
const circuit = new Sha256(wasm, {
  circuit: read("circuit.xbc"),
  provingKey: read("pk.bin"),
  verifyingKey: read("vk.bin"),
});
function check(ok: boolean, what: string) {
  if (!ok) throw new Error(`sha256: ${what}`);
}
function throws(f: () => unknown): boolean {
  try {
    f();
    return false;
  } catch {
    return true;
  }
}


// sha256("abc"), as its 128-bit halves.
const digest = {
  hi: "247859944228867399418143717509236138531",
  lo: "233961684503093977937504818427099878829",
};
const msg = new TextEncoder().encode("abc");

const { proof, publicInputs } = circuit.prove({ msg, digest });
check(circuit.verify(proof, publicInputs), "the proof verifies");
check(String(publicInputs.digest.lo) === digest.lo, "the digest decodes");
check(!circuit.verify(proof, { digest: { hi: digest.hi, lo: 1 } }), "a wrong digest is rejected");
check(throws(() => circuit.prove({ msg: [97, 98, 100], digest })), "the wrong message is refused");
check(throws(() => circuit.prove({ msg: [97, 98], digest })), "a short message is refused before proving");
console.log("✅ sha256 client");
