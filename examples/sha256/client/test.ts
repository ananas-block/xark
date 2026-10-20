// Node test for the generated `sha256` client (`xark client`): prove with typed
// inputs through xark-wasm, verify, and check rejections. Run by
// scripts/client-check.sh, which regenerates `sha256.ts` and builds the keys.
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


// sha256("abc"): a `Hash` takes its 32 bytes (natural encoding) or its halves.
const digest = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const halves = {
  hi: "247859944228867399418143717509236138531",
  lo: "233961684503093977937504818427099878829",
};
const msg = new TextEncoder().encode("abc");

const { proof, publicInputs } = circuit.prove({ msg, digest });
check(circuit.verify(proof, publicInputs), "the proof verifies");
check(String(publicInputs.digest.lo) === halves.lo, "the digest decodes to its halves");
check(circuit.verify(proof, { digest: halves }), "the halves verify the same proof");
check(circuit.verify(proof, { digest }), "so do the 32 bytes");
check(!circuit.verify(proof, { digest: { hi: halves.hi, lo: 1 } }), "a wrong digest is rejected");
check(circuit.verify(circuit.prove({ msg: "0x616263", digest: halves }).proof, { digest }), "hex message, halves");
check(throws(() => circuit.prove({ msg, digest: "0x00" })), "a short hash is refused");
check(throws(() => circuit.prove({ msg: [97, 98, 100], digest })), "the wrong message is refused");
check(throws(() => circuit.prove({ msg: [97, 98], digest })), "a short message is refused before proving");
console.log("✅ sha256 client");
