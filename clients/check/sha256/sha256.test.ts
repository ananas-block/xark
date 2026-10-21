// The generated `sha256` client (`xark client`) through xark-wasm. Run by
// scripts/client-check.sh, which regenerates `sha256.ts` and builds the keys.
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { artifacts } from "../artifacts";
import { Sha256, Sha256Prover, Sha256Verifier } from "./sha256";

// sha256("abc"): a `Hash` is its 32 bytes.
const digest = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const msg = new TextEncoder().encode("abc");

let prover: Sha256Prover;
let verifier: Sha256Verifier;
beforeAll(async () => {
  prover = await Sha256.prover(wasm, artifacts("sha256"));
  verifier = await Sha256.verifier(wasm, artifacts("sha256"));
});

test("proves a preimage", () => {
  const proof = prover.prove({ msg, digest });
  expect(proof.publicInputs.digest).toBeInstanceOf(Uint8Array);
  expect(proof.publicInputs.digest).toHaveLength(32);
  expect(verifier.verify(proof)).toBe(true);
  expect(verifier.verify(proof, { digest })).toBe(true);
  expect(verifier.verify(proof, { digest: digest.replace(/ad$/, "ae") })).toBe(false);
  // Bytes go in as a `Uint8Array`, byte values, or hex.
  expect(verifier.verify(prover.prove({ msg: "0x616263", digest: proof.publicInputs.digest }), { digest })).toBe(true);
});

test("refuses bad inputs", () => {
  expect(() => prover.prove({ msg, digest: "0x00" })).toThrow(); // a short hash
  expect(() => prover.prove({ msg: [97, 98, 100], digest })).toThrow(); // the wrong message
  expect(() => prover.prove({ msg: [97, 98], digest })).toThrow(); // a short message
});
