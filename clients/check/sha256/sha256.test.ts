// The generated `sha256` client (`xark client`) through xark-wasm. Run by
// scripts/client-check.sh, which regenerates `sha256.ts` and builds the keys.
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { artifacts } from "../../../clients/check/artifacts";
import { Sha256 } from "./sha256";

const sha256 = new Sha256(wasm, artifacts("sha256"));
// sha256("abc"): a `Hash` is its 32 bytes.
const digest = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const msg = new TextEncoder().encode("abc");

test("proves a preimage", () => {
  const { proof, publicInputs } = sha256.prove({ msg, digest });
  expect(publicInputs.digest).toBeInstanceOf(Uint8Array);
  expect(publicInputs.digest).toHaveLength(32);
  expect(sha256.verify(proof, publicInputs)).toBe(true);
  expect(sha256.verify(proof, { digest })).toBe(true);
  expect(sha256.verify(proof, { digest: digest.replace(/ad$/, "ae") })).toBe(false);
  // Bytes go in as a `Uint8Array`, byte values, or hex.
  expect(sha256.verify(sha256.prove({ msg: "0x616263", digest: publicInputs.digest }).proof, { digest })).toBe(true);
});

test("refuses bad inputs", () => {
  expect(() => sha256.prove({ msg, digest: "0x00" })).toThrow(); // a short hash
  expect(() => sha256.prove({ msg: [97, 98, 100], digest })).toThrow(); // the wrong message
  expect(() => sha256.prove({ msg: [97, 98], digest })).toThrow(); // a short message
});
