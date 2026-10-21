// The generated `merkle` client (`xark client`) through xark-wasm. Run by
// scripts/client-check.sh, which regenerates `merkle.ts` and builds the keys.
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { artifacts } from "../artifacts";
import { Field, Merkle } from "./merkle";

const merkle = new Merkle(wasm, artifacts("merkle"));
const root = new Field(19217897426496189115890594488318047711322540293288184119629031241572428947159n);
const fields = (xs: number[]) => xs.map((x) => new Field(x));
const inputs = { leaf: new Field(7), siblings: fields([11, 22, 33, 44]), indexBits: fields([1, 0, 1, 0]), root };

test("proves membership", () => {
  const { proof, publicInputs } = merkle.prove(inputs);
  expect(publicInputs).toEqual({ root });
  expect(merkle.verify(proof, publicInputs)).toBe(true);
  expect(merkle.verify(proof, { root: new Field(12345) })).toBe(false);
});

test("refuses a non-member", () => {
  expect(() => merkle.prove({ ...inputs, leaf: new Field(8) })).toThrow();
});
