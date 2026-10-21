// The generated `cube` client (`xark client`) through xark-wasm. Run by
// scripts/client-check.sh, which regenerates `cube.ts` and builds the keys.
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { artifacts, serve } from "../artifacts";
import { Cube } from "./cube";

const cube = new Cube(wasm, artifacts("cube"));
// The BN254 scalar field modulus: p + 3 would prove as 3 if it wrapped.
const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

test("proves and verifies", () => {
  const { proof, publicInputs } = cube.prove({ secret: 3, result: 27 });
  expect(publicInputs).toEqual({ result: 27n });
  expect(cube.verify(proof, publicInputs)).toBe(true);
  expect(cube.verify(proof, { result: 28 })).toBe(false);
});

test("refuses bad inputs", () => {
  expect(() => cube.prove({ secret: 3, result: 28 })).toThrow();
  expect(() => cube.prove({ secret: p + 3n, result: 27 })).toThrow();
  expect(() => cube.prove({ secret: -1, result: 27 })).toThrow();
});

test("loads its build output from a URL", async () => {
  const server = await serve("cube");
  try {
    const fetched = await Cube.load(wasm, server.url);
    const { proof, publicInputs } = fetched.prove({ secret: 3, result: 27 });
    // A verifier needs only the verifying key.
    const verifier = await Cube.load(wasm, new URL(server.url), ["verifyingKey"]);
    expect(verifier.verify(proof, publicInputs)).toBe(true);
    expect(() => verifier.prove({ secret: 3, result: 27 })).toThrow(/needs `circuit`/);
    await expect(Cube.load(wasm, server.url + "missing/")).rejects.toThrow(/404/);
    await expect(Cube.load(wasm, "/circuits/cube/")).rejects.toThrow(/pass an absolute URL/);
  } finally {
    await server.close();
  }
});
