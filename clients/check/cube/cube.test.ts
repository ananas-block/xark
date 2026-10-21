// The generated `cube` client (`xark client`) through xark-wasm. Run by
// scripts/client-check.sh, which regenerates `cube.ts` and builds the keys.
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { artifacts, serve } from "../artifacts";
import { Cube, Field } from "./cube";
import { Field as KycField } from "../zk_kyc/zk_kyc";

const cube = new Cube(wasm, artifacts("cube"));
// The BN254 scalar field modulus: p + 3 would prove as 3 if it wrapped.
const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const inputs = { secret: new Field(3), result: new Field(27) };

test("proves and verifies", () => {
  const { proof, publicInputs } = cube.prove(inputs);
  expect(publicInputs).toEqual({ result: new Field(27) });
  expect(publicInputs.result.equals(27)).toBe(true);
  expect(cube.verify(proof, publicInputs)).toBe(true);
  expect(cube.verify(proof, { result: new Field(28) })).toBe(false);
});

test("refuses bad inputs", () => {
  expect(() => cube.prove({ ...inputs, result: new Field(28) })).toThrow();
});

test("a Field is checked when it's made", () => {
  // Every form is the same element.
  const three = new Field(3);
  for (const x of [3n, "3", " 3 ", "0x03", new Uint8Array([3]), new Uint8Array(32).fill(3, 0, 1), three]) {
    expect(new Field(x).value).toBe(3n);
  }
  // Bytes are little-endian, as proofs and Rust's `Field::from_le_bytes` have them.
  expect(new Field(new Uint8Array([1, 2])).value).toBe(0x0201n);
  expect(Field.fromBeBytes(new Uint8Array([1, 2])).value).toBe(0x0102n);
  const big = new Field(p - 1n).toBytes();
  expect(big).toEqual(Uint8Array.from(Buffer.from((p - 1n).toString(16).padStart(64, "0"), "hex")).reverse());
  expect(new Field(big).value).toBe(p - 1n);
  expect(JSON.stringify({ x: three })).toBe('{"x":"3"}');
  // Each generated client has its own copy of the class; a Field from one passes to another.
  expect(cube.verify(cube.prove({ ...inputs, secret: new KycField(3) }).proof, { result: new KycField(27) })).toBe(true);
  // Not below p, negative, inexact or malformed: refused, rather than wrapped.
  expect(() => new Field(p + 3n)).toThrow(/not below the field's modulus/);
  expect(() => new Field(new Uint8Array(32).fill(0xff))).toThrow(/not below the field's modulus/);
  expect(() => new Field(-1)).toThrow(/negative/);
  expect(() => new Field(2 ** 53)).toThrow(/not a safe integer/);
  expect(() => new Field(1.5)).toThrow(/not a safe integer/);
  for (const s of ["", "-1", "1e3", "0x", "12abc"]) expect(() => new Field(s)).toThrow(/not a decimal or 0x-hex/);
  expect(() => new Field(new Uint8Array(33))).toThrow(/at most 32/);
  // @ts-expect-error: not a field element's form (tsc checks this line)
  expect(() => new Field(null)).toThrow(/can't make a field element/);
});

test("loads its build output from a URL", async () => {
  const server = await serve("cube");
  try {
    const fetched = await Cube.load(wasm, server.url);
    const { proof, publicInputs } = fetched.prove(inputs);
    // A verifier needs only the verifying key.
    const verifier = await Cube.load(wasm, new URL(server.url), ["verifyingKey"]);
    expect(verifier.verify(proof, publicInputs)).toBe(true);
    expect(() => verifier.prove(inputs)).toThrow(/needs `circuit`/);
    await expect(Cube.load(wasm, server.url + "missing/")).rejects.toThrow(/404/);
    await expect(Cube.load(wasm, "/circuits/cube/")).rejects.toThrow(/pass an absolute URL/);
  } finally {
    await server.close();
  }
});
