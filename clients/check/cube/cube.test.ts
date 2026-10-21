// The generated `cube` client (`xark client`) through xark-wasm. `npm test` runs it,
// after setup.ts builds the example and its keys.
import { artifacts, serve } from "../artifacts";
import { Cube, CubeProver, CubeVerifier, Field } from "./cube";
import { Field as KycField } from "../zk_kyc/zk_kyc";

// The BN254 scalar field modulus: p + 3 would prove as 3 if it wrapped.
const p = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
// A field input takes a `Field` or a plain integer; decoded values are `Field`s.
const inputs = { secret: 3, result: 27 };

let prover: CubeProver;
let verifier: CubeVerifier;
beforeAll(async () => {
  prover = await Cube.prover(artifacts("cube"));
  verifier = await Cube.verifier(artifacts("cube").verifyingKey);
});

test("proves and verifies", () => {
  const proof = prover.prove(inputs);
  expect(proof.publicInputs).toEqual({ result: new Field(27) });
  expect(proof.publicInputs.result.equals(27)).toBe(true);
  expect(verifier.verify(proof)).toBe(true);
  // Against the public inputs a verifier requires.
  expect(verifier.verify(proof, { result: new Field(27) })).toBe(true);
  expect(verifier.verify(proof, { result: 28 })).toBe(false);
});

test("a proof travels as one blob", () => {
  const proof = prover.prove(inputs);
  const blob = proof.toBytes();
  expect(verifier.verify(blob)).toBe(true);
  expect(verifier.decode(blob)).toEqual(proof);
  expect(verifier.verify(blob, { result: new Field(28) })).toBe(false);
  const tampered = blob.slice();
  tampered[tampered.length - 32] ^= 1; // the public input, 27 → 26
  expect(verifier.decode(tampered).publicInputs.result.equals(26)).toBe(true);
  expect(verifier.verify(tampered)).toBe(false);
  expect(verifier.verify(blob.slice(0, 10))).toBe(false);
  expect(() => verifier.decode(blob.slice(0, 10))).toThrow(/not a serialized proof/);
});

test("refuses bad inputs", () => {
  expect(() => prover.prove({ ...inputs, result: 28 })).toThrow();
  // Checked as a `Field` would be, naming the input: never wrapped or rounded.
  expect(() => prover.prove({ ...inputs, secret: p + 3n })).toThrow(/secret/);
  expect(() => prover.prove({ ...inputs, secret: -1 })).toThrow(/secret/);
  expect(() => prover.prove({ ...inputs, secret: 2 ** 53 + 2 })).toThrow(/secret: .* is not a safe integer/);
  expect(() => prover.prove({ ...inputs, secret: "three" })).toThrow(/secret/);
  expect(prover.prove({ secret: new Field(3), result: 27n }).publicInputs.result.equals(27)).toBe(true);
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
  // Every client re-exports the one `Field`.
  expect(KycField).toBe(Field);
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
    const proof = (await Cube.prover(server.url)).prove(inputs);
    // A verifier fetches only the verifying key, and can't prove.
    const fetched = await Cube.verifier(new URL(server.url));
    expect(fetched.verify(proof)).toBe(true);
    // @ts-expect-error: a verifier has no `prove` (tsc checks this line)
    expect(fetched.prove).toBeUndefined();
    await expect(Cube.prover(server.url + "missing/")).rejects.toThrow(/404/);
    await expect(Cube.verifier("/circuits/cube/")).rejects.toThrow(/pass an absolute URL/);
    // @ts-expect-error: proving needs the circuit and proving key (tsc checks this line)
    await expect(Cube.prover({ verifyingKey: artifacts("cube").verifyingKey })).rejects.toThrow(/needs `circuit`/);
  } finally {
    await server.close();
  }
});
