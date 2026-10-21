// Generated clients in a real browser (headless Chromium): the runtime loads
// xark-wasm's web build and runs its `init()`, fetches the build output from URLs
// as an app would, proves and verifies, and runs the Rust functions from
// client.wasm. Vite serves the examples' build output (`/@fs/…`).
import { inject } from "vitest";
import { Cube } from "../cube/cube";
import { Country, Field, Identity, Policy, ZkKyc } from "../zk_kyc/zk_kyc";

const url = (example: string) => new URL(`/@fs${inject("examples")}/${example}/target/xark/${example}/`, location.href);

test("proves and verifies in the browser", async () => {
  const prover = await Cube.prover(url("cube"));
  const proof = prover.prove({ secret: 3, result: 27 });
  const verifier = await Cube.verifier(url("cube"));
  expect(verifier.verify(proof.toBytes(), { result: 27 })).toBe(true);
  expect(verifier.verify(proof.toBytes(), { result: 28 })).toBe(false);
  expect(() => prover.prove({ secret: 3, result: 28 })).toThrow();
});

test("runs the circuit's Rust functions in the browser", async () => {
  await ZkKyc.ready(url("zk_kyc"));
  const policy = Policy.on(new Date("2026-10-20")).minAge(18).nationalities([Country.US]);
  expect(policy.bornBy).toEqual(new Date("2008-10-20"));
  const id = {
    document: "A1938274",
    born: new Date("1990-01-01"),
    nationality: Country.US,
    netWorth: 1_000_000,
    expires: new Date("2030-01-01"),
    salt: new Field(1),
  };
  expect(Identity.commitment(id)).toBeInstanceOf(Field);
});
