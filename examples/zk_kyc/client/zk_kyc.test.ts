// The generated `zk_kyc` client (`xark client`) through xark-wasm. Run by
// scripts/client-check.sh, which regenerates `zk_kyc.ts` and builds the keys.
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { artifacts } from "../../../clients/check/artifacts";
import { type Identity, ZkKyc, type ZkKycPublicInputs } from "./zk_kyc";

const kyc = new ZkKyc(wasm, artifacts("zk_kyc"));

// The holder's credential, in the circuit's own types: `Text`, `Date`, a `Country`.
// A `Date` is read as its UTC day: `new Date("1990-01-01")` is 1990-01-01 anywhere.
const id: Identity = {
  document: "A1938274",
  born: new Date("1990-01-01"),
  nationality: "US",
  netWorth: 1_000_000,
  expires: new Date("2030-01-01"),
  salt: "33701741659145338741541800171033551611705418330992198479621539463087461139",
};
// The issuer's Poseidon2 commitment over `id` (see the Rust tests).
const commitment = 4058172634906005022229777495117820733710818327967433754570325414295423937452n;
// Born before 2008-10-20, worth ≥ 500k, valid today, from US/GB/FR/DE.
const policy: ZkKycPublicInputs = {
  commitment,
  bornBefore: new Date("2008-10-20"),
  minNetWorth: 500_000,
  today: new Date("2026-10-20"),
  allowed: ["US", "GB", "FR", "DE"],
};

test("proves a compliant holder", () => {
  const { proof, publicInputs, publicInputBytes } = kyc.prove({ id, ...policy });
  expect(publicInputs).toEqual({
    commitment,
    bornBefore: new Date("2008-10-20"),
    minNetWorth: 500_000n,
    today: new Date("2026-10-20"),
    allowed: ["DE", "FR", "GB", "US"], // in bit order
  });
  expect(kyc.verify(proof, publicInputs)).toBe(true);
  expect(kyc.verify(proof, policy)).toBe(true);
  expect(kyc.verify(proof, publicInputBytes)).toBe(true);
  expect(kyc.verify(proof, { ...policy, allowed: ["US", "GB"] })).toBe(false);
});

test("names the check a holder fails", () => {
  const fails = (inputs: object) => () => kyc.prove({ id, ...policy, ...inputs });
  expect(fails({ allowed: ["GB", "FR"] })).toThrow(
    /the inputs fail the check at src\/lib\.rs:\d+:\d+: `id\.nationality\.require_one_of\(allowed\);`/,
  );
  expect(fails({ bornBefore: new Date("1989-12-31") })).toThrow(/`require\(id\.born < born_before\);`/);
  expect(fails({ minNetWorth: 2_000_000 })).toThrow(/`require\(id\.net_worth >= min_net_worth\);`/);
  expect(fails({ commitment: 1 })).toThrow(/`require_eq\(id\.commitment\(\), commitment\);`/);
});

test("names the input at fault", () => {
  const long = { ...id, document: "a document number past 31 bytes" + "!" };
  expect(() => kyc.prove({ id: long, ...policy })).toThrow(/id\.document.*longer than 31 bytes/);
  expect(() => kyc.prove({ id, ...policy, today: new Date("not a day") })).toThrow(/today: invalid Date/);
});
