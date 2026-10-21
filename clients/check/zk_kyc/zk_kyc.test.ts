// The generated `zk_kyc` client (`xark client`) through xark-wasm. Run by
// scripts/client-check.sh, which regenerates `zk_kyc.ts` and builds the keys.
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { artifacts } from "../../../clients/check/artifacts";
import { Country, Identity, initClient, Policy, ZkKyc } from "./zk_kyc";

const kyc = new ZkKyc(wasm, artifacts("zk_kyc"));
beforeAll(() => initClient(artifacts("zk_kyc").client!));

// The holder's credential, in the circuit's own types: `Text`, `Date`, a `Country`.
// A `Date` is read as its UTC day: `new Date("1990-01-01")` is 1990-01-01 anywhere.
const id: Identity = {
  document: "A1938274",
  born: new Date("1990-01-01"),
  nationality: Country.US,
  netWorth: 1_000_000,
  expires: new Date("2030-01-01"),
  salt: "33701741659145338741541800171033551611705418330992198479621539463087461139",
};
// The issuer's Poseidon2 commitment over `id` (the Rust `id.commitment()`; see the
// test below, which computes it here).
const commitment = 14027122776066679586866430602253390234316410519759139985776472857287265910584n;
// 18 or older on 2026-10-20, worth ≥ 500k, a document valid that day, from US/GB/FR/DE
// (as data; the test below builds it with the Rust constructors).
const policy: Policy = {
  today: new Date("2026-10-20"),
  bornBy: new Date("2008-10-20"),
  minNetWorth: 500_000,
  allowed: [Country.US, Country.GB, "FR", "DE"], // constants or names
};

test("builds the policy and the commitment with the circuit's Rust code", () => {
  // `Policy::on(..).min_age(..)…` and `Identity::commitment`, from `#[xark::export]`.
  // (`minNetWorth` is also a field, so it isn't a method on the value: `Policy.minNetWorth(…)`.)
  const adult = Policy.on(new Date("2026-10-20")).minAge(18);
  const built = Policy.minNetWorth(adult, 500_000).nationalities(["US", "GB", "FR", "DE"]);
  expect(built).toEqual({ ...policy, minNetWorth: 500_000n, allowed: ["DE", "FR", "GB", "US"] });
  expect(Policy.minAge(policy, 21).bornBy).toEqual(new Date("2005-10-20"));
  expect(Identity.commitment(id)).toBe(commitment);
  const { proof, publicInputs } = kyc.prove({ id, commitment: Identity.commitment(id), policy: built });
  expect(kyc.verify(proof, publicInputs)).toBe(true);
  // A Rust panic is an exception with its message, and the module keeps working.
  expect(() => built.minAge(3000)).toThrow(/a date before year 0/);
  expect(Policy.on(new Date("2024-02-29")).minAge(1).bornBy).toEqual(new Date("2023-02-28"));
  // Values are checked on the way in, as for `prove`.
  expect(() => Policy.on(new Date("2026-10-20")).nationalities(["XX" as Country])).toThrow(/"XX" is not a Country/);
});

test("countries are typed", () => {
  expect(Country.US).toBe("US");
  // @ts-expect-error: not an ISO 3166 code, so not a `Country` (tsc checks this line)
  const unknown: Country = "XX";
  expect(() => kyc.prove({ id: { ...id, nationality: unknown }, commitment, policy })).toThrow(
    /"XX" is not a Country/,
  );
});

test("proves a compliant holder", () => {
  const { proof, publicInputs, publicInputBytes } = kyc.prove({ id, commitment, policy });
  expect(publicInputs).toEqual({
    commitment,
    policy: {
      today: new Date("2026-10-20"),
      bornBy: new Date("2008-10-20"),
      minNetWorth: 500_000n,
      allowed: ["DE", "FR", "GB", "US"], // in bit order
    },
  });
  expect(kyc.verify(proof, publicInputs)).toBe(true);
  expect(kyc.verify(proof, { commitment, policy })).toBe(true);
  expect(kyc.verify(proof, publicInputBytes)).toBe(true);
  expect(kyc.verify(proof, { commitment, policy: { ...policy, allowed: ["US", "GB"] } })).toBe(false);
});

test("names the check a holder fails", () => {
  const fails = (rules: Partial<Policy>) => () =>
    kyc.prove({ id, commitment, policy: { ...policy, ...rules } });
  expect(fails({ allowed: ["GB", "FR"] })).toThrow(
    /the inputs fail the check at src\/lib\.rs:\d+:\d+: `id\.nationality\.require_in\(policy\.allowed\);`/,
  );
  expect(fails({ bornBy: new Date("1989-12-31") })).toThrow(/`require\(id\.born <= policy\.born_by\);`/);
  expect(fails({ minNetWorth: 2_000_000 })).toThrow(/`require\(id\.net_worth >= policy\.min_net_worth\);`/);
  expect(() => kyc.prove({ id, commitment: 1, policy })).toThrow(
    /`require_eq\(id\.commitment\(\), commitment\);`/,
  );
});

test("computes the issuer's commitment as the circuit does", () => {
  // `xark_poseidon2::hash(id.to_fields())`, the circuit's `id.commitment()`.
  const fields = kyc.fields("Identity", id);
  expect(fields).toHaveLength(6);
  expect(BigInt(wasm.poseidon2(fields.map(String)))).toBe(commitment);
});

test("names the input at fault", () => {
  const long = { ...id, document: "a document number past 31 bytes" + "!" };
  expect(() => kyc.prove({ id: long, commitment, policy })).toThrow(/id\.document.*longer than 31 bytes/);
  expect(() => kyc.prove({ id, commitment, policy: { ...policy, today: new Date("not a day") } })).toThrow(
    /today: invalid Date/,
  );
});
