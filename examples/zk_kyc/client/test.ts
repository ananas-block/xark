// Node test for the generated `zk_kyc` client (`xark codegen ts`): prove with typed
// inputs through xark-wasm, verify, and check rejections. Run by
// scripts/codegen-check.sh, which regenerates `zk_kyc.ts` and builds the keys.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as wasm from "../../../crates/wasm/dist/node/xark_wasm.js";
import { ZkKyc } from "./zk_kyc";

const dir = join(__dirname, "..", "target", "xark", "zk_kyc");
const read = (f: string) => new Uint8Array(readFileSync(join(dir, f)));
const circuit = new ZkKyc(wasm, {
  circuit: read("circuit.xbc"),
  provingKey: read("pk.bin"),
  verifyingKey: read("vk.bin"),
});
function check(ok: boolean, what: string) {
  if (!ok) throw new Error(`zk_kyc: ${what}`);
}
function throws(f: () => unknown): boolean {
  try {
    f();
    return false;
  } catch {
    return true;
  }
}


const user = {
  id: "3762531230650282305",
  dob: 19900101,
  country: 21333,
  nonce: "107489751367048338162988283588945819705777698572417243920860455291229215602451",
};
// The issuer's Poseidon2 commitment over `user` (see the Rust test).
const commitment = 12878865688106088761792099203939159416017581602557940089653423899691492680101n;

const { proof, publicInputs, publicInputBytes } = circuit.prove({ user, maxDob: 20200101, commitment });
check(circuit.verify(proof, publicInputs), "the proof verifies");
check(circuit.verify(proof, publicInputBytes), "the proof verifies against the raw public-input bytes");
check(BigInt(publicInputs.commitment) === commitment, "the commitment decodes");
check(!circuit.verify(proof, { maxDob: 20200102, commitment }), "a different policy is rejected");
check(throws(() => circuit.prove({ user, maxDob: 19900101, commitment })), "a too-young user is refused");
check(throws(() => circuit.prove({ user, maxDob: 20200101, commitment: 1 })), "a wrong commitment is refused");
console.log("✅ zk_kyc client");
