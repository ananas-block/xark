// Test harness only: an example's build output (`xark build` + `xark setup`, run by
// scripts/client-check.sh). An app gets these bytes however it ships them — a
// bundler asset, `fetch`, a CDN — so the example tests take them from here.
import { readFileSync } from "node:fs";
import { join } from "node:path";

export function artifacts(example: string) {
  const dir = join(__dirname, "..", "..", "examples", example, "target", "xark", example);
  const read = (f: string) => new Uint8Array(readFileSync(join(dir, f)));
  return { circuit: read("circuit.xbc"), provingKey: read("pk.bin"), verifyingKey: read("vk.bin") };
}
