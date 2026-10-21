// Test harness only: an example's build output (`xark build` + `xark setup`, run by
// scripts/client-check.sh). An app gets these bytes however it ships them — a
// bundler asset, `fetch`, a CDN — so the example tests take them from here.
import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";

const outDir = (example: string) => join(__dirname, "..", "..", "examples", example, "target", "xark", example);

export function artifacts(example: string) {
  const dir = outDir(example);
  const read = (f: string) => new Uint8Array(readFileSync(join(dir, f)));
  return {
    circuit: read("circuit.xbc"),
    provingKey: read("pk.bin"),
    verifyingKey: read("vk.bin"),
    sources: readFileSync(join(dir, "sources.json"), "utf8"),
  };
}

/** Serve an example's build output over HTTP on a free local port, as an app would. */
export async function serve(example: string): Promise<{ url: string; close: () => Promise<void> }> {
  const dir = outDir(example);
  const server = createServer(async (req, res) => {
    const name = (req.url ?? "/").slice(1);
    try {
      if (name.includes("/") || name.includes("..")) throw new Error("no");
      res.end(await readFile(join(dir, name)));
    } catch {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/`,
    close: () => new Promise((ok) => server.close(() => ok())),
  };
}
