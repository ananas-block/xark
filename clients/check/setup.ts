// Vitest global setup: everything the client tests need, built fresh.
//
// Builds the `xark` CLI and xark-wasm's node package (when missing, or with
// XARK_REBUILD_WASM set). Then, for each example with a folder here (`cube/`,
// `zk_kyc/`, …): `xark build`, dev keys from `xark setup`, and its client from
// `xark client`, into a temporary directory. `clients.test.ts` checks those
// against the committed clients; the examples' own tests prove and verify
// through them.
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestProject } from "vitest/node";

const here = __dirname;
const root = join(here, "..", "..");

/** The examples this folder tests: a folder holding `<name>.test.ts`. */
export const examples = readdirSync(here, { withFileTypes: true })
  .filter((d) => d.isDirectory() && existsSync(join(here, d.name, `${d.name}.test.ts`)))
  .map((d) => d.name)
  .sort();

/** Run a command; on failure, throw with everything it printed. */
function run(what: string, cmd: string, args: string[], cwd = root) {
  try {
    execFileSync(cmd, args, { cwd, stdio: "pipe", encoding: "utf8" });
  } catch (e) {
    const { stdout = "", stderr = "" } = e as { stdout?: string; stderr?: string };
    throw new Error(`${what} failed: ${cmd} ${args.join(" ")}\n${stdout}${stderr}`);
  }
}

export default function setup(project: TestProject) {
  run("building xark", "cargo", ["build", "-q", "--release", "-p", "xark-cli", "--bin", "xark"]);
  const xark = join(process.env.CARGO_TARGET_DIR ?? join(root, "target"), "release", "xark");
  if (!existsSync(join(root, "crates/wasm/dist/node/xark_wasm.js")) || process.env.XARK_REBUILD_WASM) {
    run("building xark-wasm", "wasm-pack", ["build", "crates/wasm", "--target", "nodejs", "--release", "--out-dir", "dist/node"]);
  }
  const generated = mkdtempSync(join(tmpdir(), "xark-clients-"));
  for (const name of examples) {
    const dir = join(root, "examples", name);
    run(`${name}: xark build`, xark, ["build", dir]);
    run(`${name}: xark setup`, xark, ["setup", dir, "--insecure-dev-mode", "--deterministic-rng", "1"]);
    run(`${name}: xark client`, xark, ["client", "--out", join(generated, `${name}.ts`)], dir);
  }
  project.provide("generated", generated);
}

declare module "vitest" {
  export interface ProvidedContext {
    /** The directory `xark client` wrote this run's clients to. */
    generated: string;
  }
}
