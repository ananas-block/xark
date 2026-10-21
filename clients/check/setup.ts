// Vitest global setup: everything the client tests need, built fresh.
//
// Builds the `xark` CLI and xark-wasm's node package (when missing, or with
// XARK_REBUILD_WASM set), and for the browser tests (XARK_BROWSER, set by `npm run
// test:browser`) its web package too, also when older than the node one. Then, for
// each example with a folder here (`cube/`, `zk_kyc/`, …): `xark build`, dev keys from
// `xark setup`, and its client from `xark client`, into a temporary directory.
// `clients.test.ts` checks those against the committed clients; the examples' own
// tests prove and verify through them.
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, statSync } from "node:fs";
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
  const dist = (target: string) => join(root, "crates/wasm/dist", target, "xark_wasm_bg.wasm");
  const built = (target: string) => (existsSync(dist(target)) ? statSync(dist(target)).mtimeMs : 0);
  const rebuild = !!process.env.XARK_REBUILD_WASM;
  const targets = process.env.XARK_BROWSER ? [["nodejs", "node"], ["web", "web"]] : [["nodejs", "node"]];
  for (const [target, out] of targets) {
    const stale = out === "web" && built("web") < built("node");
    if (rebuild || !built(out) || stale) {
      run(`building xark-wasm (${out})`, "wasm-pack", ["build", "crates/wasm", "--target", target, "--release", "--out-dir", `dist/${out}`]);
    }
  }
  const generated = mkdtempSync(join(tmpdir(), "xark-clients-"));
  for (const name of examples) {
    const dir = join(root, "examples", name);
    run(`${name}: xark build`, xark, ["build", dir]);
    run(`${name}: xark setup`, xark, ["setup", dir, "--insecure-dev-mode", "--deterministic-rng", "1"]);
    run(`${name}: xark client`, xark, ["client", "--out", join(generated, `${name}.ts`)], dir);
  }
  project.provide("generated", generated);
  project.provide("examples", join(root, "examples"));
}

declare module "vitest" {
  export interface ProvidedContext {
    /** The directory `xark client` wrote this run's clients to. */
    generated: string;
    /** The repository's `examples/`, whose build output the browser tests fetch. */
    examples: string;
  }
}
