// Exercise the native generator, then typecheck its output and positive/negative
// usage cases against the real client declarations, including library checks.
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "../..");
const output = mkdtempSync(join(tmpdir(), "xark-client-names-"));
try {
  execFileSync("cargo", ["test", "-p", "xark-cli", "--lib",
    "commands::client::ts::tests::allocates_collision_free_client_names", "--", "--exact"], {
    cwd: root,
    env: { ...process.env, XARK_CLIENT_NAMES_OUT: output },
    stdio: "inherit",
  });
  writeFileSync(join(output, "tsconfig.json"), JSON.stringify({
    compilerOptions: {
      target: "ES2020",
      module: "ESNext",
      moduleResolution: "Bundler",
      strict: true,
      noEmit: true,
      skipLibCheck: false,
      types: [],
      paths: { "@blueshift-gg/xark-wasm/client": [join(root, "crates/wasm/js/client.d.ts")] },
    },
    include: ["*.ts"],
  }));
  execFileSync(process.execPath, [join(here, "node_modules/typescript/bin/tsc"), "--project", output], {
    cwd: here,
    stdio: "inherit",
  });
} finally {
  rmSync(output, { recursive: true, force: true });
}
