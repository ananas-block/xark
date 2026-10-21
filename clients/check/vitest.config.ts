import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// `npm test`: builds what the clients need (setup.ts), checks the committed clients
// are current (clients.test.ts), typechecks everything, and runs each example's
// `<name>/<name>.test.ts`, proving and verifying through xark-wasm's node build.
// `npm run update` rewrites stale clients.
export default defineConfig({
  cacheDir: fileURLToPath(new URL("node_modules/.vite", import.meta.url)),
  test: {
    include: ["*.test.ts", "*/*.test.ts"],
    globalSetup: ["./setup.ts"],
    globals: true,
    testTimeout: 60_000,
    hookTimeout: 120_000,
    // Type errors, and an `@ts-expect-error` with nothing to expect, fail the run.
    typecheck: {
      enabled: true,
      include: ["*.test.ts", "*/*.test.ts"],
      tsconfig: "./tsconfig.json",
      ignoreSourceErrors: false,
    },
  },
});
