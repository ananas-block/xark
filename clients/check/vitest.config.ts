import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Runs each example client's `<name>/<name>.test.ts` against xark-wasm's node build.
export default defineConfig({
  cacheDir: fileURLToPath(new URL("node_modules/.vite", import.meta.url)),
  test: {
    include: ["*/*.test.ts"],
    globals: true,
    testTimeout: 60_000,
  },
});
