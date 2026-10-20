import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Runs `examples/*/client/*.test.ts` against xark-wasm's node build.
export default defineConfig({
  cacheDir: fileURLToPath(new URL("node_modules/.vite", import.meta.url)),
  test: {
    root: "../..",
    include: ["examples/*/client/*.test.ts"],
    globals: true,
    testTimeout: 60_000,
  },
});
