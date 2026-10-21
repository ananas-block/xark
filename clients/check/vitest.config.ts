import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// `npm test`: builds what the clients need (setup.ts), checks the committed clients
// are current (clients.test.ts), typechecks everything, runs each example's
// `<name>/<name>.test.ts` through xark-wasm's node build, and `browser/` in
// headless Chromium through its web build. `npm run update` rewrites stale clients.
const repo = fileURLToPath(new URL("../..", import.meta.url));

export default defineConfig({
  cacheDir: fileURLToPath(new URL("node_modules/.vite", import.meta.url)),
  // The browser tests fetch the examples' build output and xark-wasm from the repo.
  server: { fs: { allow: [repo] } },
  // xark-wasm's web build loads its .wasm beside itself: serve it as it is.
  optimizeDeps: { exclude: ["@blueshift-gg/xark-wasm"] },
  test: {
    globalSetup: ["./setup.ts"],
    globals: true,
    testTimeout: 60_000,
    hookTimeout: 120_000,
    projects: [
      {
        extends: true,
        test: {
          name: "node",
          include: ["*.test.ts", "*/*.test.ts"],
          exclude: ["browser/**"],
          // Type errors, and an `@ts-expect-error` with nothing to expect, fail the run.
          typecheck: {
            enabled: true,
            include: ["*.test.ts", "*/*.test.ts"],
            tsconfig: "./tsconfig.json",
            ignoreSourceErrors: false,
          },
        },
      },
      {
        extends: true,
        test: {
          name: "browser",
          include: ["browser/*.test.ts"],
          browser: {
            enabled: true,
            provider: "playwright",
            headless: true,
            instances: [{ browser: "chromium" }],
          },
        },
      },
    ],
  },
});
