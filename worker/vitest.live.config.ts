import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

// Vitest config for live integration tests (PostgreSQL, etc.).
// Identical to vitest.config.ts but WITHOUT the `**/*.live.test.ts`
// exclusion, so live tests are actually executed when explicitly
// targeted. Used by generate-release-evidence.sh's run_live_postgres_gate.
export default defineConfig({
  resolve: {
    alias: {
      "cloudflare:workers": fileURLToPath(
        new URL("./test/cloudflare-workers-runtime.ts", import.meta.url),
      ),
    },
  },
  test: {
    environment: "node",
    globals: false,
    exclude: [
      "**/node_modules/**",
      "**/dist/**",
    ],
  },
});
