import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // Vitest's 5s default is not a statement about how long these tests take — it's a statement
    // about how long they take ON AN IDLE MACHINE. The suite is ~384 files whose cost is dominated
    // by module collection/transform, so a full parallel run saturates every core and a test doing
    // <1s of real work can sit descheduled for >4s and "time out" (issue #173). That produced a
    // different set of failures on every run, which trains everyone to dismiss real regressions as
    // flake. 15s keeps genuinely-hung tests failing fast while removing the starvation false
    // positives — and removes the incentive to keep bumping timeouts one test at a time.
    testTimeout: 15_000,
    // Same reasoning for setup/teardown: a beforeEach doing mkdtemp + createApp() starves too, and
    // a hook timeout fails the whole file rather than one test.
    hookTimeout: 15_000,
    // Real OCR (TesseractOcrRunner) hits the network for language data and isn't mocked by
    // every test that triggers a capture — off by default so the suite never depends on
    // network access; tests/server/ocrSearchRoute.test.ts opts back in per test.
    env: { DFIR_OCR_SEARCH: "off" },
  },
});
