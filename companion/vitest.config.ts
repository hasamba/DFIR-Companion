import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // Real OCR (TesseractOcrRunner) hits the network for language data and isn't mocked by
    // every test that triggers a capture — off by default so the suite never depends on
    // network access; tests/server/ocrSearchRoute.test.ts opts back in per test.
    env: { DFIR_OCR_SEARCH: "off" },
  },
});
