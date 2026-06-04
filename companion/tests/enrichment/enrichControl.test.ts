import { describe, it, expect } from "vitest";
import { resolveEnabledProviders } from "../../src/enrichment/enrichControl.js";

const configured = ["VirusTotal", "AbuseIPDB", "MISP", "YETI"];
const local = ["MISP", "YETI"];

describe("resolveEnabledProviders", () => {
  it("defaults to local-only when nothing is stored (OPSEC-safe)", () => {
    expect(resolveEnabledProviders(null, configured, local)).toEqual(["MISP", "YETI"]);
  });

  it("keeps an explicit list, filtered to providers still configured", () => {
    expect(resolveEnabledProviders({ providers: ["VirusTotal", "MISP", "GoneProvider"] }, configured, local))
      .toEqual(["VirusTotal", "MISP"]);
  });

  it("explicit empty list means none (enrichment off)", () => {
    expect(resolveEnabledProviders({ providers: [] }, configured, local)).toEqual([]);
  });

  it("migrates legacy { enabled } — true → all configured, false → none", () => {
    expect(resolveEnabledProviders({ enabled: true }, configured, local)).toEqual(configured);
    expect(resolveEnabledProviders({ enabled: false }, configured, local)).toEqual([]);
  });
});
