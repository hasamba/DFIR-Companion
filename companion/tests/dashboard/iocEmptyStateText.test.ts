import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2468: with "Flagged only" on, every empty IOC list said "enrich the IOCs first, or none came back
// flagged" — even when flagged IOCs existed and a provenance, type or other lens had hidden them.
// The enrichment hint is now kept for the one case it describes: Flagged on and no flagged IOC at
// all. Every other empty list says the filter hides them and names the lenses that are on.

interface IocApi {
  DfirIoc: {
    iocEmptyStateText(o: {
      total: number;
      flaggedOnly: boolean;
      flaggedTotal: number;
      lenses: string[];
      noise: boolean;
    }): string;
  };
}

const api = loadDashboardModule<IocApi>("dashboard-ioc.js", ["dashboard-escape.js"]);
const text = (o: Partial<Parameters<IocApi["DfirIoc"]["iocEmptyStateText"]>[0]>) =>
  api.DfirIoc.iocEmptyStateText({
    total: 5,
    flaggedOnly: false,
    flaggedTotal: 0,
    lenses: [],
    noise: false,
    ...o,
  });

const ENRICH = "No malicious/suspicious IOCs — enrich the IOCs first, or none came back flagged.";

describe("IOC empty-state text (#2468)", () => {
  it("says there are no IOCs on a case with none, whatever lens is on", () => {
    expect(text({ total: 0 })).toBe("No IOCs yet");
    expect(text({ total: 0, flaggedOnly: true, lenses: ["Flagged only"] })).toBe("No IOCs yet");
  });

  it("keeps the enrichment hint when Flagged is on and nothing is flagged", () => {
    expect(text({ flaggedOnly: true, flaggedTotal: 0, lenses: ["Flagged only"] })).toBe(ENRICH);
  });

  it("names the lens, not enrichment, when flagged IOCs exist but another lens hid them", () => {
    const t = text({ flaggedOnly: true, flaggedTotal: 3, lenses: ["Flagged only", "provenance / risk"] });
    expect(t).not.toContain("enrich");
    expect(t).toContain("No IOCs match the filter");
    expect(t).toContain("Flagged only");
    expect(t).toContain("provenance / risk");
  });

  it("names the active lenses without Flagged", () => {
    expect(text({ lenses: ["search", "type"] })).toBe("No IOCs match the filter (active: search, type).");
  });

  it("adds the noise-lens hint when a noise lens is on", () => {
    const t = text({ lenses: [], noise: true });
    expect(t).toContain("No IOCs match the filter.");
    expect(t).toContain("Turn off “Signal only” / “Hide FP/no-intel” / “Hide OS system paths”");
  });

  it("is wired into the IOC panel's empty branch", () => {
    const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    const branch = html.slice(html.indexOf("if (!visible.length) {"), html.indexOf("updateIocBulkBar();"));
    expect(branch).toContain("DfirIoc.iocEmptyStateText(");
    expect(branch).toContain("flaggedTotal");
  });
});
