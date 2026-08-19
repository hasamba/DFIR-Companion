import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-facet-filters.js — the Hosts filter's near-duplicate-merge awareness.
//
// The near-duplicate host panel (dashboard-host-duplicates.js) lets an analyst merge, e.g.,
// "DESKTOP-OPE297N" into "DESKTOP-OPE297N.localdomain". That merge is stored as an asset-override
// (public/js/dashboard-asset-graph.js's assetOverrideMerges()) and does NOT touch the raw
// ForensicEvent.asset values — so hostFacets() has to resolve each raw asset through the merge
// chain itself, or the Hosts filter keeps showing both spellings as separate checkboxes even after
// the analyst merges them.
interface Api {
  hostFacets(ft: Array<{ asset?: string }>): string[];
  hostFacetValue(raw: string | undefined | null): string | null;
}

function load(merges: Record<string, string>): Api {
  // dashboard-asset-graph.js only learns overrides through loadAssetOverrides(), which fetches —
  // there is no seam to inject data directly, so the merge map is supplied the way js/dashboard-
  // facet-filters.js actually reads it: as a global function, `typeof assetOverrideMerges ===
  // "function"`, guarded exactly like the production code guards a module that hasn't loaded yet.
  return loadDashboardModule<Api>("dashboard-facet-filters.js", ["dashboard-state.js"], {
    assetOverrideMerges: () => merges,
  });
}

const FT = [
  { asset: "DESKTOP-OPE297N" },
  { asset: "DESKTOP-OPE297N.localdomain" },
  { asset: "WIN-UK1GV882OK6" },
];

describe("hostFacets groups a merged near-duplicate host into one entry", () => {
  it("lists every raw spelling as its own facet before any merge", () => {
    const { hostFacets } = load({});
    expect(hostFacets(FT).sort()).toEqual(
      ["DESKTOP-OPE297N", "DESKTOP-OPE297N.localdomain", "WIN-UK1GV882OK6"].sort(),
    );
  });

  it("collapses the merged pair into the canonical spelling once merged", () => {
    const merges = { "host:desktop-ope297n": "host:desktop-ope297n.localdomain" };
    const { hostFacets } = load(merges);
    expect(hostFacets(FT).sort()).toEqual(["DESKTOP-OPE297N.localdomain", "WIN-UK1GV882OK6"].sort());
  });

  it("resolves both raw spellings' events to the same facet value after a merge", () => {
    const merges = { "host:desktop-ope297n": "host:desktop-ope297n.localdomain" };
    const { hostFacets, hostFacetValue } = load(merges);
    hostFacets(FT); // populates the raw->facet-value map hostFacetValue reads
    expect(hostFacetValue("DESKTOP-OPE297N")).toBe("DESKTOP-OPE297N.localdomain");
    expect(hostFacetValue("DESKTOP-OPE297N.localdomain")).toBe("DESKTOP-OPE297N.localdomain");
    expect(hostFacetValue("WIN-UK1GV882OK6")).toBe("WIN-UK1GV882OK6");
  });

  it("is case- and trailing-dot-insensitive when reading raw asset spellings, matching the server's canonicalHostName", () => {
    // companion/src/routes/hostDuplicates.ts's readPair() always runs both sides through
    // canonicalHostName (lowercase, trimmed, trailing dot stripped) before storing a merge, so the
    // merge map itself is always already canonical. What varies is the raw ForensicEvent.asset
    // spelling an importer wrote — different case, or a trailing dot from a raw FQDN capture — and
    // the client has to canonicalize THAT the same way before it will find the stored merge.
    const merges = { "host:desktop-ope297n": "host:desktop-ope297n.localdomain" };
    const ft = [
      { asset: "Desktop-OPE297N" },
      { asset: "DESKTOP-OPE297N.localdomain." },
      { asset: "WIN-UK1GV882OK6" },
    ];
    const { hostFacets } = load(merges);
    expect(hostFacets(ft)).toHaveLength(2);
  });

  it("never leaves the raw timeline events themselves touched — only the filter's grouping", () => {
    const merges = { "host:desktop-ope297n": "host:desktop-ope297n.localdomain" };
    load(merges);
    expect(FT.map((e) => e.asset)).toEqual([
      "DESKTOP-OPE297N",
      "DESKTOP-OPE297N.localdomain",
      "WIN-UK1GV882OK6",
    ]);
  });
});
