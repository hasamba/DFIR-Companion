import { describe, expect, it } from "vitest";
import { computeMainSource } from "../../src/analysis/caseMainSource.js";
import { huntLanguageFor, planHuntGroups } from "../../src/analysis/huntLanguage.js";
import { HUNT_PLATFORMS } from "../../src/analysis/huntPlatforms.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ALL = [...HUNT_PLATFORMS];

describe("huntLanguageFor (#2559)", () => {
  it("maps each family to its hunt language", () => {
    expect(huntLanguageFor("velociraptor", ALL)).toEqual({ language: "vql", note: "" });
    expect(huntLanguageFor("crowdstrike", ALL).language).toBe("cql");
    expect(huntLanguageFor("defender", ALL).language).toBe("kql-device");
    expect(huntLanguageFor("m365", ALL).language).toBe("kql-cloud");
    expect(huntLanguageFor("elastic", ALL).language).toBe("esql");
    expect(huntLanguageFor("splunk", ALL).language).toBe("spl");
    expect(huntLanguageFor(null, ALL)).toEqual({ language: "vql", note: "" });
  });

  it("host tools with no query language fall back to VQL, with a note", () => {
    const c = huntLanguageFor("host-other", ALL);
    expect(c.language).toBe("vql");
    expect(c.note).toMatch(/no hunt language/i);
  });

  it("other cloud logs get no language at all — never VQL", () => {
    const c = huntLanguageFor("cloud-other", ALL);
    expect(c.language).toBeNull();
    expect(c.note).toMatch(/Query Translator/);
  });

  it("a language disabled by DFIR_HUNT_PLATFORMS falls back to VQL with a note", () => {
    const c = huntLanguageFor("defender", ["velociraptor", "splunk"]);
    expect(c.language).toBe("vql");
    expect(c.note).toMatch(/disabled/);
  });
});

function ev(id: string, sources: string[], batch: string): ForensicEvent {
  return {
    id,
    timestamp: "2026-01-01T00:00:00Z",
    description: "row",
    severity: "High",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources,
    importBatchId: batch,
  };
}

describe("planHuntGroups (#2559)", () => {
  const events = [ev("c1", ["CrowdStrike Falcon"], "b1"), ev("v1", ["Velociraptor"], "b2")];
  const items = [
    { id: "f1", fam: "crowdstrike" as const },
    { id: "f2", fam: "velociraptor" as const },
    { id: "f3", fam: null },
  ];

  it("a main source sends every item to its language", () => {
    const main = computeMainSource(events, "crowdstrike");
    const plan = planHuntGroups(
      items,
      (i) => i.fam,
      (i) => i.id,
      main,
      ALL,
    );
    expect(plan.groups).toEqual([{ language: "cql", ids: ["f1", "f2", "f3"] }]);
  });

  it("a mixed case sends each item to its own evidence's language; no evidence → VQL", () => {
    const main = computeMainSource(events, null);
    expect(main.effective).toBe("mixed");
    const plan = planHuntGroups(
      items,
      (i) => i.fam,
      (i) => i.id,
      main,
      ALL,
    );
    expect(plan.groups).toEqual([
      { language: "vql", ids: ["f2", "f3"] },
      { language: "cql", ids: ["f1"] },
    ]);
  });

  it("an other-cloud main source yields no group and a note", () => {
    const main = computeMainSource(events, "cloud-other");
    const plan = planHuntGroups(
      items,
      (i) => i.fam,
      (i) => i.id,
      main,
      ALL,
    );
    expect(plan.groups).toEqual([]);
    expect(plan.notes.join(" ")).toMatch(/Query Translator/);
  });
});
