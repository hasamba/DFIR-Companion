import { describe, expect, it } from "vitest";
import {
  computeMainSource,
  evidenceFileKey,
  familyForFinding,
  familyOfEvent,
  familyOfEvents,
  parseMainSourceOverride,
} from "../../src/analysis/caseMainSource.js";
import { CLOUD_SOURCE_LABELS } from "../../src/analysis/cloudOnlyCase.js";
import { MDE_HUNTING_SOURCE } from "../../src/analysis/mdeHuntingImport.js";
import type { Finding, ForensicEvent } from "../../src/analysis/stateTypes.js";

let n = 0;
function ev(over: Partial<ForensicEvent>): ForensicEvent {
  n += 1;
  return {
    id: `e${n}`,
    timestamp: "2026-01-01T00:00:00Z",
    description: "row",
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
}

/** `rows` forensic rows from one uploaded file (one settle = one batch). */
function file(
  batch: string,
  sources: string[],
  rows = 3,
  over: Partial<ForensicEvent> = {},
): ForensicEvent[] {
  return Array.from({ length: rows }, () => ev({ importBatchId: batch, sources, ...over }));
}

describe("familyOfEvent (#2559)", () => {
  it("maps importer labels to their family", () => {
    expect(familyOfEvent(ev({ sources: ["Velociraptor"] }))).toBe("velociraptor");
    expect(familyOfEvent(ev({ sources: ["CrowdStrike Falcon"] }))).toBe("crowdstrike");
    expect(familyOfEvent(ev({ sources: ["Microsoft Defender"] }))).toBe("defender");
    expect(familyOfEvent(ev({ sources: ["Microsoft Sentinel"] }))).toBe("defender");
    expect(familyOfEvent(ev({ sources: [MDE_HUNTING_SOURCE] }))).toBe("defender");
    expect(familyOfEvent(ev({ sources: ["Elastic"] }))).toBe("elastic");
    expect(familyOfEvent(ev({ sources: ["Splunk"] }))).toBe("splunk");
    expect(familyOfEvent(ev({ sources: ["Hayabusa"] }))).toBe("host-other");
    expect(familyOfEvent(ev({ sources: ["SIEM import"] }))).toBe("host-other");
  });

  it("reads the vendor from a generic SIEM row's description prefix", () => {
    const e = ev({ sources: ["SIEM import"], description: "CrowdStrike Falcon: ProcessRollup2 x.exe" });
    expect(familyOfEvent(e)).toBe("crowdstrike");
    expect(familyOfEvent(ev({ sources: ["SIEM import"], description: "Splunk: 4688" }))).toBe("splunk");
  });

  it("puts M365/Entra in its own family and every other cloud label in cloud-other", () => {
    expect(familyOfEvent(ev({ sources: ["Microsoft 365"] }))).toBe("m365");
    expect(familyOfEvent(ev({ sources: ["Entra ID"] }))).toBe("m365");
    expect(familyOfEvent(ev({ description: "Entra sign-in: alice from 1.2.3.4" }))).toBe("m365");
    for (const label of CLOUD_SOURCE_LABELS) {
      const fam = familyOfEvent(ev({ sources: [label] }));
      expect(["m365", "cloud-other"]).toContain(fam);
    }
    expect(familyOfEvent(ev({ sources: ["AWS CloudTrail"] }))).toBe("cloud-other");
    expect(familyOfEvent(ev({ sources: ["Okta"] }))).toBe("cloud-other");
  });
});

describe("family precedence for cloud rows exported from a SIEM (#2559)", () => {
  it("a Splunk, Elastic or Falcon export of cloud logs keeps its tool — that is where the analyst queries it", () => {
    expect(familyOfEvent(ev({ sources: ["Splunk"], description: "Entra sign-in: alice" }))).toBe("splunk");
    expect(familyOfEvent(ev({ sources: ["Elastic", "AWS CloudTrail"] }))).toBe("elastic");
    expect(familyOfEvent(ev({ sources: ["CrowdStrike Falcon", "Okta"] }))).toBe("crowdstrike");
  });

  it("a Sentinel / Defender export of tenant logs reads as Microsoft 365", () => {
    expect(familyOfEvent(ev({ sources: ["Microsoft Sentinel"], description: "Entra sign-in: bob" }))).toBe(
      "m365",
    );
    expect(familyOfEvent(ev({ sources: ["Microsoft Sentinel", "AWS CloudTrail"] }))).toBe("cloud-other");
  });
});

describe("evidenceFileKey (#2559)", () => {
  it("counts each Velociraptor artifact of one hunt as its own evidence file", () => {
    const a = ev({ sources: ["Velociraptor"], importBatchId: "h", artifactName: "Windows.NTFS.MFT" });
    const b = ev({ sources: ["Velociraptor"], importBatchId: "h", artifactName: "Windows.System.Pslist" });
    expect(evidenceFileKey(a, "velociraptor")).not.toBe(evidenceFileKey(b, "velociraptor"));
  });

  it("counts one uploaded export once, whatever artifact labels its rows carry", () => {
    const a = ev({ sources: ["CrowdStrike Falcon"], importBatchId: "x", artifactName: "A" });
    const b = ev({ sources: ["CrowdStrike Falcon"], importBatchId: "x", artifactName: "B" });
    expect(evidenceFileKey(a, "crowdstrike")).toBe(evidenceFileKey(b, "crowdstrike"));
  });
});

describe("computeMainSource (#2559)", () => {
  it("14 CrowdStrike files + 1 Velociraptor file → CrowdStrike, 14 of 15", () => {
    const events = [
      ...Array.from({ length: 14 }, (_, i) => file(`cs${i}`, ["CrowdStrike Falcon"])).flat(),
      ...file("v1", ["Velociraptor"], 1, { artifactName: "Windows.NTFS.MFT" }),
    ];
    const r = computeMainSource(events, null);
    expect(r.auto).toBe("crowdstrike");
    expect(r.effective).toBe("crowdstrike");
    expect(r.counts[0]).toEqual({ family: "crowdstrike", files: 14 });
    expect(r.totalFiles).toBe(15);
  });

  it("a single Velociraptor hunt with many rows from one artifact is 1 of 1", () => {
    const r = computeMainSource(file("h1", ["Velociraptor"], 39, { artifactName: "Windows.NTFS.MFT" }), null);
    expect(r.auto).toBe("velociraptor");
    expect(r.totalFiles).toBe(1);
  });

  it("a Velociraptor hunt that collected 40 artifacts counts 40 files (files, not imports)", () => {
    const hunt = Array.from({ length: 40 }, (_, i) =>
      ev({ sources: ["Velociraptor"], importBatchId: "hunt", artifactName: `Artifact.${i}` }),
    );
    const cs = Array.from({ length: 14 }, (_, i) => file(`cs${i}`, ["CrowdStrike Falcon"])).flat();
    const r = computeMainSource([...hunt, ...cs], null);
    expect(r.auto).toBe("velociraptor");
    expect(r.counts.find((c) => c.family === "velociraptor")?.files).toBe(40);
  });

  it("1 + 1 from two families is mixed", () => {
    const r = computeMainSource([...file("a", ["CrowdStrike Falcon"]), ...file("b", ["Velociraptor"])], null);
    expect(r.auto).toBe("mixed");
  });

  it("below 70% is mixed; at 70% with two families is a main source", () => {
    const six = Array.from({ length: 6 }, (_, i) => file(`s${i}`, ["Splunk"])).flat();
    const four = Array.from({ length: 4 }, (_, i) => file(`e${i}`, ["Elastic"])).flat();
    expect(computeMainSource([...six, ...four], null).auto).toBe("mixed");
    const seven = Array.from({ length: 7 }, (_, i) => file(`s${i}`, ["Splunk"])).flat();
    const three = Array.from({ length: 3 }, (_, i) => file(`e${i}`, ["Elastic"])).flat();
    expect(computeMainSource([...seven, ...three], null).auto).toBe("splunk");
  });

  it("an M365-only case → m365; a CloudTrail-only case → cloud-other", () => {
    expect(computeMainSource(file("m", ["Microsoft 365"]), null).auto).toBe("m365");
    expect(computeMainSource(file("t", ["AWS CloudTrail"]), null).auto).toBe("cloud-other");
  });

  it("counts legacy rows with no batch id once per family", () => {
    const legacy = [ev({ sources: ["Splunk"] }), ev({ sources: ["Splunk"] }), ev({ sources: ["Elastic"] })];
    const r = computeMainSource(legacy, null);
    expect(r.totalFiles).toBe(2);
    expect(r.auto).toBe("mixed");
  });

  it("an empty case has no main source and the override still wins", () => {
    expect(computeMainSource([], null).auto).toBeNull();
    expect(computeMainSource([], "splunk").effective).toBe("splunk");
  });

  it("the override replaces the automatic choice, including 'mixed'", () => {
    const events = file("a", ["CrowdStrike Falcon"]);
    expect(computeMainSource(events, "elastic").effective).toBe("elastic");
    expect(computeMainSource(events, "mixed").effective).toBe("mixed");
    expect(computeMainSource(events, "mixed").auto).toBe("crowdstrike");
  });
});

describe("per-finding family on a mixed case (#2559)", () => {
  it("uses the most common family among the finding's related events", () => {
    const events = [
      ev({ id: "x1", sources: ["CrowdStrike Falcon"] }),
      ev({ id: "x2", sources: ["CrowdStrike Falcon"] }),
      ev({ id: "x3", sources: ["Velociraptor"] }),
    ];
    const byId = new Map(events.map((e) => [e.id, e]));
    const f = { id: "f1", relatedEventIds: ["x1", "x2", "x3"] } as unknown as Finding;
    expect(familyForFinding(f, byId)).toBe("crowdstrike");
    expect(familyOfEvents(events)).toBe("crowdstrike");
    expect(familyForFinding({ id: "f2", relatedEventIds: [] } as unknown as Finding, byId)).toBeNull();
  });
});

describe("parseMainSourceOverride (#2559)", () => {
  it("accepts a family, 'mixed' or null and rejects anything else", () => {
    expect(parseMainSourceOverride("crowdstrike")).toEqual({ ok: true, value: "crowdstrike" });
    expect(parseMainSourceOverride("mixed")).toEqual({ ok: true, value: "mixed" });
    expect(parseMainSourceOverride(null)).toEqual({ ok: true, value: null });
    expect(parseMainSourceOverride("vql").ok).toBe(false);
    expect(parseMainSourceOverride(3).ok).toBe(false);
  });
});
