import { describe, it, expect } from "vitest";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    id: over.id, timestamp: "2026-05-26T12:00:00Z", description: "event", severity: "High",
    mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...over,
  };
}

describe("correlateEvents", () => {
  it("merges a Velociraptor event and a THOR event about the same file (shared hash)", () => {
    const HASH = "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef";
    const velo = ev({ id: "m1e1", description: `Downloaded file evil.exe flagged, sha256 ${HASH}`,
      severity: "High", sources: ["CSV import"], sourceScreenshots: ["0001_velo.csv"], timestamp: "2026-05-26T08:35:23Z" });
    const thor = ev({ id: "t2e5", description: "THOR Alert [Filescan]: Malware file found — C:\\Tools\\evil.exe",
      severity: "Critical", sha256: HASH, sources: ["THOR"], sourceScreenshots: ["0002_thor.json"], timestamp: "2026-05-26T08:35:23Z" });

    const out = correlateEvents([velo, thor]);
    expect(out).toHaveLength(1);                       // one canonical event
    expect(out[0].severity).toBe("Critical");          // most severe wins
    expect(out[0].sources).toEqual(expect.arrayContaining(["CSV import", "THOR"]));
    expect(out[0].sourceScreenshots).toEqual(expect.arrayContaining(["0001_velo.csv", "0002_thor.json"]));
    // Corroboration is conveyed via the sources field, NOT by mutating the description.
    expect(out[0].description).not.toContain("corroborated");
  });

  it("never invents 'unknown source' for a source-less event, and self-heals a legacy note", () => {
    // An event from a build before `sources` existed (no sources) merged with a THOR event.
    const legacy = ev({ id: "old", description: "Malware file found — evil.exe [corroborated by 2 sources: unknown source, THOR]",
      sha256: "c".repeat(64), timestamp: "2025-01-01T00:00:00Z" }); // no sources field
    const thor = ev({ id: "new", description: "Malware file found — evil.exe",
      sha256: "c".repeat(64), timestamp: "2025-01-01T00:00:00Z", sources: ["THOR"] });
    const out = correlateEvents([legacy, thor]);
    expect(out).toHaveLength(1);
    expect(out[0].sources).toEqual(["THOR"]);              // only the real source, no "unknown source"
    expect(out[0].description).not.toContain("corroborated"); // legacy note stripped
  });

  it("merges same path within the time window, keeps distinct paths separate", () => {
    const a = ev({ id: "a", description: "m.exe by THOR", path: "c:\\users\\srv\\m.exe", timestamp: "2026-05-26T12:00:00Z", sources: ["THOR"] });
    const b = ev({ id: "b", description: "m.exe by Velo", path: "c:\\users\\srv\\m.exe", timestamp: "2026-05-26T12:00:01Z", sources: ["CSV import"] });
    const c = ev({ id: "c", description: "other.exe", path: "c:\\users\\srv\\other.exe", timestamp: "2026-05-26T12:00:00Z", sources: ["THOR"] });
    const out = correlateEvents([a, b, c], { windowSeconds: 2 });
    expect(out).toHaveLength(2);                        // a+b merge, c separate
    const merged = out.find((e) => e.sources && e.sources.length === 2)!;
    expect(merged.sources).toEqual(expect.arrayContaining(["THOR", "CSV import"]));
  });

  it("does NOT treat a URL in the description as a shared file path (#102)", () => {
    // Two different Defender detections seconds apart, each message carrying the same Microsoft
    // fwlink URL. The URL must not be read as a filesystem path and collapse them into one.
    const url = "https://go.microsoft.com/fwlink/?linkid=37020&name=HackTool:Win32";
    const a = ev({ id: "a", description: `Antivirus Hacktool Detection — ${url}/Passview&threatid=1`, timestamp: "2026-06-03T08:15:40.382Z" });
    const b = ev({ id: "b", description: `Antivirus Hacktool Detection — ${url}/Mimikatz&threatid=2`, timestamp: "2026-06-03T08:15:40.417Z" });
    expect(correlateEvents([a, b], { windowSeconds: 2 })).toHaveLength(2);
  });

  it("correlates a description path against a STRUCTURED path (AI event ↔ import)", () => {
    const ai = ev({ id: "a", description: "wrote payload to /usr/local/bin/x", path: undefined, timestamp: "2026-06-03T08:00:00Z", sources: ["screenshot"] });
    const imp = ev({ id: "b", description: "THOR finding", path: "/usr/local/bin/x", timestamp: "2026-06-03T08:00:01Z", sources: ["THOR"] });
    expect(correlateEvents([ai, imp], { windowSeconds: 2 })).toHaveLength(1);
  });

  it("does NOT merge two FREE-TEXT path mentions (a shared process exe is too weak) (#102)", () => {
    // Distinct Sysmon Proc-Access detections seconds apart that merely share SrcProc powershell.exe
    // in their text must stay separate — neither carries a structured path.
    const exe = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    const a = ev({ id: "a", description: `Proc Access — SrcProc: ${exe} TgtProc: ${exe} Access: 5136`, path: undefined, timestamp: "2026-06-03T08:41:40.537Z", sources: ["Velociraptor"] });
    const b = ev({ id: "b", description: `Proc Access — SrcProc: ${exe} TgtProc: ${exe} Access: 2097151`, path: undefined, timestamp: "2026-06-03T08:41:40.549Z", sources: ["Velociraptor"] });
    expect(correlateEvents([a, b], { windowSeconds: 2 })).toHaveLength(2);
  });

  it("does NOT merge same path when timestamps are outside the window", () => {
    const a = ev({ id: "a", path: "c:\\x.exe", timestamp: "2026-05-26T12:00:00Z" });
    const b = ev({ id: "b", path: "c:\\x.exe", timestamp: "2026-05-26T12:05:00Z" }); // 5 min apart
    expect(correlateEvents([a, b], { windowSeconds: 2 })).toHaveLength(2);
  });

  it("extracts a hash from the description text to match a structured event", () => {
    const HASH = "a".repeat(64);
    const fromText = ev({ id: "x", description: `proc spawned, hash=${HASH}` });
    const structured = ev({ id: "y", description: "THOR finding", sha256: HASH });
    expect(correlateEvents([fromText, structured])).toHaveLength(1);
  });

  it("is idempotent — correlating an already-merged result changes nothing", () => {
    const HASH = "b".repeat(64);
    const once = correlateEvents([ev({ id: "a", sha256: HASH, sources: ["THOR"] }), ev({ id: "b", sha256: HASH, sources: ["CSV"] })]);
    const twice = correlateEvents(once);
    expect(twice).toHaveLength(1);
    expect(twice[0].id).toBe(once[0].id);
  });

  it("collapses exact duplicates (same time + description) — the re-imported-file case", () => {
    // Same THOR finding imported 3 times → 3 events with identical time+description but no
    // shared id (different import prefixes). Must collapse to one.
    const dup = (id: string, src: string) => ev({
      id, description: "THOR Notice [Filescan]: Suspicious file found — C:\\Tools\\NirSoft\\lsasecretsdump.exe",
      timestamp: "2009-11-29T10:25:34Z", severity: "Medium", sources: ["THOR"], sourceScreenshots: [src],
    });
    const out = correlateEvents([dup("t4e1", "0004.json"), dup("t5e1", "0005.json"), dup("t6e1", "0006.json")]);
    expect(out).toHaveLength(1);
    expect(out[0].sourceScreenshots).toEqual(expect.arrayContaining(["0004.json", "0005.json", "0006.json"]));
    expect(out[0].sources).toEqual(["THOR"]); // same source, not falsely "3 sources"
  });

  it("leaves unrelated events untouched and in order (ids preserved)", () => {
    const a = ev({ id: "a", description: "phish opened", path: undefined });
    const b = ev({ id: "b", description: "defender disabled", path: undefined });
    const out = correlateEvents([a, b]);
    expect(out.map((e) => e.id)).toEqual(["a", "b"]);
  });

  it("merges undated events on the same path (no time to disprove)", () => {
    const a = ev({ id: "a", path: "c:\\u.exe", timestamp: "", sources: ["THOR"] });
    const b = ev({ id: "b", path: "c:\\u.exe", timestamp: "", sources: ["CSV import"] });
    expect(correlateEvents([a, b])).toHaveLength(1);
  });

  it("preserves process-chain fields from any event in a merged group", () => {
    const HASH = "d".repeat(64);
    const primary = ev({ id: "a", description: "longer Velociraptor detection text", sha256: HASH, sources: ["Velociraptor"] });
    const withChain = ev({
      id: "b",
      description: "THOR process chain",
      sha256: HASH,
      sources: ["THOR"],
      processName: "powershell.exe",
      parentName: "winword.exe",
      chainCheck: { observed: false, note: "winword.exe -> powershell.exe is unusual", checkedAt: "2026-05-26T12:01:00Z" },
    });

    const out = correlateEvents([primary, withChain]);

    expect(out).toHaveLength(1);
    expect(out[0].processName).toBe("powershell.exe");
    expect(out[0].parentName).toBe("winword.exe");
    expect(out[0].chainCheck?.observed).toBe(false);
  });
});
