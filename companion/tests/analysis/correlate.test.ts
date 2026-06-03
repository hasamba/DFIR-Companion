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
    expect(out[0].description).toContain("corroborated by 2 sources");
  });

  it("merges same path within the time window, keeps distinct paths separate", () => {
    const a = ev({ id: "a", path: "c:\\users\\srv\\m.exe", timestamp: "2026-05-26T12:00:00Z", sources: ["THOR"] });
    const b = ev({ id: "b", path: "c:\\users\\srv\\m.exe", timestamp: "2026-05-26T12:00:01Z", sources: ["CSV import"] });
    const c = ev({ id: "c", path: "c:\\users\\srv\\other.exe", timestamp: "2026-05-26T12:00:00Z", sources: ["THOR"] });
    const out = correlateEvents([a, b, c], { windowSeconds: 2 });
    expect(out).toHaveLength(2);                        // a+b merge, c separate
    const merged = out.find((e) => e.sources && e.sources.length === 2)!;
    expect(merged.sources).toEqual(expect.arrayContaining(["THOR", "CSV import"]));
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
});
