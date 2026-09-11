import { describe, it, expect } from "vitest";
import {
  normalizeSha256,
  upsertLabIntel,
  annotateSightingsWithLabIntel,
  labIntelTag,
  isLabProduced,
  selectLabIntelForDisplay,
} from "../../src/analysis/labIntel.js";
import type { ForensicEvent, InvestigationState, LabIntelRecord } from "../../src/analysis/stateTypes.js";

const SHA = "a".repeat(64);
const rec = (over: Partial<LabIntelRecord> = {}): LabIntelRecord => ({
  sha256: SHA,
  source: "CAPEv2",
  runId: "42",
  verdict: "malicious",
  score: 9,
  family: "Emotet",
  signatures: ["injection_explorer", "c2_beacon"],
  detonatedAt: "2026-09-10T10:00:00.000Z",
  importedAt: "2026-09-10T11:00:00.000Z",
  ...over,
});
const ev = (over: Partial<ForensicEvent> & { id: string }): ForensicEvent => ({
  timestamp: "2026-05-01T08:00:00Z",
  description: "file created C:\\Users\\x\\invoice.exe",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  sources: ["KAPE"],
  ...over,
});
const state = (events: ForensicEvent[], labIntel?: LabIntelRecord[]): InvestigationState =>
  ({
    findings: [],
    iocs: [],
    mitreTechniques: [],
    forensicTimeline: events,
    labIntel,
  }) as unknown as InvestigationState;

describe("normalizeSha256", () => {
  it("accepts exactly 64 hex, trimmed and lowercased", () => {
    expect(normalizeSha256(`  ${"A".repeat(64)} `)).toBe("a".repeat(64));
  });
  // A field named sha256 is not an identity until it is one — a common token or an md5 must never
  // become the key that attaches lab behaviour to a sighting.
  it.each(["", "deadbeef", "b".repeat(32), "g".repeat(64), `${"a".repeat(63)}z`])("rejects %j", (bad) =>
    expect(normalizeSha256(bad)).toBe(""),
  );
});

describe("upsertLabIntel", () => {
  it("adds by (sha256, source, runId) and replaces the same key", () => {
    const a = upsertLabIntel([], [rec()]);
    expect(a).toHaveLength(1);
    const b = upsertLabIntel(a, [rec({ score: 10 })]);
    expect(b).toHaveLength(1);
    expect(b[0].score).toBe(10);
    const c = upsertLabIntel(b, [rec({ runId: "43" }), rec({ source: "Falcon Sandbox", runId: "j1" })]);
    expect(c).toHaveLength(3);
  });
  it("drops a record whose sha256 does not normalise", () => {
    expect(upsertLabIntel([], [rec({ sha256: "not-a-hash" })])).toEqual([]);
  });
  it("is deterministic in order regardless of insertion order", () => {
    const x = upsertLabIntel([], [rec({ runId: "9" }), rec({ runId: "10" })]);
    const y = upsertLabIntel([], [rec({ runId: "10" }), rec({ runId: "9" })]);
    expect(x).toEqual(y);
  });
});

describe("annotateSightingsWithLabIntel", () => {
  it("puts the sample's detonations on the incident event that carries the hash — and touches nothing else on it", () => {
    const e = ev({ id: "e1", sha256: SHA, severity: "Info", timestamp: "2026-05-01T08:00:00Z" });
    const out = annotateSightingsWithLabIntel(state([e], [rec()]));
    const got = out.forensicTimeline[0];
    expect(got.labIntel).toHaveLength(1);
    expect(got.labIntel?.[0].verdict).toBe("malicious");
    expect(got.timestamp).toBe("2026-05-01T08:00:00Z"); // NOT the detonation time
    expect(got.severity).toBe("Info");
    expect(got.description).toBe(e.description);
  });
  it("matches on the normalised hash, so an uppercase digest on the event still matches", () => {
    const out = annotateSightingsWithLabIntel(state([ev({ id: "e1", sha256: SHA.toUpperCase() })], [rec()]));
    expect(out.forensicTimeline[0].labIntel).toHaveLength(1);
  });
  it("never annotates a lab row, even one carrying the hash", () => {
    const out = annotateSightingsWithLabIntel(state([ev({ id: "e1", sha256: SHA, origin: "lab" })], [rec()]));
    expect(out.forensicTimeline[0].labIntel).toBeUndefined();
  });
  it("clears a stale annotation when the registry no longer has the record", () => {
    const stale = ev({ id: "e1", sha256: SHA, labIntel: [rec()] });
    const out = annotateSightingsWithLabIntel(state([stale], []));
    expect(out.forensicTimeline[0].labIntel).toBeUndefined();
  });
  it("is a no-op that returns the same object when there is no registry", () => {
    const s = state([ev({ id: "e1", sha256: SHA })]);
    expect(annotateSightingsWithLabIntel(s)).toBe(s);
  });
  it("does not mutate its input", () => {
    const e = ev({ id: "e1", sha256: SHA });
    annotateSightingsWithLabIntel(state([e], [rec()]));
    expect(e.labIntel).toBeUndefined();
  });
});

describe("selectLabIntelForDisplay", () => {
  // Four reruns must not hide the newest or the worst behind a lexical run-id sort.
  it("orders newest detonation first, worst verdict on ties, caps at 3 and reports the overflow", () => {
    const recs = [
      rec({ runId: "sb10", detonatedAt: "2026-09-01T00:00:00Z", verdict: "unknown" }),
      rec({ runId: "sb2", detonatedAt: "2026-09-04T00:00:00Z", verdict: "malicious" }),
      rec({ runId: "sb3", detonatedAt: "2026-09-04T00:00:00Z", verdict: "suspicious" }),
      rec({ runId: "sb9", detonatedAt: "2026-09-02T00:00:00Z", verdict: "unknown" }),
    ];
    const { shown, omitted } = selectLabIntelForDisplay(recs);
    expect(shown.map((r) => r.runId)).toEqual(["sb2", "sb3", "sb9"]);
    expect(omitted).toBe(1);
  });
});

describe("labIntelTag", () => {
  it("renders one compact tag per record, with the family, score, and up to two signatures", () => {
    const tag = labIntelTag([rec()]);
    expect(tag).toBe(" <sandbox:CAPEv2 malicious Emotet 9 injection_explorer,c2_beacon>");
  });
  it("says how many were omitted when capped", () => {
    const recs = [1, 2, 3, 4].map((n) => rec({ runId: String(n), detonatedAt: `2026-09-0${n}T00:00:00Z` }));
    expect(labIntelTag(recs)).toMatch(/\+1 more>$/);
  });
  it("is empty for none", () => {
    expect(labIntelTag(undefined)).toBe("");
    expect(labIntelTag([])).toBe("");
  });
});

describe("isLabProduced", () => {
  it("is true for a row the importer marked", () => {
    expect(isLabProduced(ev({ id: "e", origin: "lab" }))).toBe(true);
  });
  // Legacy rows predate the field. They are recognised ONLY when every source is a sandbox provider
  // AND the description carries the importer's own prefix — provably sandbox-produced.
  it("recognises a legacy CAPE verdict row and a legacy Falcon signature row by their real prefixes", () => {
    expect(
      isLabProduced(
        ev({ id: "e", sources: ["CAPEv2"], description: "CAPE sandbox: Emotet — invoice.exe score 9/10" }),
      ),
    ).toBe(true);
    expect(
      isLabProduced(
        ev({ id: "e", sources: ["CAPEv2"], description: "CAPE signature: injection_explorer — …" }),
      ),
    ).toBe(true);
    expect(
      isLabProduced(
        ev({ id: "e", sources: ["Falcon Sandbox"], description: "Falcon Sandbox: malicious — x.exe" }),
      ),
    ).toBe(true);
    expect(
      isLabProduced(
        ev({ id: "e", sources: ["Falcon Sandbox"], description: "Falcon signature: Writes to registry" }),
      ),
    ).toBe(true);
  });
  // A row that ALREADY merged with a host observation is contaminated evidence, not a lab row: it is
  // never reclassified, because demoting it would hide a real host event.
  it("is false when a host source is also present, and false for a host row that merely mentions a sandbox", () => {
    expect(isLabProduced(ev({ id: "e", sources: ["CAPEv2", "KAPE"], description: "CAPE sandbox: …" }))).toBe(
      false,
    );
    expect(
      isLabProduced(ev({ id: "e", sources: ["KAPE"], description: "note: see CAPE sandbox: report" })),
    ).toBe(false);
  });
});
