import { describe, it, expect } from "vitest";
import {
  backfillDefenderEpisodeFindings,
  defenderFindingId,
} from "../../src/analysis/defenderEpisodeFindings.js";
import { corroborateDefenderEpisodes } from "../../src/analysis/defenderEpisodes.js";
import { backfillHighSeverityFindings } from "../../src/analysis/highSeverityFindings.js";
import { groundAndScoreFindings, SINGLE_SOURCE_CONFIDENCE_CAP } from "../../src/analysis/findingGrounding.js";
import {
  DEFENDER_FINDING_ID_PREFIX,
  isDeterministicFindingId,
  renameForgedFindingIds,
} from "../../src/analysis/responseSchema.js";
import { emptyState, type ForensicEvent, type Finding } from "../../src/analysis/stateTypes.js";

// #964: for a Defender record that allowed, failed to remediate, or remediated, followed by a
// HASH-matched start — one deterministic finding per record, machine-owned outcome fields, linked
// to both events so the generic High backfill does not fire a second one.

const T = "2026-06-01T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const H = 3600;
const PATH = "C:\\Users\\a.mehta\\Downloads\\invoice.exe";
const THREAT = "Trojan:Win32/Wacatac.B!ml";
const SHA = "425a1a21a4dbc212c3c3db5f8fecdd6235e7e7fe2fcfce3affe3f9f80aa24a92";

const ev = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: "e",
  timestamp: T,
  description: "",
  severity: "Medium",
  mitreTechniques: [],
  sourceScreenshots: [],
  relatedFindingIds: [],
  asset: "WS-042",
  path: PATH,
  ...over,
});
const defender = (disposition: string, over: Partial<ForensicEvent> = {}, withHash = true): ForensicEvent =>
  ev({
    id: `d-${disposition}`,
    description: `[control: ${disposition}] Quarantine ${THREAT} — ${PATH} (EID 1117, Microsoft Defender) @ WS-042`,
    sources: ["Microsoft Defender"],
    canonical: {
      event: { category: "file", type: "action", action: "Quarantine", outcome: "success" },
      file: { path: PATH },
      time: { normalized: over.timestamp ?? T },
      defender: {
        disposition,
        threat: THREAT,
        detectionId: "{5B6A6C58-1F33-4B4E-9A9F-0C0A1D2E3F40}",
        eventType: "action",
        resources: [PATH],
        resourcesTotal: 1,
        ...(withHash ? { sha256: SHA } : {}),
      },
    } as never,
    ...over,
  });
const start = (over: Partial<ForensicEvent> = {}): ForensicEvent =>
  ev({
    id: "s1",
    timestamp: at(H),
    description: "Sysmon 1 Process create: invoice.exe",
    severity: "Low",
    sources: ["Sysmon"],
    sha256: SHA,
    canonical: { event: { category: "process", type: "start" } } as never,
    ...over,
  });
const stateOf = (events: ForensicEvent[], findings: Finding[] = []) => {
  const s = emptyState("c1");
  s.forensicTimeline = corroborateDefenderEpisodes(events);
  s.findings = findings;
  return s;
};
const all = (s: ReturnType<typeof stateOf>) => new Set(s.forensicTimeline.map((e) => e.id));

describe("backfillDefenderEpisodeFindings", () => {
  it("allowed + hash-matched start → one High finding with machine control/execution, linked to both events", () => {
    const s = stateOf([defender("allowed"), start()]);
    const out = backfillDefenderEpisodeFindings(s, all(s), at(2 * H));
    expect(out.findings).toHaveLength(1);
    const f = out.findings[0];
    expect(f.id.startsWith(DEFENDER_FINDING_ID_PREFIX)).toBe(true);
    expect(isDeterministicFindingId(f.id)).toBe(true);
    expect(f).toMatchObject({
      severity: "High",
      status: "open",
      control: "allowed",
      controlSource: "machine",
      execution: "observed",
      executionSource: "machine",
      mitreTechniques: [],
      confidence: 85,
      title: `Defender allowed ${THREAT} on WS-042; the same file later started`,
    });
    expect(f.description).toContain(SHA);
    expect(f.description).toContain("1h 0m");
    expect(f.description).not.toMatch(/retry|re-dropped|T1204/);
    for (const id of ["d-allowed", "s1"])
      expect(out.forensicTimeline.find((e) => e.id === id)!.relatedFindingIds).toEqual([f.id]);
    // Two tools (Defender, Sysmon) on one host: grounding keeps the stated 85. When one tool
    // recorded both rows, the single-source rule caps it.
    const grade = (st: typeof out) =>
      groundAndScoreFindings({
        findings: st.findings,
        scopedEvents: st.forensicTimeline,
        iocs: [],
        graphLinkedEventIds: new Set(),
      })[0].confidence;
    expect(grade(out)).toBe(85);
    const oneTool = stateOf([defender("allowed"), start({ sources: ["Microsoft Defender"] })]);
    expect(grade(backfillDefenderEpisodeFindings(oneTool, all(oneTool), at(2 * H)))).toBe(
      SINGLE_SOURCE_CONFIDENCE_CAP,
    );
    // The generic High backfill sees the linked start row and raises nothing more.
    const generic = backfillHighSeverityFindings(out, all(out), at(3 * H));
    expect(generic.findings).toHaveLength(1);
  });
  it("remediation-failed and remediated qualify; blocked, none-observed and a detection-only record do not", () => {
    for (const d of ["remediation-failed", "remediated"]) {
      const s = stateOf([defender(d), start()]);
      const out = backfillDefenderEpisodeFindings(s, all(s), at(2 * H));
      expect(out.findings).toHaveLength(1);
      expect(out.findings[0].control).toBe(d);
    }
    for (const d of ["blocked", "none-observed", "unknown"]) {
      const s = stateOf([defender(d), start()]);
      expect(backfillDefenderEpisodeFindings(s, all(s), at(2 * H)).findings).toHaveLength(0);
    }
  });
  it("a path-only pairing gets no finding, and the generic backfill does not fire on it either", () => {
    const s = stateOf([defender("allowed", {}, false), start({ sha256: undefined })]);
    const out = backfillDefenderEpisodeFindings(s, all(s), at(2 * H));
    expect(out.findings).toHaveLength(0);
    expect(out.forensicTimeline.find((e) => e.id === "s1")!.severity).toBe("Medium");
    expect(backfillHighSeverityFindings(out, all(out), at(3 * H)).findings).toHaveLength(0);
  });
  it("two records with different dispositions and their own sequels are two findings, identical for both input orders", () => {
    const a = defender("allowed", { id: "d1", timestamp: T });
    const s1 = start({ id: "s1", timestamp: at(H) });
    const r = defender("remediated", { id: "d2", timestamp: at(2 * H) });
    const s2 = start({ id: "s2", timestamp: at(3 * H) });
    const one = backfillDefenderEpisodeFindings(
      stateOf([a, s1, r, s2]),
      new Set(["d1", "s1", "d2", "s2"]),
      at(4 * H),
    );
    const two = backfillDefenderEpisodeFindings(
      stateOf([s2, r, s1, a]),
      new Set(["d1", "s1", "d2", "s2"]),
      at(4 * H),
    );
    expect(one.findings.map((f) => [f.id, f.control]).sort()).toEqual(
      two.findings.map((f) => [f.id, f.control]).sort(),
    );
    expect(one.findings).toHaveLength(2);
    expect(one.findings.map((f) => f.control).sort()).toEqual(["allowed", "remediated"]);
  });
  it("the id is the record's content: stable when the merged row takes a duplicate's event id", () => {
    const a = defender("allowed", { id: "d1" });
    const b = defender("allowed", { id: "e-hayabusa-high" });
    expect(defenderFindingId(a)).toBe(defenderFindingId(b));
    expect(defenderFindingId(defender("allowed", { asset: "WS-043" }))).not.toBe(defenderFindingId(a));
  });
  it("a window holding either endpoint keeps the finding under its id; one holding neither leaves it to the carry; a model echo is rebuilt, status kept", () => {
    const s = stateOf([defender("allowed"), start()]);
    // Either endpoint in scope mints the same id (code round 1, finding 3): a narrow window never
    // drops the finding, and the dismissal marker re-applies by id.
    const onlyStart = backfillDefenderEpisodeFindings(s, new Set(["s1"]), at(2 * H)).findings;
    const onlyRecord = backfillDefenderEpisodeFindings(s, new Set(["d-allowed"]), at(2 * H)).findings;
    expect(onlyStart.map((f) => f.id)).toEqual(onlyRecord.map((f) => f.id));
    expect(onlyStart).toHaveLength(1);
    expect(backfillDefenderEpisodeFindings(s, new Set(), at(2 * H)).findings).toHaveLength(0);
    // A model echoed the known id with its own words: the pass rebuilds title, severity, outcome
    // fields and description; the analyst's status survives.
    const id = defenderFindingId(s.forensicTimeline.find((e) => e.id === "d-allowed")!);
    const echoed: Finding = {
      id,
      severity: "Low",
      title: "nothing to see",
      description: "model prose",
      relatedIocs: [],
      mitreTechniques: ["T1204.002"],
      sourceScreenshots: [],
      firstSeen: T,
      lastUpdated: T,
      status: "dismissed",
    };
    const known = new Set([id]);
    expect(renameForgedFindingIds({ findings: [echoed] } as never, known).findings[0].id).toBe(id);
    const out = backfillDefenderEpisodeFindings({ ...s, findings: [echoed] }, all(s), at(2 * H));
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      id,
      severity: "High",
      status: "dismissed",
      control: "allowed",
      execution: "observed",
      mitreTechniques: [],
    });
    expect(out.findings[0].title).not.toBe("nothing to see");
    // The partner left the case: the finding stays under its id with the analyst's status, but its
    // machine claims are withdrawn and its links removed (code round 1, finding 4).
    const partnerless = backfillDefenderEpisodeFindings(
      { ...out, forensicTimeline: out.forensicTimeline.filter((e) => e.id !== "s1") },
      new Set(["d-allowed"]),
      at(3 * H),
    );
    expect(partnerless.findings).toHaveLength(1);
    expect(partnerless.findings[0]).toMatchObject({
      id,
      status: "dismissed",
      severity: "Low",
      confidence: 10,
      execution: "unknown",
      control: "unknown",
    });
    expect(
      partnerless.findings[0].description.startsWith("No longer supported by the current evidence"),
    ).toBe(true);
    expect(partnerless.forensicTimeline.find((e) => e.id === "d-allowed")!.relatedFindingIds).toEqual([]);
    // Run again: the prefix does not stack.
    const again = backfillDefenderEpisodeFindings(partnerless, new Set(["d-allowed"]), at(4 * H));
    expect(again.findings[0].description.split("No longer supported")).toHaveLength(2);
    // The record out of scope says nothing: the finding is left as it is.
    const untouched = backfillDefenderEpisodeFindings(
      { ...out, forensicTimeline: out.forensicTimeline.filter((e) => e.id !== "s1") },
      new Set(),
      at(3 * H),
    );
    expect(untouched.findings[0].severity).toBe("High");
  });
});
