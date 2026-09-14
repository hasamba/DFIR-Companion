import { describe, it, expect } from "vitest";
import {
  corroborateDefenderEpisodes,
  defenderEpisodeMatches,
  defenderEpisodes,
  DEFENDER_SEQUEL_MARKER,
  DEFENDER_SEQUEL_TOLERANCE_MS,
  STARTS_NAMED_MAX,
} from "../../src/analysis/defenderEpisodes.js";
import { correlateEvents, cleanDescription } from "../../src/analysis/correlate.js";
import { DERIVED_NOTE_NAMES } from "../../src/analysis/derivedNote.js";
import type { ControlDisposition, ForensicEvent, Severity } from "../../src/analysis/stateTypes.js";

// #930 item 1 part B (#964): a Defender action, then a later start of the same file on the same
// host. Pairs with ONE exact preceding Defender record; a path match says "the same path", a hash
// match (the Defender record's OWN sha256 only) says "the same file". Only raises; recomputed on
// every merge.

interface Ev {
  id: string;
  timestamp: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  path?: string;
  asset?: string;
  sha256?: string;
  sources?: string[];
  relatedFindingIds?: string[];
  canonical?: {
    event?: { category?: string; type?: string; action?: string; outcome?: string };
    file?: { path?: string; sha256?: string };
    time?: { normalized?: string };
    defender?: {
      disposition: ControlDisposition;
      threat: string;
      detectionId?: string;
      eventType: "detection" | "action";
      resources: string[];
      container?: string;
      resourcesTotal: number;
    };
  };
}

const T = "2026-06-01T10:00:00.000Z";
const at = (s: number) => new Date(Date.parse(T) + s * 1000).toISOString();
const H = 3600;
const PATH = "C:\\Users\\a.mehta\\Downloads\\invoice.exe";
const THREAT = "Trojan:Win32/Wacatac.B!ml";
const SHA = "425a1a21a4dbc212c3c3db5f8fecdd6235e7e7fe2fcfce3affe3f9f80aa24a92";

const defender = (
  disposition: ControlDisposition,
  over: Partial<Ev> = {},
  block: Partial<NonNullable<Ev["canonical"]>["defender"]> = {},
): Ev => ({
  id: over.id ?? `d-${disposition}`,
  timestamp: T,
  description: `[control: ${disposition}] Quarantine ${THREAT} — ${PATH} (EID 1117, Microsoft Defender) @ WS-042`,
  severity: "Medium",
  mitreTechniques: [],
  path: PATH,
  asset: "WS-042",
  sources: ["Microsoft Defender"],
  ...over,
  canonical: {
    event: {
      category: "file",
      type: disposition === "unknown" ? "detection" : "action",
      action: "Quarantine",
      outcome: "success",
    },
    file: { path: PATH },
    time: { normalized: over.timestamp ?? T },
    defender: {
      disposition,
      threat: THREAT,
      detectionId: "{5B6A6C58-1F33-4B4E-9A9F-0C0A1D2E3F40}",
      eventType: disposition === "unknown" ? "detection" : "action",
      resources: [PATH],
      resourcesTotal: 1,
      ...block,
    },
    ...(over.canonical ?? {}),
  },
});
const start = (over: Partial<Ev> = {}): Ev => ({
  id: "s1",
  timestamp: at(H),
  description: "Sysmon 1 Process create: invoice.exe",
  severity: "Low",
  mitreTechniques: [],
  path: PATH,
  asset: "WS-042",
  sources: ["Sysmon"],
  canonical: { event: { category: "process", type: "start" } },
  ...over,
});
const run = (events: Ev[]) => corroborateDefenderEpisodes(events);
const find = (out: Ev[], id: string) => out.find((e) => e.id === id)!;

describe("episodes", () => {
  it("groups by host + detection id, else host + threat + normalised path; a gap closes an episode", () => {
    const a = defender("unknown", { id: "d1", timestamp: T });
    const b = defender("remediated", { id: "d2", timestamp: at(60) });
    const later = defender("unknown", { id: "d3", timestamp: at(48 * H) });
    const eps = defenderEpisodes([a, b, later], 24);
    expect(eps).toHaveLength(2);
    expect(eps[0].records.map((r) => r.event.id)).toEqual(["d1", "d2"]);
    expect(eps[1].records.map((r) => r.event.id)).toEqual(["d3"]);
    expect(eps[0].id).not.toBe(eps[1].id);
    // No detection id: threat + path is the identity; a different path is another episode.
    const noId = (id: string, path: string, ts: string) =>
      defender("unknown", { id, timestamp: ts, path }, { detectionId: undefined, resources: [path] });
    const byPath = defenderEpisodes(
      [noId("x1", PATH, T), noId("x2", PATH, at(10)), noId("x3", "C:\\tmp\\other.exe", at(20))],
      24,
    );
    expect(byPath).toHaveLength(2);
    // Two hosts never share an episode.
    expect(defenderEpisodes([a, defender("remediated", { id: "d9", asset: "WS-043" })], 24)).toHaveLength(2);
  });
  it("the episode id is record content, not the timeline event id", () => {
    const one = defenderEpisodes([defender("unknown", { id: "d1" })], 24)[0].id;
    const renamed = defenderEpisodes([defender("unknown", { id: "e-high-hayabusa" })], 24)[0].id;
    expect(renamed).toBe(one);
    expect(defenderEpisodes([defender("unknown", { id: "d1", timestamp: at(48 * H) })], 24)[0].id).not.toBe(
      one,
    );
  });
});

describe("pairing — one exact preceding record, its disposition", () => {
  it("failed → start → remediated says remediation-failed; remediated → start → failed says remediated", () => {
    const failed = defender("remediation-failed", { id: "d1", timestamp: T });
    const ok = defender("remediated", { id: "d2", timestamp: at(2 * H) });
    const s = start({ id: "s1", timestamp: at(H) });
    const out = run([failed, s, ok]);
    expect(find(out, "s1").description).toContain(
      `${DEFENDER_SEQUEL_MARKER} remediation-failed of ${THREAT}; a process later started from the same path ${PATH} (1h 0m later)]`,
    );
    const swapped = run([
      defender("remediated", { id: "d1", timestamp: T }),
      start({ id: "s1", timestamp: at(H) }),
      defender("remediation-failed", { id: "d2", timestamp: at(2 * H) }),
    ]);
    expect(find(swapped, "s1").description).toContain(`${DEFENDER_SEQUEL_MARKER} remediated of ${THREAT};`);
    expect(find(swapped, "s1").description).not.toContain("remediation-failed");
  });
  it("a start inside the tolerance, before the record, or past the gap bound does not pair; a detection-only record pairs as unknown", () => {
    const d = defender("allowed", { id: "d1" });
    expect(
      find(run([d, start({ timestamp: at(DEFENDER_SEQUEL_TOLERANCE_MS / 1000) })]), "s1").description,
    ).not.toContain(DEFENDER_SEQUEL_MARKER);
    expect(find(run([d, start({ timestamp: at(-H) })]), "s1").description).not.toContain(
      DEFENDER_SEQUEL_MARKER,
    );
    expect(find(run([d, start({ timestamp: at(25 * H) })]), "s1").description).not.toContain(
      DEFENDER_SEQUEL_MARKER,
    );
    const det = run([defender("unknown", { id: "d1" }), start()]);
    expect(find(det, "s1").description).toContain(
      `${DEFENDER_SEQUEL_MARKER} detected (no action recorded) ${THREAT};`,
    );
  });
});

describe("what matches", () => {
  it("a path match raises to Medium, adds no technique, says 'the same path' and never 'the same file'", () => {
    const out = run([defender("allowed"), start()]);
    const s = find(out, "s1");
    expect(s.severity).toBe("Medium");
    expect(s.mitreTechniques).toEqual([]);
    expect(s.description).toContain("a process later started from the same path");
    expect(s.description).not.toMatch(/same file|retry|re-dropped|T1204/);
    // The Defender record says what followed; its severity stays Medium.
    const d = find(out, "d-allowed");
    expect(d.severity).toBe("Medium");
    expect(d.description).toContain(
      `${DEFENDER_SEQUEL_MARKER} allowed of ${THREAT}; 1 later start from the same path, first at ${at(H)}]`,
    );
  });
  it("a second archive member matches by its member path; a resource beyond the bounded list is said, not matched", () => {
    const member = "C:\\Users\\a.mehta\\Downloads\\pack.zip->dropper.exe";
    const d = defender("allowed", {}, { resources: [PATH, member], resourcesTotal: 3 });
    const out = run([d, start({ path: member })]);
    expect(find(out, "s1").description).toContain(`a process later started from the same path ${member}`);
    expect(find(out, "d-allowed").description).toContain("1 of 3 listed resources not read");
  });
  it("a hash match needs the Defender record's OWN sha256 — never a borrowed earlier hash, never a veto", () => {
    // A hashed earlier start at the path, then the detection, then a start with another hash:
    // path match, nothing about "not the same file".
    const earlier = start({ id: "s0", timestamp: at(-2 * H), sha256: "a".repeat(64) });
    const d = defender("allowed", { timestamp: T });
    const out = run([earlier, d, start({ sha256: "b".repeat(64) })]);
    expect(find(out, "s1").description).toContain("a process later started from the same path");
    expect(find(out, "s1").description).not.toMatch(/same file|differs|reused/);
    expect(find(out, "s0").description).not.toContain(DEFENDER_SEQUEL_MARKER);
    // The record carries its own digest (an export that has one): the same digest starting later is
    // "the same file", High; a different digest at the same path is a path match only.
    const own = defender("allowed", { sha256: SHA, canonical: { file: { path: PATH, sha256: SHA } } });
    const hashed = run([own, start({ sha256: SHA })]);
    expect(find(hashed, "s1").severity).toBe("High");
    expect(find(hashed, "s1").description).toContain(
      `${DEFENDER_SEQUEL_MARKER} allowed of ${THREAT}; the same file (sha256) later started from ${PATH} (1h 0m later)]`,
    );
    const other = run([own, start({ sha256: "c".repeat(64) })]);
    expect(find(other, "s1").severity).toBe("Medium");
    expect(find(other, "s1").description).toContain("from the same path");
  });
  it("a different host never matches; equal short labels pair only when the label names one host", () => {
    const d = defender("allowed", { asset: "ws01.corp-a.example" });
    expect(find(run([d, start({ asset: "ws01.corp-b.example" })]), "s1").description).not.toContain(
      DEFENDER_SEQUEL_MARKER,
    );
    expect(find(run([d, start({ asset: "WS01" })]), "s1").description).toContain(DEFENDER_SEQUEL_MARKER);
    // A third host with the same label makes the short one ambiguous: no pairing.
    const ambiguous = run([
      d,
      start({ asset: "WS01" }),
      start({ id: "s2", asset: "ws01.corp-b.example", timestamp: at(50 * H) }),
    ]);
    expect(find(ambiguous, "s1").description).not.toContain(DEFENDER_SEQUEL_MARKER);
  });
  it("a Prefetch / Amcache presence row is not a start; a non-start row's hash never enters", () => {
    const own = defender("allowed", { sha256: SHA, canonical: { file: { path: PATH, sha256: SHA } } });
    const pf = start({ id: "p1", sources: ["Prefetch"], canonical: undefined, sha256: SHA });
    const thor = start({
      id: "t1",
      sources: ["THOR"],
      canonical: { event: { category: "file", type: "detection" } },
      sha256: SHA,
    });
    const out = run([own, pf, thor]);
    expect(find(out, "p1").description).not.toContain(DEFENDER_SEQUEL_MARKER);
    expect(find(out, "t1").description).not.toContain(DEFENDER_SEQUEL_MARKER);
  });
  it("names starts up to the bound and counts the rest; text from evidence is neutralised", () => {
    const d = defender(
      "allowed",
      { path: "C:\\drop\\sample[1].exe" },
      { threat: "Bad[Thing]", resources: ["C:\\drop\\sample[1].exe"] },
    );
    const starts = Array.from({ length: STARTS_NAMED_MAX + 3 }, (_, i) =>
      start({ id: `s${i}`, timestamp: at(H + i * 60), path: "C:\\drop\\sample[1].exe" }),
    );
    const out = run([d, ...starts]);
    const note = find(out, "d-allowed").description;
    expect(note).toContain(`${STARTS_NAMED_MAX + 3} later starts from the same path`);
    expect(note).toContain("Bad(Thing)");
    expect(find(out, "s0").description).toContain("sample(1).exe");
    expect(cleanDescription(find(out, "s0").description)).toBe(cleanDescription(starts[0].description));
  });
});

describe("merge and idempotence", () => {
  it("the note survives correlate.mergeGroup once in both input orders and across a second merge; the partner leaving removes it", () => {
    expect(DERIVED_NOTE_NAMES).toContain("after Defender");
    const annotated = run([defender("allowed"), start({ severity: "Low" })]);
    const s = find(annotated, "s1") as unknown as ForensicEvent;
    // A higher-severity unannotated duplicate of the same start (another tool, same path/time).
    const twin = {
      ...(start({ id: "s1-twin", severity: "High", sources: ["EDR"] }) as unknown as ForensicEvent),
      description: "EDR process start: invoice.exe",
    };
    const merge = (evs: ForensicEvent[]) =>
      correlateEvents(evs.map((e) => ({ ...e, relatedFindingIds: [], sourceScreenshots: [] })));
    const ab = merge([s, twin]).find((e) => e.description.includes(DEFENDER_SEQUEL_MARKER))!;
    const ba = merge([twin, s]).find((e) => e.description.includes(DEFENDER_SEQUEL_MARKER))!;
    expect(ab.description.split(DEFENDER_SEQUEL_MARKER)).toHaveLength(2);
    expect(ba.description.split(DEFENDER_SEQUEL_MARKER)).toHaveLength(2);
    const again = merge([ab])[0];
    expect(again.description.split(DEFENDER_SEQUEL_MARKER)).toHaveLength(2);
    // Re-run over the annotated rows: nothing doubles.
    const twice = run(annotated);
    expect(find(twice, "s1").description).toBe(s.description);
    // The Defender record left the case: the note comes off, the raised severity stays.
    const gone = run([find(annotated, "s1")]);
    expect(gone[0].description).not.toContain(DEFENDER_SEQUEL_MARKER);
    expect(gone[0].severity).toBe("Medium");
  });
  it("defenderEpisodeMatches exposes the typed pairing the finding pass reads", () => {
    const own = defender("allowed", { sha256: SHA, canonical: { file: { path: PATH, sha256: SHA } } });
    const m = defenderEpisodeMatches(
      [own, start({ sha256: SHA }), start({ id: "s2", timestamp: at(2 * H) })],
      24,
    );
    expect(m).toHaveLength(1);
    expect(m[0].record.event.id).toBe("d-allowed");
    expect(m[0].disposition).toBe("allowed");
    expect(m[0].starts.map((s) => [s.event.id, s.by])).toEqual([
      ["s1", "hash"],
      ["s2", "path"],
    ]);
  });
});
