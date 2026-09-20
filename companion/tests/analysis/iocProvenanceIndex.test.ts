// PLAN-1452 slice C — the equivalence harness.
//
// The two IOC-provenance reads no longer stream the whole super-timeline: they ask the case
// database's FTS term index (`event_terms`) for candidate rows and run the UNCHANGED #1444 builders
// over those. The index only has to hand the builders a superset of the true matches, so the proof
// is one comparison: after every write path that touches the index, the indexed reader must
// deep-equal the whole-array reference over `load()` + `eventBatches()`.
//
// This file drives a REAL temp case database through every such path in one scripted sequence —
// state saves that add, re-grade (tagger), rewrite (update) and drop (undo) forensic rows; super
// appends with id and content dedup collisions; an IOC added after its events; cap eviction;
// prune; and a legacy database with no index at all — and compares after each step.
import { describe, it, expect, beforeAll } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore, INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { createIocProvenanceReads } from "../../src/analysis/iocProvenanceRead.js";
import { deriveIocProvenance, type IocProvenance } from "../../src/analysis/iocProvenance.js";
import { buildIocProvenanceChains, type IocProvenanceChain } from "../../src/analysis/iocProvenanceChain.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type IOC,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";

const CASE = "c1";
const T = (day: number, hour = 0): string =>
  `2026-06-${String(day).padStart(2, "0")}T${String(hour).padStart(2, "0")}:00:00Z`;
const IP = "10.9.8.7";
const IP_LONGER = "10.9.8.77"; // contains IP as a SUBSTRING of one token — must never count for IP
const SHA = "AB".repeat(32);
const MD5 = "CD".repeat(16);
const PATH = "C:\\Program Files\\x\\drop.ps1";
const DOMAIN = "evil.example";

function ev(p: Partial<ForensicEvent> & { id: string; severity: ForensicEvent["severity"] }): ForensicEvent {
  return {
    timestamp: T(1),
    description: "",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}
const ioc = (p: Partial<IOC> & { id: string; type: IOC["type"]; value: string }): IOC => ({
  firstSeen: T(1),
  ...p,
});
const finding = (p: Partial<Finding> & { id: string }): Finding => ({
  severity: "Medium",
  title: "f",
  description: "",
  relatedIocs: [],
  sourceScreenshots: [],
  mitreTechniques: [],
  firstSeen: T(1),
  lastUpdated: T(1),
  status: "open",
  ...p,
});

const BASE_IOCS: IOC[] = [
  ioc({ id: "i-ip", type: "ip", value: IP }),
  ioc({ id: "i-sha", type: "hash", value: SHA }),
  ioc({ id: "i-path", type: "file", value: PATH }),
  // The authoritative link points at a super row that does not exist yet (step 3 appends it).
  ioc({ id: "i-dom", type: "domain", value: DOMAIN, extractedFrom: ["s-auth", "s-missing"] }),
];
// Compact row builder: id, severity, timestamp, description, then any structured fields.
const row = (
  id: string,
  severity: ForensicEvent["severity"],
  timestamp: string,
  description: string,
  extra: Partial<ForensicEvent> = {},
): ForensicEvent => ev({ id, severity, timestamp, description, ...extra });

const BASE_FORENSIC: ForensicEvent[] = [
  row("f1", "High", T(1), `outbound connect to ${IP} from WS-01`),
  row("f2", "Info", T(1, 1), "hash observed on disk", { sha256: SHA.toLowerCase() }),
  row("f3", "Low", T(1, 2), "dropper written", { path: PATH }),
  row("f4", "Medium", T(1, 3), "scheduled task created"),
];
const FINDINGS: Finding[] = [finding({ id: "fd1", relatedIocs: ["i-ip", "i-dom"] })];

function stateWith(iocs: readonly IOC[], forensicTimeline: readonly ForensicEvent[]): InvestigationState {
  return {
    ...emptyState(CASE),
    iocs: [...iocs],
    findings: FINDINGS,
    forensicTimeline: [...forensicTimeline],
  };
}

// 15 noise rows: a path field no IOC names, and a description whose only IP token is IP_LONGER.
const NOISE: ForensicEvent[] = Array.from({ length: 15 }, (_, i) =>
  row(`n${i}`, "Info", T(10 + i), `file observed f${i}.dll beside ${IP_LONGER}`, {
    path: `C:\\Windows\\f${i}.dll`,
  }),
);
const SUPER_A: ForensicEvent[] = [
  row("s1", "Info", T(2), `Second Sighting Of ${IP} By The Proxy`),
  row("s2", "Low", T(3), `dns query ${DOMAIN.toUpperCase()} resolved`, { asset: "WS-01" }),
  row("s3", "Info", T(4), "hash row, upper-cased field", { sha256: SHA }),
  row("s-auth", "Info", T(5), "an authoritative link whose text never names the value"),
  row("s6", "Info", T(6), "md5 row", { md5: MD5 }),
  row("s7", "Medium", T(7), `${IP} seen by the firewall`),
  row("s8", "Info", "", `undated row naming ${IP}`),
  row("s9", "Info", T(8), "path as a lower-cased field", { path: PATH.toLowerCase() }),
  row("s10", "Info", T(9), "svchost.exe started"),
  row("s11", "Info", T(9, 1), "lsass.exe accessed"),
];
const SUPER_B: ForensicEvent[] = [
  // Duplicate BY ID: dropped. Its High grade must not leak into i-ip's rank through the index.
  row("s1", "High", T(2), `re-import of ${IP} under the same id`),
  // Duplicate BY CONTENT (timestamp + description + host): dropped, same trap for i-dom.
  row("s2-dup", "High", T(3), `dns query ${DOMAIN.toUpperCase()} resolved`, { asset: "WS-01" }),
  ...NOISE.slice(0, 8),
];
const SUPER_C: ForensicEvent[] = [
  ...NOISE.slice(8),
  row("s12", "Info", T(25), "explorer.exe started"),
  row("s13", "Info", T(25, 1), "winlogon.exe started"),
  row("s14", "Info", T(25, 2), "services.exe started"),
];
// Step 4: two IOCs whose values ALREADY sit in super rows (n* descriptions, s6's md5 field).
const LATE_IOCS: IOC[] = [
  ioc({ id: "i-ip2", type: "ip", value: IP_LONGER }),
  ioc({ id: "i-md5", type: "hash", value: MD5 }),
];

let cases: CaseStore;
let stateStore: StateStore;
let superStore: SuperTimelineStore;
let dbPath: string;

interface Answers {
  provenance: Record<string, IocProvenance>;
  chains: Record<string, IocProvenanceChain>;
}

async function referenceAnswers(caseId: string): Promise<Answers & { superRows: number }> {
  const state = await stateStore.load(caseId);
  const superRows: ForensicEvent[] = [];
  for await (const batch of superStore.eventBatches(caseId)) superRows.push(...batch);
  const events = [...state.forensicTimeline, ...superRows];
  return {
    provenance: deriveIocProvenance(state.iocs, events),
    chains: buildIocProvenanceChains(state.iocs, events, state.findings),
    superRows: superRows.length,
  };
}

// A fresh reader per call (no coalescing across steps) and a spy on the store method the indexed
// path must go through, so a reader that silently fell back to streaming cannot pass.
async function indexedAnswers(caseId: string): Promise<Answers & { candidateCalls: number }> {
  const indexed = stateStore;
  expect(typeof indexed.iocProvenanceCandidates).toBe("function");
  const original = indexed.iocProvenanceCandidates;
  let candidateCalls = 0;
  indexed.iocProvenanceCandidates = (id, keys, ids) => {
    candidateCalls++;
    return original.call(indexed, id, keys, ids);
  };
  try {
    const reads = createIocProvenanceReads({ stateStore, superTimelineStore: superStore });
    const provenance = await reads.provenance(caseId);
    const chains = await reads.chains(caseId);
    return { provenance, chains, candidateCalls };
  } finally {
    indexed.iocProvenanceCandidates = original;
  }
}

async function expectIndexedEqualsStreamed(caseId: string): Promise<Answers & { superRows: number }> {
  const reference = await referenceAnswers(caseId);
  const indexed = await indexedAnswers(caseId);
  // A case with no IOCs may legitimately skip the lookup; with IOCs the indexed path MUST be taken.
  if (Object.keys(reference.provenance).length > 0) expect(indexed.candidateCalls).toBeGreaterThanOrEqual(1);
  expect(indexed.provenance).toEqual(reference.provenance);
  expect(indexed.chains).toEqual(reference.chains);
  return reference;
}

const extractionIds = (chain: IocProvenanceChain): string[] => chain.extraction.map((e) => e.eventId);

describe("IOC provenance: indexed read equals the streaming reference (PLAN-1452)", () => {
  beforeAll(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-ioc-index-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
    stateStore = new StateStore(cases);
    superStore = new SuperTimelineStore(cases, 100_000);
    dbPath = join(cases.stateDir(CASE), INVESTIGATION_DB_FILENAME);
  });

  it("1. an empty case answers empty on both paths", async () => {
    const r = await expectIndexedEqualsStreamed(CASE);
    expect(r.provenance).toEqual({});
    expect(r.chains).toEqual({});
  });

  it("2. forensic rows saved with the IOCs: token, structured-field and path-with-spaces matches", async () => {
    await stateStore.save(stateWith(BASE_IOCS, BASE_FORENSIC));
    const r = await expectIndexedEqualsStreamed(CASE);
    expect(r.provenance).toEqual({
      "i-ip": "detection",
      "i-sha": "telemetry",
      "i-path": "detection",
      "i-dom": "telemetry",
    });
    expect(extractionIds(r.chains["i-path"])).toEqual(["f3"]);
    expect(r.chains["i-dom"].extractionAuthoritative).toBe(false); // s-auth is not there yet
  });

  it("3. three super batches with id and content collisions, an authoritative link, and substring noise", async () => {
    await superStore.append(CASE, SUPER_A);
    await expectIndexedEqualsStreamed(CASE);
    await superStore.append(CASE, SUPER_B);
    await expectIndexedEqualsStreamed(CASE);
    await superStore.append(CASE, SUPER_C);
    const r = await expectIndexedEqualsStreamed(CASE);
    expect(r.superRows).toBe(28); // 30 appended, the two duplicates dropped
    // Sorted by timestamp string: the undated s8 ("") sorts first. Never a noise row.
    expect(extractionIds(r.chains["i-ip"])).toEqual(["s8", "f1", "s1", "s7"]);
    expect(r.chains["i-dom"].extractionAuthoritative).toBe(true);
    expect(extractionIds(r.chains["i-dom"])).toEqual(["s-auth"]);
    expect(r.chains["i-dom"].extraction[0].valueHidden).toBe(true);
    expect(extractionIds(r.chains["i-sha"])).toEqual(["f2", "s3"]);
    expect(extractionIds(r.chains["i-path"])).toEqual(["f3", "s9"]);
  });

  it("4. an IOC added AFTER its events is found with no rebuild", async () => {
    await stateStore.save(stateWith([...BASE_IOCS, ...LATE_IOCS], BASE_FORENSIC));
    const r = await expectIndexedEqualsStreamed(CASE);
    expect(extractionIds(r.chains["i-ip2"])).toEqual(NOISE.map((e) => e.id));
    expect(extractionIds(r.chains["i-md5"])).toEqual(["s6"]);
  });

  it("5. a tagger re-grade (Info → High on f2) moves i-sha to detection", async () => {
    const regraded = BASE_FORENSIC.map((e) => (e.id === "f2" ? { ...e, severity: "High" as const } : e));
    await stateStore.save(stateWith([...BASE_IOCS, ...LATE_IOCS], regraded));
    const r = await expectIndexedEqualsStreamed(CASE);
    expect(r.provenance["i-sha"]).toBe("detection");
  });

  it("6. an undo (f3 removed, shorter array) drops the path match to its Info super row", async () => {
    const undone = BASE_FORENSIC.filter((e) => e.id !== "f3").map((e) =>
      e.id === "f2" ? { ...e, severity: "High" as const } : e,
    );
    await stateStore.save(stateWith([...BASE_IOCS, ...LATE_IOCS], undone));
    const r = await expectIndexedEqualsStreamed(CASE);
    expect(r.provenance["i-path"]).toBe("telemetry");
    expect(extractionIds(r.chains["i-path"])).toEqual(["s9"]);
  });

  it("7. an update (f1's description no longer names the ip) re-indexes the row in place", async () => {
    const updated = BASE_FORENSIC.filter((e) => e.id !== "f3").map((e) => {
      if (e.id === "f2") return { ...e, severity: "High" as const };
      if (e.id === "f1") return { ...e, description: "outbound connect from WS-01 (address redacted)" };
      return e;
    });
    await stateStore.save(stateWith([...BASE_IOCS, ...LATE_IOCS], updated));
    const r = await expectIndexedEqualsStreamed(CASE);
    expect(extractionIds(r.chains["i-ip"])).toEqual(["s8", "s1", "s7"]);
  });

  it("8. cap eviction (max 12) drops the oldest-imported rows out of both answers", async () => {
    const small = new SuperTimelineStore(cases, 12);
    await small.append(CASE, [
      row("x1", "Info", T(26), "late row one"),
      row("x2", "Info", T(27), "late row two"),
      row("x3", "Info", T(28), "late row three"),
    ]);
    const r = await expectIndexedEqualsStreamed(CASE);
    expect(r.superRows).toBe(12);
    expect(r.provenance["i-ip"]).toBe("telemetry"); // s1, s7, s8 evicted; f1 no longer names it
    expect(extractionIds(r.chains["i-ip"])).toEqual([]);
    expect(r.chains["i-dom"].extractionAuthoritative).toBe(false); // s-auth evicted
    expect(extractionIds(r.chains["i-ip2"])).toEqual(NOISE.slice(9).map((e) => e.id));
  });

  it("9. prune-by-time deletes through the same trigger", async () => {
    // StateStore exposes no prune method; the worker op is the store's own prune path (it is what
    // authObservationStore drives), so the trigger's third DELETE path is covered from here.
    const deleted = await caseSqliteWorker.request<number>({
      op: "pruneEntitiesBefore",
      dbPath,
      kind: "superTimeline",
      beforeMs: Date.parse(T(22)),
    });
    expect(deleted).toBe(3); // n9 (T19), n10 (T20), n11 (T21); n12 at T22 stays
    const r = await expectIndexedEqualsStreamed(CASE);
    expect(r.superRows).toBe(9);
    expect(extractionIds(r.chains["i-ip2"])).toEqual(NOISE.slice(12).map((e) => e.id));
  });

  it("10. a legacy database (no event_terms, no version stamp) is backfilled on the first read", async () => {
    const DatabaseSync = loadDatabaseSync();
    const db = new DatabaseSync(dbPath);
    db.exec(
      "DROP TRIGGER IF EXISTS entities_terms_delete; DROP TABLE IF EXISTS event_terms; " +
        "DELETE FROM storage_meta WHERE key='event_terms_version';",
    );
    db.close();
    const r = await expectIndexedEqualsStreamed(CASE);
    // Equality alone could hold on an empty index only if nothing matched — pin that it did.
    expect(extractionIds(r.chains["i-ip2"])).toEqual(NOISE.slice(12).map((e) => e.id));
    const check = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const row = check.prepare("SELECT value FROM storage_meta WHERE key='event_terms_version'").get();
      expect(row).toBeDefined();
    } finally {
      check.close();
    }
  });
});

// PLAN-1452 "What this fixes vs leaves alone", known divergence: an IOC value made only of separator
// characters. The builders compare structured fields by trimmed-lowercased string equality, so a row
// whose `path` is literally "***" matches the IOC "***" on the reference path. FTS tokenizes "***"
// to nothing, so the indexed path never fetches that row. Values that short are not IOCs in practice
// (both builders already skip anything under three characters); this test documents the gap so a
// future change that closes it, or widens it, is a deliberate one.
describe("IOC provenance: the separator-only divergence is documented, not hidden", () => {
  it("differs ONLY for the separator-only IOC", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-ioc-index-sep-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
    stateStore = new StateStore(cases);
    superStore = new SuperTimelineStore(cases, 100_000);
    await stateStore.save(
      stateWith(
        [ioc({ id: "i-sep", type: "other", value: "***" }), ioc({ id: "i-ip", type: "ip", value: IP })],
        [
          ev({
            id: "f-sep",
            severity: "High",
            description: "a row whose only IOC-shaped field is its path",
            path: "***",
          }),
          ev({ id: "f-ip", severity: "High", description: `beacon to ${IP}` }),
        ],
      ),
    );
    const reference = await referenceAnswers(CASE);
    const indexed = await indexedAnswers(CASE);
    expect(indexed.candidateCalls).toBeGreaterThanOrEqual(1);

    const omitSep = <T>(record: Record<string, T>): Record<string, T> =>
      Object.fromEntries(Object.entries(record).filter(([id]) => id !== "i-sep"));
    expect(omitSep(indexed.provenance)).toEqual(omitSep(reference.provenance));
    expect(omitSep(indexed.chains)).toEqual(omitSep(reference.chains));

    expect(reference.provenance["i-sep"]).toBe("detection");
    expect(extractionIds(reference.chains["i-sep"])).toEqual(["f-sep"]);
    expect(indexed.provenance["i-sep"]).toBe("telemetry");
    expect(extractionIds(indexed.chains["i-sep"])).toEqual([]);
  });
});
