import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, readFile, writeFile, copyFile, rename } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, basename, dirname } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { ScopeStore } from "../../src/analysis/scope.js";
import { FalsePositiveStore } from "../../src/analysis/falsePositive.js";
import { ClockSkewStore } from "../../src/analysis/clockSkewStore.js";
import { FindingOutcomeStore } from "../../src/analysis/findingOutcome.js";
import { RemediationStore } from "../../src/analysis/remediationBoundary.js";
import { ServedLocationStore } from "../../src/analysis/servedLocation.js";
import { SensitiveLocationStore } from "../../src/analysis/sensitiveLocation.js";
import { FILTERED_STATE_SIDE_FILES } from "../../src/reports/filteredState.js";
import { ReportLiteCache, caseReadRevision, REPORT_LITE_IDLE_MS } from "../../src/reports/reportLiteCache.js";
import { CaseLoadCoalescer } from "../../src/reports/stateLoadGate.js";
import { LoadLimiter } from "../../src/analysis/wholeCaseLoadLimit.js";
import { emptyState, type ForensicEvent, type InvestigationState } from "../../src/analysis/stateTypes.js";

// #2057: the five report-lite surfaces (timeline gaps, swimlane, IOC blocklist, STIX, interactive
// report) keep the filtered slim state of the case being viewed, keyed on an exact revision of every
// input the filter reads. A report must NEVER be served from a state older than any write to the
// case: these tests pin that every write — database, side file, delete/re-create, file replacement,
// or one racing the load — makes the next request read the case again.

let root: string;
let caseStore: CaseStore;
let stateStore: StateStore;
let writer: ReportWriter;

const event = (id: string, timestamp: string): ForensicEvent => ({
  id,
  timestamp,
  description: `event ${id} on HOST-1`,
  severity: "High",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  asset: "HOST-1",
});

async function seed(ids: string[], caseId = "c1"): Promise<void> {
  const state = emptyState(caseId);
  ids.forEach((id, i) => state.forensicTimeline.push(event(id, `2026-06-01T1${i}:00:00Z`)));
  state.iocs.push({
    id: "ioc-1",
    type: "ip",
    value: "198.51.100.7",
    firstSeen: "2026-06-01T10:00:00Z",
    sources: [],
  } as unknown as InvestigationState["iocs"][number]);
  await stateStore.save(state);
}

const liteIds = async (caseId = "c1"): Promise<string[]> =>
  (await writer.filteredState(caseId, true)).forensicTimeline.map((e) => e.id);

const revision = (caseId = "c1") => caseReadRevision(caseStore, stateStore.databasePath(caseId), caseId);

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-litecache-"));
  caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  stateStore = new StateStore(caseStore);
  writer = new ReportWriter(caseStore, stateStore, {
    scope: new ScopeStore(caseStore),
    falsePositives: new FalsePositiveStore(caseStore),
    clockSkew: new ClockSkewStore(caseStore),
  });
  await seed(["a", "b"]);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("report-lite cache (#2057)", () => {
  it("1. a second sequential request reuses the filtered state and answers identically", async () => {
    const load = vi.spyOn(stateStore, "load");
    const first = await writer.timelineGaps("c1");
    const second = await writer.timelineGaps("c1");
    expect(second).toEqual(first);
    expect(await writer.swimlane("c1")).toEqual(await writer.swimlane("c1"));
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("2. a database write makes the next request reload and show it", async () => {
    expect(await liteIds()).toEqual(["a", "b"]);
    const load = vi.spyOn(stateStore, "load");
    await seed(["a", "b", "c"]);
    expect(await liteIds()).toEqual(["a", "b", "c"]);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("3a. every side store the filter reads is covered by the revision", async () => {
    // Which stores does loadFilteredState read? Scanned from its source, so a new side input that
    // is not added to FILTERED_STATE_SIDE_FILES (and to this table) fails here.
    const src = await readFile(new URL("../../src/reports/filteredState.ts", import.meta.url), "utf8");
    const body = src.slice(src.indexOf("export async function loadFilteredState"));
    const read = new Set<string>([
      ...[...body.matchAll(/src\.(\w+)\b/g)].map((m) => m[1]),
      ...[...body.matchAll(/new (\w+Store)\(/g)].map((m) => m[1]),
    ]);
    const priv = (store: unknown, method: string, caseId: string): string =>
      (store as Record<string, (id: string) => string>)[method](caseId);
    const table: Record<string, string[]> = {
      state: [], // the database itself: covered by the pool's write sequence and the file identity
      cases: [], // the store handle the side stores below are built from
      clockSkew: [priv(new ClockSkewStore(caseStore), "path", "c1")],
      scope: [priv(new ScopeStore(caseStore), "path", "c1")],
      falsePositives: [
        priv(new FalsePositiveStore(caseStore), "path", "c1"),
        priv(new FalsePositiveStore(caseStore), "legacyPath", "c1"),
      ],
      FindingOutcomeStore: [priv(new FindingOutcomeStore(caseStore), "path", "c1")],
      RemediationStore: [priv(new RemediationStore(caseStore), "path", "c1")],
      ServedLocationStore: [priv(new ServedLocationStore(caseStore), "path", "c1")],
      SensitiveLocationStore: [priv(new SensitiveLocationStore(caseStore), "path", "c1")],
    };
    expect([...read].sort()).toEqual(Object.keys(table).sort());
    const files = Object.values(table).flat();
    expect(files.map((p) => basename(p)).sort()).toEqual([...FILTERED_STATE_SIDE_FILES].sort());
    for (const path of files) {
      expect(dirname(path)).toBe(caseStore.stateDir("c1"));
      const before = await revision();
      expect(before).not.toBeNull();
      await writeFile(path, "[]");
      const created = await revision();
      expect(created, path).not.toBe(before);
      await writeFile(path, "[ ]"); // an in-place rewrite, not only a rename, changes it too
      expect(await revision(), path).not.toBe(created);
    }
  });

  it("3b. a scope edit and a false-positive mark each reach the next request", async () => {
    expect(await liteIds()).toEqual(["a", "b"]);
    await new ScopeStore(caseStore).save("c1", {
      start: "2026-06-01T10:30:00Z",
      end: "2026-06-01T23:00:00Z",
    });
    expect(await liteIds()).toEqual(["b"]);
    await new ScopeStore(caseStore).save("c1", { start: "", end: "" });
    expect(await liteIds()).toEqual(["a", "b"]);
    await new FalsePositiveStore(caseStore).save("c1", [
      { id: "event:a", kind: "event", ref: "a", reason: "benign", markedAt: "2026-06-02T00:00:00Z" },
    ] as never);
    expect(await liteIds()).toEqual(["b"]);
  });

  it("4. a write that lands while a miss is loading is never cached", async () => {
    const original = stateStore.load.bind(stateStore);
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    let readDone!: () => void;
    const read = new Promise<void>((r) => (readDone = r));
    vi.spyOn(stateStore, "load").mockImplementationOnce(async (caseId, opts) => {
      const before = await original(caseId, opts);
      readDone();
      await held;
      return before;
    });
    const early = liteIds();
    await read;
    await seed(["a", "b", "c"]);
    release();
    expect(await early).toEqual(["a", "b"]); // that caller asked before the write finished
    expect(await liteIds()).toEqual(["a", "b", "c"]);
  });

  it("5a. a deleted case re-created with the same id is a miss", async () => {
    expect(await liteIds()).toEqual(["a", "b"]);
    await caseStore.deleteCaseFolder("c1");
    await caseStore.createCase({ caseId: "c1", name: "n2", investigator: "i", aiProvider: null });
    await seed(["x"]);
    expect(await liteIds()).toEqual(["x"]);
  });

  it("5b. a database file replaced outside the pool (a restore or unarchive) is a miss", async () => {
    await seed(["r1"], "c1");
    const backup = join(root, "backup.sqlite");
    await copyFile(stateStore.databasePath("c1"), backup);
    await seed(["a", "b"]);
    expect(await liteIds()).toEqual(["a", "b"]);
    const before = await revision();
    await rename(backup, stateStore.databasePath("c1"));
    expect(await revision()).not.toBe(before);
  });

  it("6. clock-dependent output stays live across cache hits", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-07-01T00:00:00Z"));
    const load = vi.spyOn(stateStore, "load");
    const first = await writer.iocBlocklist("c1", "txt");
    vi.setSystemTime(new Date("2026-08-01T00:00:00Z"));
    const second = await writer.iocBlocklist("c1", "txt");
    expect(load).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(second)).toContain("2026-08-01");
    expect(JSON.stringify(first)).not.toContain("2026-08-01");
  });

  it("7a. a case with no database yet (legacy JSON) has no revision and is never cached", async () => {
    await caseStore.createCase({ caseId: "legacy", name: "n", investigator: "i", aiProvider: null });
    expect(await caseReadRevision(caseStore, stateStore.databasePath("legacy"), "legacy")).toBeNull();
  });
});

describe("ReportLiteCache bounds (#2057)", () => {
  const coalescer = () => new CaseLoadCoalescer<string>(new LoadLimiter(2));

  it("7b. holds at most one case", async () => {
    const cache = new ReportLiteCache<string>(async (id) => `rev-${id}`, coalescer());
    expect(await cache.load("c1", async () => "s1")).toBe("s1");
    expect(await cache.load("c2", async () => "s2")).toBe("s2");
    expect(cache.size).toBe(1);
    const read = vi.fn(async () => "s2-again");
    expect(await cache.load("c2", read)).toBe("s2");
    expect(read).not.toHaveBeenCalled();
  });

  it("7c. evicts after the idle period", async () => {
    vi.useFakeTimers();
    const cache = new ReportLiteCache<string>(async () => "rev", coalescer());
    await cache.load("c1", async () => "s1");
    expect(cache.size).toBe(1);
    vi.advanceTimersByTime(REPORT_LITE_IDLE_MS + 1);
    expect(cache.size).toBe(0);
  });

  it("7d. a null or failing revision bypasses the cache", async () => {
    const nullRev = new ReportLiteCache<string>(async () => null, coalescer());
    await nullRev.load("c1", async () => "s1");
    expect(nullRev.size).toBe(0);
    const failing = new ReportLiteCache<string>(async () => {
      throw new Error("stat failed");
    }, coalescer());
    expect(await failing.load("c1", async () => "s1")).toBe("s1");
    expect(failing.size).toBe(0);
  });

  it("7e. a revision that changed during the load is not stored", async () => {
    let rev = 0;
    const cache = new ReportLiteCache<string>(async () => `r${rev}`, coalescer());
    await cache.load("c1", async () => {
      rev++;
      return "s1";
    });
    expect(cache.size).toBe(0);
  });

  it("7g. concurrent misses share a load only at the same revision", async () => {
    let rev = "r1";
    const cache = new ReportLiteCache<string>(async () => rev, coalescer());
    let reads = 0;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    const read = async () => {
      reads++;
      await held;
      return `s${reads}`;
    };
    const a = cache.load("c1", read);
    const b = cache.load("c1", read);
    await new Promise((r) => setImmediate(r));
    expect(reads).toBe(1);
    rev = "r2"; // a write lands: a later arrival must not join the earlier load
    const c = cache.load("c1", read);
    await new Promise((r) => setImmediate(r));
    release();
    expect(await a).toBe(await b);
    expect(await c).not.toBe(await a);
    expect(reads).toBe(2);
  });

  it("7f. a failed load stores nothing", async () => {
    const cache = new ReportLiteCache<string>(async () => "rev", coalescer());
    await expect(cache.load("c1", async () => Promise.reject(new Error("disk")))).rejects.toThrow("disk");
    expect(cache.size).toBe(0);
  });
});

// #1915 (reopened): a caller whose client went away stops waiting on a shared miss, but the miss
// still loads, is cached, and reaches every caller that stayed.
describe("ReportLiteCache abort (#1915)", () => {
  const flush = () => new Promise((r) => setImmediate(r));

  it("one caller aborting a shared miss leaves it running; the result is still cached", async () => {
    const cache = new ReportLiteCache<string>(
      async () => "rev",
      new CaseLoadCoalescer<string>(new LoadLimiter(2)),
    );
    let reads = 0;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    const read = async () => {
      reads++;
      await held;
      return "state";
    };
    const gone = new AbortController();
    const a = cache.load("c1", read, gone.signal);
    const b = cache.load("c1", read, new AbortController().signal);
    await flush();
    gone.abort();
    await expect(a).rejects.toMatchObject({ name: "AbortError" });
    release();
    expect(await b).toBe("state");
    expect(reads).toBe(1);
    expect(cache.size).toBe(1);
    expect(await cache.load("c1", read)).toBe("state"); // a hit
    expect(reads).toBe(1);
  });

  it("a miss every caller left while it was queued never reads the case", async () => {
    const limiter = new LoadLimiter(1);
    const cache = new ReportLiteCache<string>(async () => "rev", new CaseLoadCoalescer<string>(limiter));
    let releaseHolder!: () => void;
    const holder = limiter.run(() => new Promise<void>((r) => (releaseHolder = r)));
    let reads = 0;
    const read = async () => {
      reads++;
      return "state";
    };
    const one = new AbortController();
    const two = new AbortController();
    const a = cache.load("c1", read, one.signal);
    const b = cache.load("c1", read, two.signal);
    await flush();
    one.abort();
    two.abort();
    await expect(a).rejects.toMatchObject({ name: "AbortError" });
    await expect(b).rejects.toMatchObject({ name: "AbortError" });
    releaseHolder();
    await holder;
    await flush();
    expect(reads).toBe(0);
    expect(limiter.waiting).toBe(0);
    expect(await cache.load("c1", read)).toBe("state"); // a newcomer gets a fresh load
    expect(reads).toBe(1);
  });
});
