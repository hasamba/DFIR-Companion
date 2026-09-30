import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore, INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { emptyState, type IOC } from "../../src/analysis/stateTypes.js";
import {
  baselineEntities,
  baselineEntityIds,
  captureImportBaseline,
  releaseImportBaseline,
} from "../../src/analysis/importBaseline.js";
import { settleIocsDiff } from "../../src/routes/importSettleDiff.js";
import { baselineCheckpoint } from "../../src/analysis/importUndoRows.js";
import { applyUndoDelta, computeUndoDelta } from "../../src/analysis/importUndoDelta.js";
import { diffIocs } from "../../src/analysis/iocsDiff.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";

// #1874: an import no longer reads the whole IOC list three times. The settle's IOC diff and the undo
// checkpoint are computed from the IOC journal (the images of the IOC rows the import wrote or
// deleted) and the IOC ids in order. These tests drive random IOC changes through the real case
// database and require the results to equal the old whole-list algorithms exactly.

let root: string;
let cases: CaseStore;
let store: StateStore;
let C = "c1";

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-ioc-journal-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  store = new StateStore(cases);
  C = "c1";
});

// A fresh case per random run (deleting a live database file under its WAL is not a reset).
async function freshCase(seed: number): Promise<void> {
  C = `s${seed}`;
  await cases.createCase({ caseId: C, name: "n", investigator: "i", aiProvider: "mock" });
}

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

// A small deterministic PRNG so a failing seed can be replayed.
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

const VALUES = [
  "evil.example.com",
  "EVIL.example.com",
  "10.0.0.1",
  "c:\\temp\\a.exe",
  "Ünïcode.example",
  "",
  "x",
];
const TYPES = ["domain", "ip", "file"] as const;

type Opts = { weirdIds?: boolean; weirdValues?: boolean; objects?: boolean };

function randomIoc(r: () => number, n: number, o: Opts): IOC {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
  let value: unknown = r() < 0.5 ? pick(VALUES) : `v${Math.floor(r() * 12)}`;
  if (o.weirdValues && r() < 0.15) value = pick([7, 0, true, null, 7.5]);
  if (o.objects && r() < 0.1) value = { nested: "x" };
  const ioc: Record<string, unknown> = { id: `i${String(n).padStart(3, "0")}`, type: pick(TYPES), value };
  if (o.weirdIds && r() < 0.15) ioc.id = pick(["", undefined, 5, "i001", "dup"]);
  if (ioc.id === undefined) delete ioc.id;
  if (r() < 0.3) ioc.note = `n${Math.floor(r() * 3)}`;
  return ioc as unknown as IOC;
}

// Mutate a list the ways an import and the writers around it do: append, edit value/type, delete,
// move, re-add a removed id.
function mutate(r: () => number, list: IOC[], next: () => number, o: Opts): IOC[] {
  const out = [...list];
  const steps = 1 + Math.floor(r() * 6);
  for (let k = 0; k < steps; k++) {
    const roll = r();
    const i = Math.floor(r() * Math.max(out.length, 1));
    if (roll < 0.35 || !out.length) out.push(randomIoc(r, next(), o));
    else if (roll < 0.55) out[i] = { ...out[i], value: randomIoc(r, 0, o).value };
    else if (roll < 0.65) out[i] = { ...out[i], type: "other" };
    else if (roll < 0.8) out.splice(i, 1);
    else if (roll < 0.9) out.splice(Math.floor(r() * out.length), 0, ...out.splice(i, 1));
    else out.splice(i, 0, randomIoc(r, next(), o));
  }
  return out;
}

async function save(iocs: IOC[]): Promise<void> {
  const s = await store.load(C);
  await store.save({ ...s, iocs });
}

async function roundTrip(seed: number, o: Opts): Promise<void> {
  const r = rng(seed);
  let n = 0;
  const next = () => ++n;
  const initial = Array.from({ length: Math.floor(r() * 8) }, () => randomIoc(r, next(), o));
  if (initial.length || r() < 0.7) await store.save({ ...emptyState(C), iocs: initial });
  const before = await store.load(C);
  const baseline = await captureImportBaseline(store, C);
  try {
    // One or two writes inside the section: a shrink then a grow reuses row ids.
    let list = mutate(r, before.iocs, next, o);
    await save(list);
    if (r() < 0.5) {
      list = mutate(r, list, next, o);
      await save(list);
    }
    const after = await store.load(C);
    expect(await settleIocsDiff(store, C, baseline), `diff seed ${seed}`).toEqual(
      diffIocs(before.iocs, after.iocs),
    );
    const checkpoint = await baselineCheckpoint(store, baseline, "label", "at");
    expect(checkpoint?.delta, `delta seed ${seed}`).toEqual(computeUndoDelta(before, after));
    expect(applyUndoDelta(after, checkpoint!.delta!), `undo seed ${seed}`).toEqual(before);
    expect(checkpoint!.counts?.iocs).toBe(before.iocs.length);
    expect(baselineEntityIds(baseline)).toEqual(before.iocs.map((i) => i.id));
    // #1887: the import receipt's before and after entity lists (no forensic rows here)
    expect(baselineEntities(baseline)).toEqual(before.iocs.map((i) => i.id));
    expect((await store.iocJournal.outline(C))?.ids ?? [], `outline seed ${seed}`).toEqual(
      after.iocs.map((i) => i.id),
    );
  } finally {
    await releaseImportBaseline(store, baseline);
  }
}

describe("IOC journal: diff and undo equal the whole-list algorithms (#1874)", () => {
  it("string values, unique ids", async () => {
    for (let seed = 1; seed <= 60; seed++) {
      await rm(join(cases.stateDir(C), INVESTIGATION_DB_FILENAME), { force: true });
      await roundTrip(seed, {});
    }
  });

  it("non-string values, missing / empty / duplicate / numeric ids", async () => {
    for (let seed = 100; seed <= 160; seed++) {
      await rm(join(cases.stateDir(C), INVESTIGATION_DB_FILENAME), { force: true });
      await roundTrip(seed, { weirdIds: true, weirdValues: true });
    }
  });

  it("an object value anywhere takes the whole lists", async () => {
    for (let seed = 200; seed <= 230; seed++) {
      await rm(join(cases.stateDir(C), INVESTIGATION_DB_FILENAME), { force: true });
      await roundTrip(seed, { objects: true, weirdValues: true });
    }
  });

  it("an untouched object-valued IOC is still reported as the old diff did", async () => {
    await store.save({
      ...emptyState(C),
      iocs: [{ id: "i001", type: "x", value: { a: 1 } } as unknown as IOC],
    });
    const before = await store.load(C);
    const baseline = await captureImportBaseline(store, C);
    await save([...before.iocs, { id: "i002", type: "ip", value: "1.2.3.4" } as IOC]);
    const after = await store.load(C);
    const diff = await settleIocsDiff(store, C, baseline);
    expect(diff).toEqual(diffIocs(before.iocs, after.iocs));
    expect(diff.removed).toHaveLength(1); // identity: the old diff never matched it to itself
    await releaseImportBaseline(store, baseline);
  });

  it("the capture holds no IOC list and the settle reads only touched IOC rows", async () => {
    const iocs = Array.from({ length: 50 }, (_, i) => ({
      id: `i${i + 1}`,
      type: "ip",
      value: `10.0.0.${i}`,
    }));
    await store.save({ ...emptyState(C), iocs: iocs as IOC[] });
    const baseline = await captureImportBaseline(store, C);
    expect(baseline.overview.iocs).toEqual([]);
    expect(baseline.iocOutline?.ids).toEqual(iocs.map((i) => i.id));
    await save([...(iocs as IOC[]), { id: "i51", type: "ip", value: "10.0.0.3" } as IOC]);
    const got = await store.iocJournal.diffInputs({
      caseId: C,
      token: baseline.journalToken,
      fence: baseline.journalFence,
      before: baseline.iocOutline!,
    });
    expect(got?.current.map((r) => r.payload.id)).toEqual(["i51"]);
    expect(got?.images).toEqual([]);
    expect(got?.holders).toEqual(["10.0.0.3"]); // the untouched i4 holds the value
    expect(await settleIocsDiff(store, C, baseline)).toEqual({ added: [], removed: [] });
    await releaseImportBaseline(store, baseline);
  });

  it("a lost journal fails the diff instead of reporting a partial one", async () => {
    await store.save({ ...emptyState(C), iocs: [{ id: "i1", type: "ip", value: "1.1.1.1" } as IOC] });
    const baseline = await captureImportBaseline(store, C);
    await releaseImportBaseline(store, baseline);
    await expect(settleIocsDiff(store, C, baseline)).rejects.toThrow(/journal/);
    expect(await baselineCheckpoint(store, baseline, "l", "a")).toBeNull();
  });
});

// The candidate query before #1874, kept here as the oracle.
function oldCandidates(dbPath: string, lowered: string[], aliasIds: string[]) {
  const db = new (loadDatabaseSync())(dbPath);
  try {
    const rows = db
      .prepare(
        "SELECT row_id, ordinal, version, payload FROM entities WHERE kind='iocs' AND (" +
          "json_extract(payload, '$.id') IN (SELECT value FROM json_each(?)) OR " +
          "lower(json_extract(payload, '$.value')) IN (SELECT value FROM json_each(?)) OR " +
          "json_type(payload, '$.value') IS NOT 'text' OR json_extract(payload, '$.value') GLOB '*[^ -~]*'" +
          ") ORDER BY ordinal",
      )
      .all(JSON.stringify(aliasIds), JSON.stringify(lowered)) as {
      row_id: number;
      ordinal: number;
      version: number;
      payload: string;
    }[];
    let max = 0;
    for (const row of db
      .prepare("SELECT json_extract(payload, '$.id') AS id FROM entities WHERE kind='iocs'")
      .all() as {
      id: unknown;
    }[]) {
      const m = /^i(\d+)$/.exec(row.id as string);
      if (m) max = Math.max(max, parseInt(m[1], 10));
    }
    return {
      rows: rows.map((r) => ({
        rowId: Number(r.row_id),
        ordinal: Number(r.ordinal),
        version: Number(r.version),
        payload: r.payload,
      })),
      nextSeq: max + 1,
    };
  } finally {
    db.close();
  }
}

describe("merge IOC candidates read indexes, not every IOC (#1874)", () => {
  it("returns exactly the old query's rows, order and next sequence", async () => {
    for (let seed = 1; seed <= 40; seed++) {
      await freshCase(seed);
      const dbPath = join(cases.stateDir(C), INVESTIGATION_DB_FILENAME);
      const r = rng(seed);
      let n = 0;
      const iocs = Array.from({ length: 1 + Math.floor(r() * 25) }, () =>
        randomIoc(r, ++n, { weirdIds: true, weirdValues: true, objects: true }),
      );
      if (r() < 0.2) iocs.push({ id: "i0000099", type: "other", value: "i1000" } as IOC); // leading zeros
      if (r() < 0.2) iocs.push({ type: "x", value: "i9999" } as unknown as IOC); // entity_id from the value
      if (r() < 0.1) iocs.push({ id: "i99999999999999999999", type: "other", value: "big" } as IOC);
      await store.save({ ...emptyState(C), iocs });
      const lowered = [...new Set(iocs.map((i) => String(i.value).toLowerCase()))].filter(() => r() < 0.4);
      const aliasIds = ["i001", "dup", "", "i0000099", "zz"].filter(() => r() < 0.5);
      const got = await store.mergeIocCandidates(C, lowered, aliasIds);
      expect(got, `seed ${seed}`).toEqual(oldCandidates(dbPath, lowered, aliasIds));
    }
  });

  it("every IOC query names an index SQLite can use (no full IOC scan)", async () => {
    await store.save({
      ...emptyState(C),
      iocs: [{ id: "i1", type: "ip", value: "1.1.1.1" }] as IOC[],
    });
    // Opening through the writer creates the indexes; the plans must name them.
    await caseSqliteWorker.request({
      op: "ensureDatabase",
      dbPath: join(cases.stateDir(C), INVESTIGATION_DB_FILENAME),
    });
    const db = new (loadDatabaseSync())(join(cases.stateDir(C), INVESTIGATION_DB_FILENAME));
    try {
      const plan = (sql: string) =>
        (db.prepare("EXPLAIN QUERY PLAN " + sql).all("[]", "[]") as { detail: string }[])
          .map((x) => x.detail)
          .join(" | ");
      expect(
        plan(
          "SELECT row_id FROM entities INDEXED BY entities_ioc_value_idx WHERE kind='iocs' AND " +
            "lower(json_extract(payload, '$.value')) IN (SELECT value FROM json_each(?)) AND ? IS NOT NULL",
        ),
      ).toContain("entities_ioc_value_idx");
      const indexes = (
        db.prepare("SELECT name FROM sqlite_master WHERE type='index'").all() as { name: string }[]
      ).map((x) => x.name);
      expect(indexes).toEqual(
        expect.arrayContaining([
          "entities_ioc_value_idx",
          "entities_ioc_odd_idx",
          "entities_ioc_badid_idx",
          "entities_ioc_seq_idx",
        ]),
      );
    } finally {
      db.close();
    }
  });
});
