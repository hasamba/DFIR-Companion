// #1874: the case's tags live in the case database (state/investigation.sqlite), migrated once from
// the old side file state/tags.json. Every TagsStore caller must see exactly what the file-based store
// gave it: the same list in the same order, the same dedupe, the same protection calls. The file-based
// store is kept below, verbatim, as the oracle the random sequences run against.
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { CaseStore } from "../../src/storage/caseStore.js";
import { atomicWrite } from "../../src/storage/atomicWrite.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { TAGGER_AUTHOR_PREFIX } from "../../src/analysis/superTimeline.js";
import { TAGGER_PREFIX_SQL } from "../../src/analysis/caseSqliteSchema.js";
import { INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import {
  TagsStore,
  normalizeLabel,
  tagSchema,
  type EventProtectionSink,
  type NewTag,
  type Tag,
} from "../../src/analysis/tags.js";

// ── The file-based TagsStore as it was before #1874 (the oracle) ────────────────────────────────
function protectsEvent(tag: Pick<Tag, "targetType" | "author">): boolean {
  return tag.targetType === "event" && !tag.author.startsWith(TAGGER_AUTHOR_PREFIX);
}
class LegacyTagsStore {
  private readonly lock = new StateLock();
  constructor(
    private readonly cases: CaseStore,
    private readonly protection?: EventProtectionSink,
  ) {}
  private async releaseUnreferenced(caseId: string, removed: Tag[], remaining: Tag[]): Promise<void> {
    if (!this.protection) return;
    const stillHeld = new Set(remaining.filter(protectsEvent).map((t) => t.targetId));
    const released = new Set(removed.filter(protectsEvent).map((t) => t.targetId));
    for (const targetId of released) {
      if (!stillHeld.has(targetId)) await this.protection.unprotect(caseId, targetId);
    }
  }
  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "tags.json");
  }
  async load(caseId: string): Promise<Tag[]> {
    try {
      return z
        .array(tagSchema)
        .catch([])
        .parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }
  private async save(caseId: string, tags: Tag[]): Promise<void> {
    await atomicWrite(this.path(caseId), JSON.stringify(tags, null, 2));
  }
  async add(caseId: string, input: NewTag): Promise<Tag> {
    const label = normalizeLabel(input.label);
    if (!label) throw new Error("label is required");
    const targetType = String(input.targetType).trim();
    const targetId = String(input.targetId).trim();
    return this.lock.runExclusive(caseId, async () => {
      const existingTags = await this.load(caseId);
      const dup = existingTags.find(
        (t) => t.targetType === targetType && t.targetId === targetId && t.label === label,
      );
      if (dup) return dup;
      const tag: Tag = {
        id: randomUUID(),
        targetType,
        targetId,
        label,
        author: (input.author || "").trim() || "anonymous",
        createdAt: new Date().toISOString(),
      };
      if (this.protection && protectsEvent(tag)) await this.protection.protect(caseId, targetId);
      await this.save(caseId, [...existingTags, tag]);
      return tag;
    });
  }
  async addMany(caseId: string, inputs: readonly NewTag[]): Promise<Tag[]> {
    if (inputs.some((input) => !normalizeLabel(input.label))) throw new Error("label is required");
    if (!inputs.length) return [];
    const key = (a: string, b: string, c: string) => JSON.stringify([a, b, c]);
    return this.lock.runExclusive(caseId, async () => {
      const existingTags = await this.load(caseId);
      const seen = new Set(existingTags.map((t) => key(t.targetType, t.targetId, t.label)));
      const createdAt = new Date().toISOString();
      const created: Tag[] = [];
      for (const input of inputs) {
        const targetType = String(input.targetType).trim();
        const targetId = String(input.targetId).trim();
        const label = normalizeLabel(input.label);
        const k = key(targetType, targetId, label);
        if (seen.has(k)) continue;
        seen.add(k);
        const author = (input.author || "").trim() || "anonymous";
        created.push({ id: randomUUID(), targetType, targetId, label, author, createdAt });
      }
      if (!created.length) return [];
      for (const tag of created) {
        if (this.protection && protectsEvent(tag)) await this.protection.protect(caseId, tag.targetId);
      }
      await this.save(caseId, [...existingTags, ...created]);
      return created;
    });
  }
  async remove(caseId: string, tagId: string): Promise<Tag | null> {
    return this.lock.runExclusive(caseId, async () => {
      const tags = await this.load(caseId);
      const removed = tags.find((t) => t.id === tagId) ?? null;
      if (!removed) return null;
      const remaining = tags.filter((t) => t.id !== tagId);
      await this.save(caseId, remaining);
      await this.releaseUnreferenced(caseId, [removed], remaining);
      return removed;
    });
  }
  async removeTaggerTagsFor(caseId: string, targetIds: readonly string[]): Promise<number> {
    const targets = new Set(targetIds);
    if (!targets.size) return 0;
    return this.lock.runExclusive(caseId, async () => {
      const tags = await this.load(caseId);
      const gone = (t: Tag) =>
        t.targetType === "event" && t.author.startsWith(TAGGER_AUTHOR_PREFIX) && targets.has(t.targetId);
      const next = tags.filter((t) => !gone(t));
      const removed = tags.length - next.length;
      if (removed) await this.save(caseId, next);
      return removed;
    });
  }
  async removeByAuthorPrefix(caseId: string, prefix: string): Promise<number> {
    return this.lock.runExclusive(caseId, async () => {
      const tags = await this.load(caseId);
      const next = tags.filter((t) => !t.author.startsWith(prefix));
      const removed = tags.length - next.length;
      if (removed) {
        await this.save(caseId, next);
        await this.releaseUnreferenced(
          caseId,
          tags.filter((t) => t.author.startsWith(prefix)),
          next,
        );
      }
      return removed;
    });
  }
}

// ── helpers ───────────────────────────────────────────────────────────────────────────────────────
async function freshCases(prefix: string): Promise<CaseStore> {
  const cases = new CaseStore(await mkdtemp(join(tmpdir(), prefix)));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return cases;
}

const tagsFile = (cases: CaseStore) => join(cases.stateDir("c1"), "tags.json");
const dbFile = (cases: CaseStore) => join(cases.stateDir("c1"), INVESTIGATION_DB_FILENAME);

function tag(id: string, targetId: string, label: string, author = "alice", targetType = "event"): Tag {
  return { id, targetType, targetId, label, author, createdAt: "2026-06-04T00:00:00.000Z" };
}

function recorder(): EventProtectionSink & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    protect: async (_caseId, eventId) => {
      calls.push(`protect ${eventId}`);
      return true;
    },
    unprotect: async (_caseId, eventId) => {
      calls.push(`unprotect ${eventId}`);
    },
  };
}

function withDb<T>(cases: CaseStore, fn: (db: InstanceType<ReturnType<typeof loadDatabaseSync>>) => T): T {
  const db = new (loadDatabaseSync())(dbFile(cases));
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

// Ids are random per store: replace each by the order it first appears, so two lists compare by shape.
function canonical(tags: Tag[]): unknown[] {
  const ids = new Map<string, number>();
  return tags.map((t) => {
    if (!ids.has(t.id)) ids.set(t.id, ids.size);
    return [ids.get(t.id), t.targetType, t.targetId, t.label, t.author];
  });
}

function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("tag prefix literal (#1874)", () => {
  it("the SQL trigger's tagger prefix is TAGGER_AUTHOR_PREFIX", () => {
    expect(TAGGER_PREFIX_SQL).toBe(TAGGER_AUTHOR_PREFIX);
  });
});

describe("TagsStore migration from state/tags.json (#1874)", () => {
  let cases: CaseStore;
  let store: TagsStore;
  beforeEach(async () => {
    cases = await freshCases("dfir-tags-mig-");
    store = new TagsStore(cases);
  });

  const marker = () =>
    existsSync(dbFile(cases))
      ? withDb(cases, (db) => !!db.prepare("SELECT 1 AS x FROM storage_meta WHERE key='tags_migrated'").get())
      : false;

  it("no file: an empty list, and no marker is set", async () => {
    expect(await store.load("c1")).toEqual([]);
    await store.remove("c1", "nope");
    await store.removeByAuthorPrefix("c1", "tagger:");
    expect(marker()).toBe(false);
  });

  it("an empty file migrates to an empty list and sets the marker", async () => {
    await writeFile(tagsFile(cases), "[]");
    expect(await store.load("c1")).toEqual([]);
    expect(marker()).toBe(true);
  });

  it("a valid file migrates in file order, unknown keys stripped, duplicates kept", async () => {
    const rows = [
      { ...tag("t1", "e1", "x"), extra: 1 },
      tag("t2", "e2", "y", "tagger:r"),
      tag("t1", "e3", "x"), // duplicate id
      tag("t4", "e1", "x"), // duplicate (target, label)
    ];
    await writeFile(tagsFile(cases), JSON.stringify(rows));
    const loaded = await store.load("c1");
    expect(loaded).toEqual([
      tag("t1", "e1", "x"),
      tag("t2", "e2", "y", "tagger:r"),
      tag("t1", "e3", "x"),
      tag("t4", "e1", "x"),
    ]);
    expect(Object.keys(loaded[0])).toEqual(["id", "targetType", "targetId", "label", "author", "createdAt"]);
    expect(marker()).toBe(true);
    expect(existsSync(tagsFile(cases))).toBe(true); // the source file is kept
    // The DB is the authority from now on: a later edit of the file is not read.
    await writeFile(tagsFile(cases), "[]");
    expect(await store.load("c1")).toHaveLength(4);
  });

  it("a malformed element makes the whole list empty (today's zod view)", async () => {
    await writeFile(tagsFile(cases), JSON.stringify([tag("t1", "e1", "x"), { id: 5, targetType: "event" }]));
    expect(await store.load("c1")).toEqual([]);
    expect(marker()).toBe(true);
  });

  it("a non-array file is an empty list", async () => {
    await writeFile(tagsFile(cases), JSON.stringify({ tags: [tag("t1", "e1", "x")] }));
    expect(await store.load("c1")).toEqual([]);
  });

  it("corrupt JSON throws, as the file-based load did, and migrates nothing", async () => {
    await writeFile(tagsFile(cases), "[{not json");
    await expect(store.load("c1")).rejects.toThrow();
    await expect(
      store.add("c1", { targetType: "event", targetId: "e1", author: "a", label: "x" }),
    ).rejects.toThrow();
    expect(marker()).toBe(false);
  });

  it("a tags.json that appears later (no marker yet) is migrated", async () => {
    expect(await store.load("c1")).toEqual([]);
    await store.removeTaggerTagsFor("c1", ["e1"]);
    await writeFile(tagsFile(cases), JSON.stringify([tag("t9", "e9", "late")]));
    expect(await store.load("c1")).toEqual([tag("t9", "e9", "late")]);
  });

  it("the first write sets the marker even with no file", async () => {
    await store.add("c1", { targetType: "ioc", targetId: "i1", author: "a", label: "x" });
    expect(marker()).toBe(true);
    await writeFile(tagsFile(cases), JSON.stringify([tag("t9", "e9", "late")]));
    expect((await store.load("c1")).map((t) => t.targetId)).toEqual(["i1"]);
  });

  it("a database written before the tags table existed is migrated on the next read", async () => {
    await store.add("c1", { targetType: "ioc", targetId: "i1", author: "a", label: "x" });
    withDb(cases, (db) => {
      db.exec("DROP TABLE tags; DELETE FROM storage_meta WHERE key='tags_migrated'");
    });
    await writeFile(tagsFile(cases), JSON.stringify([tag("t1", "e1", "x")]));
    expect(await store.load("c1")).toEqual([tag("t1", "e1", "x")]);
  });
});

describe("TagsStore on the database matches the file-based store (#1874)", () => {
  const TYPES = ["event", "ioc", " event "];
  const TARGETS = ["e1", "e2", "e3", " e1", "d"];
  const LABELS = ["x", "X ", "y", "a b", "z"];
  const AUTHORS = ["alice", "tagger:r1", "tagger:r2", "", "Tagger:x", "  bob "];
  const seed: Tag[] = [
    tag("d1", "e1", "x", "alice"),
    tag("d1", "e2", "x", "alice"), // duplicate id, two targets
    tag("s1", "e3", "y", "tagger:r1"),
    tag("s2", "e3", "y", "bob"), // duplicate (target, label)
    tag("s3", "i1", "x", "alice", "ioc"),
  ];

  it("random operation sequences give the same list, results and protection calls", async () => {
    for (let run = 0; run < 12; run++) {
      const rand = mulberry32(1874 + run);
      const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)];
      const newTag = (): NewTag => ({
        targetType: pick(TYPES),
        targetId: pick(TARGETS),
        label: rand() < 0.03 ? "  " : pick(LABELS),
        author: pick(AUTHORS),
      });
      const oldCases = await freshCases("dfir-tags-old-");
      const newCases = await freshCases("dfir-tags-new-");
      if (run % 2 === 0) {
        await writeFile(tagsFile(oldCases), JSON.stringify(seed));
        await writeFile(tagsFile(newCases), JSON.stringify(seed));
      }
      const oldSink = recorder();
      const newSink = recorder();
      const oracle = new LegacyTagsStore(oldCases, oldSink);
      const store = new TagsStore(newCases, newSink);
      for (let step = 0; step < 25; step++) {
        const before = await oracle.load("c1");
        const mine = await store.load("c1");
        const op = Math.floor(rand() * 6);
        const settle = async <T>(p: Promise<T>) =>
          p.then(
            (value) => ({ value }),
            (err: Error) => ({ err: err.message }),
          );
        let a: unknown;
        let b: unknown;
        if (op === 0) {
          const input = newTag();
          a = await settle(oracle.add("c1", input));
          b = await settle(store.add("c1", input));
        } else if (op === 1) {
          const inputs = Array.from({ length: 1 + Math.floor(rand() * 6) }, newTag);
          a = await settle(oracle.addMany("c1", inputs));
          b = await settle(store.addMany("c1", inputs));
        } else if (op === 2 && before.length) {
          const i = Math.floor(rand() * before.length);
          a = await settle(oracle.remove("c1", before[i].id));
          b = await settle(store.remove("c1", mine[i].id));
        } else if (op === 3) {
          const ids = [pick(TARGETS), pick(TARGETS)];
          a = await settle(oracle.removeTaggerTagsFor("c1", ids));
          b = await settle(store.removeTaggerTagsFor("c1", ids));
        } else if (op === 4) {
          const prefix = pick(["tagger:", "tagger:r1", "ali", "", "Tagger:"]);
          a = await settle(oracle.removeByAuthorPrefix("c1", prefix));
          b = await settle(store.removeByAuthorPrefix("c1", prefix));
        } else {
          a = await settle(oracle.remove("c1", "missing"));
          b = await settle(store.remove("c1", "missing"));
        }
        const shape = (r: unknown) => {
          const v = (r as { value?: unknown }).value;
          if (Array.isArray(v))
            return { value: v.map((t: Tag) => [t.targetType, t.targetId, t.label, t.author]) };
          if (v && typeof v === "object") {
            const t = v as Tag;
            return { value: [t.targetType, t.targetId, t.label, t.author] };
          }
          return r;
        };
        expect(shape(b), `run ${run} step ${step} op ${op}`).toEqual(shape(a));
        expect(canonical(await store.load("c1")), `run ${run} step ${step}`).toEqual(
          canonical(await oracle.load("c1")),
        );
        expect(newSink.calls).toEqual(oldSink.calls);
      }
    }
  }, 60_000);

  it("returns the stored tag objects: add() of a duplicate returns the first one", async () => {
    const cases = await freshCases("dfir-tags-dup-");
    await writeFile(tagsFile(cases), JSON.stringify(seed));
    const store = new TagsStore(cases);
    expect(await store.add("c1", { targetType: "event", targetId: "e3", author: "z", label: "Y" })).toEqual(
      seed[2],
    );
    expect(await store.remove("c1", "d1")).toEqual(seed[0]);
    expect((await store.load("c1")).map((t) => t.id)).toEqual(["s1", "s2", "s3"]);
  });

  it("addMany's tags share one createdAt and get distinct ids", async () => {
    const store = new TagsStore(await freshCases("dfir-tags-ts-"));
    const created = await store.addMany("c1", [
      { targetType: "event", targetId: "e1", author: "a", label: "x" },
      { targetType: "event", targetId: "e2", author: "a", label: "x" },
    ]);
    expect(new Set(created.map((t) => t.createdAt)).size).toBe(1);
    expect(new Set(created.map((t) => t.id)).size).toBe(2);
    expect(await store.load("c1")).toEqual(created);
  });
});

describe("TagsStore cost (#1874)", () => {
  it("addMany sends only the batch: one plan and one insert, never a full list read", async () => {
    const cases = await freshCases("dfir-tags-cost-");
    const store = new TagsStore(cases);
    await store.addMany(
      "c1",
      Array.from({ length: 2000 }, (_, i) => ({
        targetType: "event",
        targetId: `old${i}`,
        author: "tagger:r",
        label: "x",
      })),
    );
    const spy = vi.spyOn(caseSqliteWorker, "request");
    const created = await store.addMany("c1", [
      { targetType: "event", targetId: "old1", author: "tagger:r", label: "x" },
      { targetType: "event", targetId: "new1", author: "tagger:r", label: "x" },
    ]);
    expect(created.map((t) => t.targetId)).toEqual(["new1"]);
    const ops = spy.mock.calls.map(([m]) => m.op);
    expect(ops).toEqual(["tagsPlan", "tagsInsert"]);
    spy.mockClear();
    expect(
      await store.addMany("c1", [{ targetType: "event", targetId: "old2", author: "tagger:r", label: "x" }]),
    ).toEqual([]);
    expect(spy.mock.calls.map(([m]) => m.op)).toEqual(["tagsPlan"]); // nothing new: no write
  });

  it("the duplicate lookup is an index search, not a scan", async () => {
    const cases = await freshCases("dfir-tags-plan-");
    await new TagsStore(cases).add("c1", { targetType: "event", targetId: "e1", author: "a", label: "x" });
    const plan = withDb(cases, (db) =>
      db
        .prepare(
          "EXPLAIN QUERY PLAN SELECT id FROM tags WHERE target_type=? AND target_id=? AND label=? ORDER BY seq LIMIT 1",
        )
        .all("event", "e1", "x")
        .map((r) => String((r as { detail: unknown }).detail))
        .join(" "),
    );
    expect(plan).toMatch(/USING (COVERING )?INDEX tags_target_idx/);
    expect(plan).not.toMatch(/TEMP B-TREE/);
  });
});
