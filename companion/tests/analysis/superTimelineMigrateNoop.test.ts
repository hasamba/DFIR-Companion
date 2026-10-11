// #2129: every super-timeline read used to post migrateSuper, which the pool routes (and counts) as a
// write, so a read-only panel moved the case's write sequence and defeated the case-open share (#2126)
// and the report-lite cache (#2057). The store now asks a READ op first (superMigrateNeeded) and posts
// migrateSuper only when a migration or sync is actually due — StateStore's stateExists pattern.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { caseSqliteWorker } from "../../src/analysis/caseSqliteWorker.js";
import { INVESTIGATION_DB_FILENAME } from "../../src/analysis/stateStore.js";
import { TAGGER_AUTHOR_PREFIX } from "../../src/analysis/superTimeline.js";
import { SET_ASIDE_NOTE_MARKERS, SET_ASIDE_REGISTRY_VERSION } from "../../src/analysis/setAsideRows.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { loadDatabaseSync } from "../../src/analysis/sqliteRuntime.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const DatabaseSync = loadDatabaseSync();
const CASE = "c1";

function ev(id: string, timestamp: string): ForensicEvent {
  return {
    id,
    timestamp,
    description: "d " + id,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

describe("a no-op super-timeline migrate keeps the case write sequence (#2129)", () => {
  let cases: CaseStore;
  let store: SuperTimelineStore;
  let dbPath: string;

  const migrateMessage = (op: string) => ({
    op,
    dbPath,
    eventsPath: join(cases.stateDir(CASE), "super-timeline.json"),
    labelsPath: join(cases.stateDir(CASE), "super-timeline-labels.json"),
    tagsPath: join(cases.stateDir(CASE), "tags.json"),
    excludeAuthorPrefix: TAGGER_AUTHOR_PREFIX,
    max: 100000,
    setAsideMarkers: SET_ASIDE_NOTE_MARKERS,
    setAsideVersion: SET_ASIDE_REGISTRY_VERSION,
  });

  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-2129-"));
    cases = new CaseStore(root);
    await cases.createCase({ caseId: CASE, name: "n", investigator: "i", aiProvider: null });
    store = new SuperTimelineStore(cases, 100000);
    dbPath = join(cases.stateDir(CASE), INVESTIGATION_DB_FILENAME);
  });

  async function settle(): Promise<void> {
    await store.append(CASE, [
      ev("e1", "2026-06-01T00:00:00Z"),
      ev("e2", "2026-06-01T00:01:00Z"),
      ev("e3", "2026-06-01T00:02:00Z"),
    ]);
    await store.query(CASE, {});
  }

  it("reads of a settled case never move the write sequence", async () => {
    await settle();
    const before = caseSqliteWorker.writeSequence(dbPath);
    expect((await store.query(CASE, {})).total).toBe(3);
    await store.meta(CASE);
    expect((await store.get(CASE, "e2"))?.id).toBe("e2");
    await store.protectedIds(CASE);
    await store.queryIndexed(CASE, {});
    expect(caseSqliteWorker.writeSequence(dbPath)).toBe(before);
  });

  it("an analyst tag write makes the next read reconcile protection, and bump the sequence", async () => {
    await settle();
    await new TagsStore(cases).add(CASE, {
      targetType: "event",
      targetId: "e1",
      author: "analyst",
      label: "key-evidence",
    });
    const before = caseSqliteWorker.writeSequence(dbPath);
    await store.query(CASE, {});
    expect(caseSqliteWorker.writeSequence(dbPath)).toBeGreaterThan(before);
    expect(await store.protectedIds(CASE)).toContain("e1");
    // Reconciled: the next read is a no-op again.
    const settled = caseSqliteWorker.writeSequence(dbPath);
    await store.query(CASE, {});
    expect(caseSqliteWorker.writeSequence(dbPath)).toBe(settled);
  });

  it("a legacy super-timeline.json with no database still migrates", async () => {
    await writeFile(
      join(cases.stateDir(CASE), "super-timeline.json"),
      JSON.stringify([ev("l1", "2026-05-01T00:00:00Z"), ev("l2", "2026-05-02T00:00:00Z")]),
    );
    const before = caseSqliteWorker.writeSequence(dbPath);
    const result = await store.query(CASE, {});
    expect(caseSqliteWorker.writeSequence(dbPath)).toBeGreaterThan(before);
    expect(result.events.map((e) => e.id)).toEqual(["l1", "l2"]);
  });

  // Drift guard: when the pre-check says "nothing due", a forced migrateSuper must change nothing.
  // If migrateSuper gains a step, this fails until superMigrateNeeded mirrors it.
  it("a forced migrateSuper on a db the pre-check calls settled changes nothing", async () => {
    await settle();
    await new TagsStore(cases).add(CASE, {
      targetType: "event",
      targetId: "e3",
      author: "analyst",
      label: "key-evidence",
    });
    await store.query(CASE, {}); // reconcile the tag write
    expect(await caseSqliteWorker.request<boolean>(migrateMessage("superMigrateNeeded"))).toBe(false);

    const snapshot = () => {
      const db = new DatabaseSync(dbPath, { readOnly: true });
      try {
        return {
          meta: db.prepare("SELECT key, value FROM storage_meta ORDER BY key").all(),
          protectedRows: db.prepare("SELECT event_id FROM super_protected ORDER BY event_id").all(),
          rows: db.prepare("SELECT count(*) AS n FROM entities WHERE kind='superTimeline'").get(),
          setAside: db.prepare("SELECT count(*) AS n FROM super_set_aside").get(),
        };
      } finally {
        db.close();
      }
    };
    const before = snapshot();
    expect(before.protectedRows).toEqual([{ event_id: "e3" }]);
    await caseSqliteWorker.request<void>(migrateMessage("migrateSuper"));
    expect(snapshot()).toEqual(before);
  });

  it("answers true when there is no database yet", async () => {
    expect(await caseSqliteWorker.request<boolean>(migrateMessage("superMigrateNeeded"))).toBe(true);
  });
});
