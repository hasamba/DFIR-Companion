import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, appendFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditExportStore } from "../../src/analysis/auditExportStore.js";
import { AuditCursorStore } from "../../src/analysis/auditExportCursor.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { parseDestinationInput } from "../../src/analysis/auditExport.js";
import type { CaseStore } from "../../src/storage/caseStore.js";

let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-audit-export-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const draft = (over: Record<string, unknown> = {}) => {
  const parsed = parseDestinationInput({
    type: "splunk",
    name: "SOC",
    splunk: { url: "https://splunk:8088", token: "hec" },
    ...over,
  });
  if (!parsed.ok || !parsed.draft) throw new Error(parsed.error);
  return parsed.draft;
};

describe("AuditExportStore", () => {
  it("starts empty — nothing leaves the box until an analyst adds a destination", async () => {
    const store = new AuditExportStore(join(root, "audit-export", "config.json"));
    expect(await store.load()).toEqual([]);
  });

  it("adds, reads back, updates and removes a destination", async () => {
    const store = new AuditExportStore(join(root, "audit-export", "config.json"));
    const added = await store.add(draft());
    expect(added.id).toBeTruthy();
    expect(await store.load()).toHaveLength(1);
    expect((await store.get(added.id))?.name).toBe("SOC");

    const updated = await store.update(added.id, draft({ name: "SOC Splunk", enabled: false }));
    expect(updated?.name).toBe("SOC Splunk");
    expect(updated?.enabled).toBe(false);
    expect(updated?.createdAt).toBe(added.createdAt);

    expect(await store.remove(added.id)).toBe(true);
    expect(await store.remove(added.id)).toBe(false);
    expect(await store.load()).toEqual([]);
  });

  it("re-validates on read so a hand-edited file cannot inject a malformed destination", async () => {
    const file = join(root, "audit-export", "config.json");
    await mkdir(join(root, "audit-export"), { recursive: true });
    const good = {
      id: "d1",
      type: "splunk",
      name: "ok",
      enabled: true,
      splunk: { url: "https://s:8088", token: "t" },
      createdAt: "",
      updatedAt: "",
    };
    await appendFile(file, JSON.stringify([good, { id: "d2", type: "carrier-pigeon" }]), "utf8");
    const store = new AuditExportStore(file);
    const loaded = await store.load();
    expect(loaded).toHaveLength(1);
    expect(loaded[0].id).toBe("d1");
  });

  it("keeps the credential out of the file's client-facing shape but in the file", async () => {
    const file = join(root, "audit-export", "config.json");
    const store = new AuditExportStore(file);
    await store.add(draft());
    // The secret must persist — the exporter needs it to authenticate.
    expect(await readFile(file, "utf8")).toContain("hec");
  });
});

describe("AuditCursorStore", () => {
  it("reports zero for a destination and case it has never seen", async () => {
    const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    expect(await cursors.get("d1", "case-1")).toBe(0);
  });

  it("remembers a position across a fresh instance — a restart must not re-send", async () => {
    const file = join(root, "audit-export", "cursors.json");
    await new AuditCursorStore(file).set("d1", "case-1", 12);
    expect(await new AuditCursorStore(file).get("d1", "case-1")).toBe(12);
  });

  it("keeps positions separate per destination and per case", async () => {
    const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    await cursors.set("d1", "case-1", 5);
    await cursors.set("d2", "case-1", 9);
    await cursors.set("d1", "case-2", 2);
    expect(await cursors.get("d1", "case-1")).toBe(5);
    expect(await cursors.get("d2", "case-1")).toBe(9);
    expect(await cursors.get("d1", "case-2")).toBe(2);
  });

  it("never moves a position backwards", async () => {
    // Two concurrent sends of overlapping batches must not rewind the high-water mark; a rewind
    // re-sends entries the SIEM already holds.
    const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    await cursors.set("d1", "case-1", 10);
    await cursors.set("d1", "case-1", 4);
    expect(await cursors.get("d1", "case-1")).toBe(10);
  });

  it("forgets a removed destination's positions", async () => {
    const cursors = new AuditCursorStore(join(root, "audit-export", "cursors.json"));
    await cursors.set("d1", "case-1", 5);
    await cursors.set("d2", "case-1", 5);
    await cursors.clearDestination("d1");
    expect(await cursors.get("d1", "case-1")).toBe(0);
    expect(await cursors.get("d2", "case-1")).toBe(5);
  });
});

describe("ActivityLogStore.readFrom", () => {
  const casesRoot = () => join(root, "cases");
  const fakeCases = (): CaseStore =>
    ({ metadataDir: (caseId: string) => join(casesRoot(), caseId, "metadata") }) as CaseStore;

  const write = async (caseId: string, lines: string[]) => {
    await mkdir(join(casesRoot(), caseId, "metadata"), { recursive: true });
    await appendFile(
      join(casesRoot(), caseId, "metadata", "activity.jsonl"),
      lines.join("\n") + "\n",
      "utf8",
    );
  };

  const entryLine = (id: string) =>
    JSON.stringify({
      id,
      timestamp: "2026-09-12T10:00:00.000Z",
      actor: "alice",
      category: "triage",
      action: "a",
      detail: "d",
      outcome: "success",
    });

  it("returns nothing for a case with no log", async () => {
    const store = new ActivityLogStore(fakeCases());
    expect(await store.readFrom("nope", 0)).toEqual({ entries: [], lines: 0 });
  });

  it("returns entries oldest-first, which is the order a SIEM must receive them", async () => {
    const store = new ActivityLogStore(fakeCases());
    await write("c1", [entryLine("e1"), entryLine("e2"), entryLine("e3")]);
    const r = await store.readFrom("c1", 0);
    expect(r.entries.map((e) => e.id)).toEqual(["e1", "e2", "e3"]);
    expect(r.lines).toBe(3);
  });

  it("returns only what follows the given position", async () => {
    const store = new ActivityLogStore(fakeCases());
    await write("c1", [entryLine("e1"), entryLine("e2")]);
    expect((await store.readFrom("c1", 1)).entries.map((e) => e.id)).toEqual(["e2"]);
    expect((await store.readFrom("c1", 2)).entries).toEqual([]);
    await write("c1", [entryLine("e3")]);
    const r = await store.readFrom("c1", 2);
    expect(r.entries.map((e) => e.id)).toEqual(["e3"]);
    expect(r.lines).toBe(3);
  });

  it("counts a malformed line so the position cannot drift off by one", async () => {
    // load() skips a corrupt line. If the cursor counted only PARSED entries, every skipped line
    // would shift the position permanently and re-send one good entry forever.
    const store = new ActivityLogStore(fakeCases());
    await write("c1", [entryLine("e1"), "not json", entryLine("e2")]);
    const r = await store.readFrom("c1", 0);
    expect(r.entries.map((e) => e.id)).toEqual(["e1", "e2"]);
    expect(r.lines).toBe(3);
    expect((await store.readFrom("c1", 3)).entries).toEqual([]);
  });

  it("counts the lines a case holds without loading them", async () => {
    const store = new ActivityLogStore(fakeCases());
    expect(await store.countLines("nope")).toBe(0);
    await write("c1", [entryLine("e1"), "not json", entryLine("e2")]);
    // Raw lines, malformed included — the same unit the delivery position counts in.
    expect(await store.countLines("c1")).toBe(3);
  });

  it("walks a whole case in batches from ONE pass over the file", async () => {
    // readFrom() re-reads and re-splits the entire file on every call, so draining a long history
    // in 500-line steps was quadratic: every batch re-read every earlier line, and each live
    // action afterwards re-read years of history to find the tail.
    const store = new ActivityLogStore(fakeCases());
    await write(
      "c1",
      Array.from({ length: 25 }, (_, i) => entryLine(`e${i}`)),
    );
    const batches: string[][] = [];
    let last = 0;
    for await (const batch of store.readBatches("c1", 0, 10)) {
      batches.push(batch.entries.map((e) => e.id));
      last = batch.lines;
    }
    expect(batches.map((b) => b.length)).toEqual([10, 10, 5]);
    expect(batches[0][0]).toBe("e0");
    expect(batches[2][4]).toBe("e24");
    expect(last).toBe(25);
  });

  it("resumes a batch walk from a position", async () => {
    const store = new ActivityLogStore(fakeCases());
    await write(
      "c1",
      Array.from({ length: 12 }, (_, i) => entryLine(`e${i}`)),
    );
    const seen: string[] = [];
    for await (const batch of store.readBatches("c1", 10, 10)) {
      seen.push(...batch.entries.map((e) => e.id));
    }
    expect(seen).toEqual(["e10", "e11"]);
  });

  it("yields nothing for a case with no log, and for a position at the end", async () => {
    const store = new ActivityLogStore(fakeCases());
    const none: unknown[] = [];
    for await (const b of store.readBatches("nope", 0, 10)) none.push(b);
    expect(none).toEqual([]);
    await write("c1", [entryLine("e1")]);
    const done: unknown[] = [];
    for await (const b of store.readBatches("c1", 1, 10)) done.push(b);
    expect(done).toEqual([]);
  });

  it("counts a malformed line in a batch walk, so the position cannot drift", async () => {
    const store = new ActivityLogStore(fakeCases());
    await write("c1", [entryLine("e1"), "not json", entryLine("e2")]);
    const batches: Array<{ ids: string[]; lines: number }> = [];
    for await (const b of store.readBatches("c1", 0, 2)) {
      batches.push({ ids: b.entries.map((e) => e.id), lines: b.lines });
    }
    expect(batches).toEqual([
      { ids: ["e1"], lines: 2 },
      { ids: ["e2"], lines: 3 },
    ]);
  });

  it("caps one read so a long-lived case cannot load its whole history into memory at once", async () => {
    const store = new ActivityLogStore(fakeCases());
    await write(
      "c1",
      Array.from({ length: 40 }, (_, i) => entryLine(`e${i}`)),
    );
    const r = await store.readFrom("c1", 0, 10);
    expect(r.entries).toHaveLength(10);
    expect(r.lines).toBe(10);
    expect(r.entries[0].id).toBe("e0");
  });
});
