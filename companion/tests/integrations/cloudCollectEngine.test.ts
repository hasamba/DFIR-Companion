import { describe, it, expect } from "vitest";
import { readFile, readdir, writeFile, appendFile } from "node:fs/promises";
import { join } from "node:path";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import { collectionPaths, parseManifest } from "../../src/integrations/cloudCollect/collectManifest.js";
import type { CollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import type {
  CloudCollectSession,
  CollectionCheckpoint,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import { collectionJobWarning } from "../../src/routes/cloudCollectJob.js";
import {
  diskFull,
  fakeSession,
  faultFs,
  kill,
  pipelineImporter,
  tempCase,
  type TempCase,
} from "../helpers/cloudCollectFakes.js";

// #2311 — the durable, resumable collection engine on a fake provider and a fault-injecting fs.

const SOURCES = [{ id: "ct", label: "CloudTrail", streamKind: "aws" as const }];
const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-02T00:00:00Z" };
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

async function start(t: TempCase, fs: CollectFs, session: CloudCollectSession) {
  await createCollection(
    fs,
    session,
    {
      dir: t.dir,
      collectionId: "cc-test-abc123",
      caseId: "c1",
      accountId: "acct1",
      accountName: "lab",
      provider: "aws",
      sources: ["ct"],
      window: WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
    },
    now,
  );
}

function run(
  t: TempCase,
  fs: CollectFs,
  session: CloudCollectSession,
  importer = pipelineImporter(t),
  resume = false,
) {
  return runCollection({ fs, session, importer, sources: SOURCES, now }, t.dir, { resume });
}

async function manifestOf(t: TempCase) {
  return parseManifest(await readFile(collectionPaths(t.dir).manifest, "utf8"));
}

async function counts(t: TempCase) {
  const state = await t.stateStore.load("c1");
  const superMeta = await t.superTimelineStore.meta("c1");
  return {
    events: state.forensicTimeline.length,
    findings: state.findings.length,
    iocs: state.iocs.length,
    superRows: superMeta.rows,
  };
}

/** Every aggregated event's member list: its paged total, and the refs that appear more than once. */
async function memberLists(t: TempCase) {
  const state = await t.stateStore.load("c1");
  const out: Record<string, { total: number; count: number; repeated: string[] }> = {};
  for (const e of state.forensicTimeline) {
    if (!e.sourceRecords?.group) continue;
    const page = await t.cloudRecordStore.pageMembers("c1", e.sourceRecords.group, { limit: 5000 });
    const refs = page.members.map((m) => `${m.ref}|${m.locator ?? ""}`);
    out[e.sourceRecords.group] = {
      total: page.total,
      count: e.sourceRecords.count,
      repeated: refs.filter((r, i) => refs.indexOf(r) !== i),
    };
  }
  return out;
}

/** The same collection, run once with nothing going wrong — the baseline every crash must match. */
async function baseline(pages: number) {
  const t = await tempCase();
  const fs = faultFs();
  const session = fakeSession({ pages });
  await start(t, fs, session);
  const cp = await run(t, fs, session);
  return { cp, counts: await counts(t) };
}

describe("cloud collection engine (#2311)", () => {
  it("saves every page with its SHA-256 and imports it with provenance", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 3 });
    await start(t, fs, session);
    const cp = await run(t, fs, session);
    expect(cp.status).toBe("complete");
    expect(cp.missing).toEqual([]);
    const m = await manifestOf(t);
    expect(m.header).toMatchObject({
      provider: "aws",
      accountRef: "123456789012",
      sources: ["ct"],
      window: WINDOW,
    });
    expect(m.pages.map((p) => [p.seq, p.pageTokenIn ?? null, p.pageTokenOut ?? null])).toEqual([
      [1, null, "t1"],
      [2, "t1", "t2"],
      [3, "t2", null],
    ]);
    for (const p of m.pages) {
      const body = await readFile(join(collectionPaths(t.dir).pages, p.file));
      const { createHash } = await import("node:crypto");
      expect(createHash("sha256").update(body).digest("hex")).toBe(p.sha256);
      expect(p.bytes).toBe(body.length);
    }
    const state = await t.stateStore.load("c1");
    const stop = state.forensicTimeline.find((e) => /StopLogging/.test(e.description))!;
    expect(stop.sourceScreenshots.some((s) => s.startsWith("evidence/cloud/cc-test-abc123/p0000"))).toBe(
      true,
    );
    expect(stop.sourceRecords?.refs.some((r) => r.includes("00000000-0000-4000-b000-"))).toBe(true);
  });

  it("kill between the page rename and its manifest line: resume quarantines the orphan, no gap, no duplicate", async () => {
    const base = await baseline(3);
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 3 });
    await start(t, fs, session);
    // The second page's manifest line never lands: its file was already renamed into pages/.
    let appends = 0;
    fs.inject("appendSync", (p) => p.endsWith("manifest.jsonl") && ++appends === 2, kill);
    await expect(run(t, fs, session)).rejects.toThrow("simulated kill");
    fs.clear();
    const cp = await run(t, fs, session, pipelineImporter(t), true);
    expect(cp.status).toBe("complete");
    expect(cp.quarantined).toEqual([expect.objectContaining({ reason: "orphan", file: "p000002-ct.json" })]);
    expect(await readdir(collectionPaths(t.dir).quarantine)).toEqual(["p000002-ct.json"]);
    const m = await manifestOf(t);
    expect(m.pages.map((p) => p.pageTokenIn ?? null)).toEqual([null, "t1", "t2"]);
    expect(await counts(t)).toEqual(base.counts);
  });

  it("drops a torn last manifest line and appends cleanly after it", async () => {
    const base = await baseline(3);
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 3 });
    await start(t, fs, session);
    fs.inject("appendSync", (p) => p.endsWith("manifest.jsonl") && p.length > 0, kill); // kill before page 1's line
    await expect(run(t, fs, session)).rejects.toThrow("simulated kill");
    fs.clear();
    await appendFile(collectionPaths(t.dir).manifest, '{"type":"page","seq":1,"sou');
    const cp = await run(t, fs, session, pipelineImporter(t), true);
    expect(cp.status).toBe("complete");
    const m = await manifestOf(t);
    expect(m.tornTail).toBe(false);
    expect(m.unreadableLines).toBe(0);
    expect(m.pages).toHaveLength(3);
    expect(await counts(t)).toEqual(base.counts);
  });

  it("a page whose hash no longer matches is quarantined as corrupt and its window fetched again", async () => {
    const base = await baseline(2);
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2 });
    await start(t, fs, session);
    // Kill the import of the first page so the run stops after the network stage.
    const importer = pipelineImporter(t, {
      duringPage: () => {
        throw kill();
      },
      noCleanup: () => true,
    });
    await expect(run(t, fs, session, importer)).rejects.toThrow("simulated kill");
    const first = (await manifestOf(t)).pages[0];
    await writeFile(join(collectionPaths(t.dir).pages, first.file), "tampered");
    const cp = await run(t, fs, session, pipelineImporter(t), true);
    expect(cp.status).toBe("complete");
    expect(cp.quarantined).toEqual([
      expect.objectContaining({ reason: "corrupt", file: first.file, sha256: expect.any(String) }),
    ]);
    const m = await manifestOf(t);
    expect(m.entries.some((e) => e.type === "restart" && e.reason === "corrupt-page")).toBe(true);
    expect(m.pages).toHaveLength(4); // 2 originals + the window fetched again
    expect(await counts(t)).toEqual(base.counts);
  });

  it("an expired cursor restarts the sub-window from its start; dedup absorbs the overlap", async () => {
    const base = await baseline(3);
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 3, expireOnce: ["t2"] });
    await start(t, fs, session);
    const cp = await run(t, fs, session);
    expect(cp.status).toBe("complete");
    const m = await manifestOf(t);
    expect(m.entries.filter((e) => e.type === "restart")).toEqual([
      expect.objectContaining({ reason: "cursor-expired", subWindowId: "ct:0" }),
    ]);
    expect(m.pages.map((p) => p.pageTokenIn ?? null)).toEqual([null, "t1", null, "t1", "t2"]);
    expect(await counts(t)).toEqual(base.counts);
  });

  it("a crash mid-import then a re-import gives the same event and finding counts", async () => {
    const base = await baseline(2);
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2 });
    await start(t, fs, session);
    // Die inside the second page, after its second batch: its ledger batch and super rows are on
    // disk, its delta is not, and its cleanup never ran.
    const importer = pipelineImporter(t, {
      duringPage: (label, batch) => {
        if (label.endsWith("p000002-ct.json") && batch === 2) throw kill();
      },
      noCleanup: () => true,
    });
    await expect(run(t, fs, session, importer)).rejects.toThrow("simulated kill");
    const resumed = pipelineImporter(t);
    const cp = await run(t, fs, session, resumed, true);
    expect(cp.status).toBe("complete");
    expect(resumed.imports).toEqual(["evidence/cloud/cc-test-abc123/p000002-ct.json"]);
    expect(await counts(t)).toEqual(base.counts);
    // #2339: the dead attempt's member rows are not listed twice; each total is the event's count.
    const members = await memberLists(t);
    expect(Object.keys(members).length).toBeGreaterThan(0);
    for (const m of Object.values(members))
      expect(m).toEqual({ total: m.count, count: m.count, repeated: [] });
    // And again: a third run over a finished collection changes nothing.
    const again = await run(t, fs, session, pipelineImporter(t), true);
    expect(again.status).toBe("complete");
    expect(await counts(t)).toEqual(base.counts);
  });

  it("a page whose import landed but was not checkpointed is never imported twice", async () => {
    const base = await baseline(2);
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2 });
    await start(t, fs, session);
    let checkpoints = 0;
    // Kill the checkpoint write that would record page 1 as imported (stage "import").
    fs.inject(
      "writeFileSync",
      (p) => p.endsWith("checkpoint.json.tmp") && ++checkpoints > 0 && checkpointStage === "import-1",
      kill,
    );
    let checkpointStage = "";
    const importer = pipelineImporter(t);
    const wrapped = {
      ...importer,
      importPage: async (...a: Parameters<typeof importer.importPage>) => {
        await importer.importPage(...a);
        checkpointStage = "import-1";
      },
    };
    await expect(run(t, fs, session, wrapped)).rejects.toThrow("simulated kill");
    fs.clear();
    const resumed = pipelineImporter(t);
    await run(t, fs, session, resumed, true);
    expect(resumed.imports).toEqual(["evidence/cloud/cc-test-abc123/p000002-ct.json"]);
    expect(await counts(t)).toEqual(base.counts);
  });

  it("disk full stops the collection as partial and keeps everything written", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 4 });
    await start(t, fs, session);
    let pages = 0;
    fs.inject(
      "writeFileSync",
      (p) => p.endsWith(".json.tmp") && p.includes("pages") && ++pages === 3,
      diskFull,
    );
    const cp: CollectionCheckpoint = await run(t, fs, session);
    expect(cp.status).toBe("partial");
    expect(cp.stopReason).toMatch(/ENOSPC/);
    expect(cp.missing).toEqual([
      expect.objectContaining({ source: "ct", reason: expect.stringMatching(/ENOSPC/) }),
    ]);
    const m = await manifestOf(t);
    expect(m.pages).toHaveLength(2);
    expect(cp.imported).toEqual(m.pages.map((p) => p.file));
    // Space is back: resume finishes the job.
    fs.clear();
    const resumed = await run(t, fs, session, pipelineImporter(t), true);
    expect(resumed.status).toBe("complete");
    expect((await manifestOf(t)).pages).toHaveLength(4);
  });

  it("disk full before the first page is still partial, not failed (#2339)", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2 });
    await start(t, fs, session);
    fs.inject("writeFileSync", (p) => p.endsWith(".json.tmp") && p.includes("pages"), diskFull);
    const cp = await run(t, fs, session);
    expect(cp.status).toBe("partial");
    expect(cp.imported).toEqual([]);
    expect(cp.stopReason).toMatch(/ENOSPC/);
    expect(collectionJobWarning(cp)).toMatch(/^partial — evidence write failed \(ENOSPC\)/);
    fs.clear();
    const resumed = await run(t, fs, session, pipelineImporter(t), true);
    expect(resumed.status).toBe("complete");
    expect((await manifestOf(t)).pages).toHaveLength(2);
  });

  it("a provider error fails only its window: partial with the reason, failed when nothing came back", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 3, failPage: 1 });
    await start(t, fs, session);
    const cp = await run(t, fs, session);
    expect(cp.status).toBe("partial");
    expect(cp.missing[0].reason).toMatch(/provider error: AccessDenied/);

    const t2 = await tempCase();
    const s2 = fakeSession({ pages: 3, failPage: 0 });
    await start(t2, fs, s2);
    expect((await run(t2, fs, s2)).status).toBe("failed");
  });
});

describe("manifest parsing and startup recovery (#2311)", () => {
  it("parseManifest drops only a torn LAST line; a bad middle line is counted, not trusted", async () => {
    const { parseManifest: parse } = await import("../../src/integrations/cloudCollect/collectManifest.js");
    const header = JSON.stringify({ type: "header", collectionId: "x", sources: [], window: WINDOW });
    const good = parse(`${header}\n{"type":"resume","at":"t"}\n{"type":"pa`);
    expect(good.tornTail).toBe(true);
    expect(good.entries).toHaveLength(2);
    expect(good.goodBytes).toBe(Buffer.byteLength(`${header}\n{"type":"resume","at":"t"}\n`));
    const middle = parse(`${header}\nnot json\n{"type":"resume","at":"t"}\n`);
    expect(middle.tornTail).toBe(false);
    expect(middle.unreadableLines).toBe(1);
    expect(middle.entries).toHaveLength(2);
  });

  it("startup marks a running collection interrupted and never resumes it", async () => {
    const { markInterruptedCollections, listCollections } =
      await import("../../src/integrations/cloudCollect/collectStore.js");
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 1 });
    const { join: joinPath } = await import("node:path");
    const dir = joinPath(t.cases.caseDir("c1"), "evidence", "cloud", "cc-20261005t000000-0123abcd");
    await createCollection(
      fs,
      session,
      {
        dir,
        collectionId: "cc-20261005t000000-0123abcd",
        caseId: "c1",
        accountId: "a",
        accountName: "lab",
        provider: "aws",
        sources: ["ct"],
        window: WINDOW,
        filters: {},
        companionVersion: "0",
      },
      now,
    );
    expect(await markInterruptedCollections(fs, t.cases.caseDir("c1"), now)).toBe(1);
    const [c] = await listCollections(fs, t.cases.caseDir("c1"));
    expect(c.checkpoint.status).toBe("interrupted");
    expect(session.calls).toHaveLength(0);
    expect(await markInterruptedCollections(fs, t.cases.caseDir("c1"), now)).toBe(0);
  });
});

describe("a quarantined page's window is always fetched again (#2311 review)", () => {
  async function corruptFirstPage(t: TempCase, fs: ReturnType<typeof faultFs>, session: CloudCollectSession) {
    await start(t, fs, session);
    const importer = pipelineImporter(t, {
      duringPage: () => {
        throw kill();
      },
      noCleanup: () => true,
    });
    await expect(run(t, fs, session, importer)).rejects.toThrow("simulated kill");
    const first = (await manifestOf(t)).pages[0];
    await writeFile(join(collectionPaths(t.dir).pages, first.file), "tampered");
    return first;
  }

  /** Kill the n-th manifest append of the next run. */
  function killNthAppend(fs: ReturnType<typeof faultFs>, n: number) {
    let appends = 0;
    fs.inject("appendSync", (p) => p.endsWith("manifest.jsonl") && ++appends === n, kill);
  }

  async function finish(
    t: TempCase,
    fs: ReturnType<typeof faultFs>,
    session: CloudCollectSession,
    base: Awaited<ReturnType<typeof baseline>>,
  ) {
    const cp = await run(t, fs, session, pipelineImporter(t), true);
    expect(cp.status).toBe("complete");
    const m = await manifestOf(t);
    expect(m.entries.filter((e) => e.type === "restart" && e.reason === "corrupt-page")).toHaveLength(1);
    expect(m.pages).toHaveLength(4); // the two originals + the window fetched again
    expect(await counts(t)).toEqual(base.counts);
  }

  it("crash after the quarantine line, before the restart line", async () => {
    const base = await baseline(2);
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2 });
    await corruptFirstPage(t, fs, session);
    killNthAppend(fs, 2); // 1 = quarantine, 2 = restart
    await expect(run(t, fs, session, pipelineImporter(t), true)).rejects.toThrow("simulated kill");
    fs.clear();
    const m = await manifestOf(t);
    expect(m.entries.some((e) => e.type === "quarantine" && e.reason === "corrupt")).toBe(true);
    expect(m.entries.some((e) => e.type === "restart")).toBe(false);
    await finish(t, fs, session, base);
  });

  it("a torn restart line is dropped and the restart made again", async () => {
    const base = await baseline(2);
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2 });
    await corruptFirstPage(t, fs, session);
    killNthAppend(fs, 2);
    await expect(run(t, fs, session, pipelineImporter(t), true)).rejects.toThrow("simulated kill");
    fs.clear();
    await appendFile(collectionPaths(t.dir).manifest, '{"type":"restart","subWindowId":"ct:');
    await finish(t, fs, session, base);
  });

  it("repeated crashes around the restart never let the window be skipped", async () => {
    const base = await baseline(2);
    const t = await tempCase();
    const fs = faultFs();
    const session = fakeSession({ pages: 2 });
    await corruptFirstPage(t, fs, session);
    killNthAppend(fs, 2);
    await expect(run(t, fs, session, pipelineImporter(t), true)).rejects.toThrow("simulated kill");
    fs.clear();
    killNthAppend(fs, 1); // the next replay's first append is the recreated restart
    await expect(run(t, fs, session, pipelineImporter(t), true)).rejects.toThrow("simulated kill");
    fs.clear();
    killNthAppend(fs, 1);
    await expect(run(t, fs, session, pipelineImporter(t), true)).rejects.toThrow("simulated kill");
    fs.clear();
    await finish(t, fs, session, base);
  });
});
