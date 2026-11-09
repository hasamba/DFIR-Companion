import { describe, it, expect } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import { collectionPaths } from "../../src/integrations/cloudCollect/collectManifest.js";
import type { CollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import type { CloudCollectSession, CollectPage } from "../../src/integrations/cloudCollect/collectTypes.js";
import {
  diskFull,
  faultFs,
  pipelineImporter,
  tempCase,
  type TempCase,
} from "../helpers/cloudCollectFakes.js";
import {
  computeLaunch,
  isComputeRow,
  isLineageRow,
  lineageIssuance,
  lineageUse,
  LINEAGE_KEY,
} from "../helpers/awsLineageRecords.js";
import { AWS_LINEAGE_MAX } from "../../src/analysis/awsLineage.js";

// #2482 — a live collection builds ONE credential lineage per credential over every page of the run,
// at the end of its import step, instead of one per page.

const SOURCES = [{ id: "ct", label: "CloudTrail", streamKind: "aws" as const }];
const GD_SOURCES = [{ id: "gd", label: "GuardDuty", streamKind: "guardduty" as const }];
const WINDOW = { start: "2026-10-01T00:00:00Z", end: "2026-10-02T00:00:00Z" };
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 5, 0, 0, tick++)).toISOString();

/** 8 pages, one record each: the key's issuance on page 1, its uses on pages 2–8 from two sources. */
function lineageSession(pages = 8): CloudCollectSession {
  return {
    identity: async () => ({
      accountRef: "111122223333",
      caller: "arn:aws:iam::111122223333:role/collector",
      sdkVersions: { fake: "1.0.0" },
    }),
    fetchPage: async (req): Promise<CollectPage> => {
      const index = req.pageToken ? Number(req.pageToken.slice(1)) : 0;
      const records = [index === 0 ? lineageIssuance(0) : lineageUse(index)];
      const next = index + 1 < pages ? `t${index + 1}` : undefined;
      return {
        body: Buffer.from(JSON.stringify({ Records: records })),
        extension: "json",
        recordCount: records.length,
        ...(next ? { nextPageToken: next } : {}),
        requestId: `req-${index}`,
        requestParams: { page: String(index), source: req.source },
      };
    },
  };
}

async function start(t: TempCase, fs: CollectFs, session: CloudCollectSession, sources = ["ct"]) {
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
      sources,
      window: WINDOW,
      filters: {},
      companionVersion: "0.0.0-test",
    },
    now,
  );
}

async function lineageRows(t: TempCase) {
  const state = await t.stateStore.load("c1");
  const superRows = (await t.superTimelineStore.query("c1", { limit: 500 })).events;
  return { forensic: state.forensicTimeline.filter(isLineageRow), super: superRows.filter(isLineageRow) };
}

describe("one credential lineage per collection run (#2482)", () => {
  it("a key issued on page 1 and used on pages 2–8 is one row that says it was issued, with every source", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = lineageSession();
    await start(t, fs, session);
    const importer = pipelineImporter(t);
    const cp = await runCollection({ fs, session, importer, sources: SOURCES, now }, t.dir, {
      resume: false,
    });
    expect(cp.status).toBe("complete");
    expect(importer.imports.filter((l) => l.includes("/p0"))).toHaveLength(8);
    expect(importer.summaries).toEqual(["evidence/cloud/cc-test-abc123/summary-aws"]);
    const { forensic } = await lineageRows(t);
    expect(forensic).toHaveLength(1);
    const [row] = forensic;
    expect(row.description).toContain(`AWS credential lineage: ${LINEAGE_KEY}`);
    expect(row.description).toContain("issued 2026-10-01T09:00:00.000Z by AssumeRole");
    expect(row.description).not.toContain("no issuance record");
    expect(row.description).toMatch(/issuance and 7 uses in this collection\]$/);
    expect(row.description).toContain("203.0.113.5");
    expect(row.description).toContain("198.51.100.7");
    expect(row.sourceScreenshots).toEqual(["evidence/cloud/cc-test-abc123/summary-aws"]);
    expect(row.canonical?.awsLineage?.basis).toMatch(/^records of this collection only \(8 pages;/);
    expect(cp.summarized).toEqual({ aws: 8 });
    const state = await t.stateStore.load("c1");
    expect(
      state.timeline.some((e) =>
        /AWS CloudTrail collection summary over 8 record\(s\) of 8 page\(s\)/.test(e.description ?? ""),
      ),
    ).toBe(true);
  });

  it("Resume after a partial run rebuilds the one row over every page — no second row, the super copy follows", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = lineageSession();
    await start(t, fs, session);
    let pages = 0;
    fs.inject(
      "writeFileSync",
      (p) => p.endsWith(".json.tmp") && p.includes("pages") && ++pages === 5,
      diskFull,
    );
    const first = await runCollection(
      { fs, session, importer: pipelineImporter(t), sources: SOURCES, now },
      t.dir,
      { resume: false },
    );
    expect(first.status).toBe("partial");
    expect(first.summarized).toEqual({ aws: 4 });
    const before = await lineageRows(t);
    expect(before.forensic).toHaveLength(1);
    expect(before.forensic[0].description).toMatch(/issuance and 3 uses in this collection\]$/);
    expect(before.super).toHaveLength(1);

    fs.clear();
    const resumed = await runCollection(
      { fs, session, importer: pipelineImporter(t), sources: SOURCES, now },
      t.dir,
      { resume: true },
    );
    expect(resumed.status).toBe("complete");
    expect(resumed.summarized).toEqual({ aws: 8 });
    const after = await lineageRows(t);
    expect(after.forensic).toHaveLength(1);
    expect(after.forensic[0].id).toBe(before.forensic[0].id);
    expect(after.forensic[0].description).toMatch(/issuance and 7 uses in this collection\]$/);
    expect(after.super).toHaveLength(1);
    expect(after.super[0].description).toMatch(/issuance and 7 uses in this collection\]$/);
  });

  it("a replay whose summary landed but was not checkpointed changes nothing", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = lineageSession();
    await start(t, fs, session);
    await runCollection({ fs, session, importer: pipelineImporter(t), sources: SOURCES, now }, t.dir, {
      resume: false,
    });
    const before = await lineageRows(t);
    // A crash between the summary's commit and its checkpoint: the checkpoint does not know it ran.
    const path = collectionPaths(t.dir).checkpoint;
    const cp = JSON.parse(await readFile(path, "utf8"));
    await writeFile(path, JSON.stringify({ ...cp, summarized: undefined, status: "interrupted" }));
    const replay = pipelineImporter(t);
    const again = await runCollection({ fs, session, importer: replay, sources: SOURCES, now }, t.dir, {
      resume: true,
    });
    expect(replay.summaries).toHaveLength(1);
    expect(again.summarized).toEqual({ aws: 8 });
    const after = await lineageRows(t);
    expect(after.forensic.map((e) => e.id)).toEqual(before.forensic.map((e) => e.id));
    expect(after.super).toHaveLength(1);
  });

  it("a collection past the summary window says how much the summaries cover", async () => {
    const t = await tempCase();
    const write = async (name: string, recs: Record<string, unknown>[]) => {
      const path = join(t.root, name);
      await writeFile(path, JSON.stringify({ Records: recs }));
      return { path, records: recs.length };
    };
    const pages = [
      await write("p1.json", [lineageIssuance(0), lineageUse(1)]),
      await write("p2.json", [lineageUse(2), lineageUse(3)]),
    ];
    const r = await t.pipeline.importCloudCollectionSummary("c1", "aws", pages, {
      collectionId: "cc-x",
      label: "evidence/cloud/cc-x/summary-aws",
      idPrefix: "ccxsaws",
      importedAt: "2026-10-02T00:00:00Z",
      summaryRecords: 3,
    });
    expect(r).toMatchObject({ pages: 2, records: 4, windowRecords: 3, truncated: true, rows: 1 });
    expect(r.state.forensicTimeline.filter(isLineageRow)[0].description).toMatch(
      /issuance and 2 uses in this collection\]$/,
    );
    expect(
      r.state.timeline.some((e) =>
        (e.description ?? "").includes(
          "whole-collection summaries built over the first 3 of 4 records — later records are not in them",
        ),
      ),
    ).toBe(true);
  });

  it("a rebuild across the lineage and compute caps drops the rows it no longer emits, from both timelines", async () => {
    const t = await tempCase();
    const key = (k: number) => `ASIAEXAMPLEKEY${String(k).padStart(6, "0")}`;
    const inst = (k: number) => `i-${String(k).padStart(17, "0")}`;
    const n = AWS_LINEAGE_MAX; // 256, the same bound as the compute lifecycles
    // Page 1: exactly n Low lineages and n launches — every one reported, nothing omitted.
    const page1 = Array.from({ length: n }, (_, j) => {
      const k = j + 1;
      return [
        lineageIssuance(4 * k, key(k)),
        lineageUse(4 * k + 2, key(k)),
        computeLaunch(4 * k + 1, inst(k)),
      ];
    }).flat();
    // Page 2: a NEWER lineage (ranked above the oldest) and an EARLIER launch (ranked above the latest).
    const page2 = [
      lineageIssuance(4 * (n + 1), key(n + 1)),
      lineageUse(4 * (n + 1) + 2, key(n + 1)),
      computeLaunch(1, inst(n + 1)),
    ];
    const write = async (name: string, recs: Record<string, unknown>[]) => {
      const path = join(t.root, name);
      await writeFile(path, JSON.stringify({ Records: recs }));
      return { path, records: recs.length };
    };
    const pages = [await write("p1.json", page1), await write("p2.json", page2)];
    const label = "evidence/cloud/cc-cap/summary-aws";
    const build = async (upTo: number) => {
      const r = await t.pipeline.importCloudCollectionSummary("c1", "aws", pages.slice(0, upTo), {
        collectionId: "cc-cap",
        label,
        idPrefix: "cccapsaws",
        importedAt: "2026-10-02T00:00:00Z",
      });
      // What the production settle's dual-write does with the build's rows.
      await t.superTimelineStore.appendReporting(
        "c1",
        r.state.forensicTimeline.filter((e) => r.ids.includes(e.id)),
      );
      return r;
    };
    const both = async () => {
      const forensic = (await t.stateStore.load("c1")).forensicTimeline;
      const superRows = (await t.superTimelineStore.query("c1", { limit: 5000 })).events;
      return { forensic, super: superRows };
    };
    const first = await build(1);
    expect(first.rows).toBe(2 * n);
    const before = await both();
    for (const rows of [before.forensic, before.super]) {
      expect(rows.filter(isLineageRow)).toHaveLength(n);
      expect(rows.filter(isComputeRow)).toHaveLength(n);
    }
    expect(before.forensic.some((e) => e.description.includes(key(1)))).toBe(true);
    expect(before.forensic.some((e) => e.description.includes(inst(n)))).toBe(true);

    const second = await build(2);
    expect(second.rows).toBe(2 * n + 2); // n + an omitted row, twice
    const after = await both();
    for (const rows of [after.forensic, after.super]) {
      expect(rows.filter(isLineageRow)).toHaveLength(n + 1);
      expect(rows.filter(isComputeRow)).toHaveLength(n + 1);
      // The displaced rows are gone; the new ones are in.
      expect(rows.some((e) => isLineageRow(e) && e.description.includes(`lineage: ${key(1)} `))).toBe(false);
      expect(rows.some((e) => isComputeRow(e) && e.description.includes(`lifecycle: ${inst(n)} `))).toBe(
        false,
      );
      expect(rows.some((e) => e.description.includes(`lineage: ${key(n + 1)} `))).toBe(true);
      expect(rows.some((e) => e.description.includes(`lifecycle: ${inst(n + 1)} `))).toBe(true);
      expect(rows.filter((e) => e.description.includes("further credential"))).toHaveLength(1);
      expect(rows.filter((e) => e.description.includes("further instance"))).toHaveLength(1);
    }
    // Only this summary's rows: the second build kept exactly the ids it reports.
    const summaryIds = after.forensic.filter((e) => e.id.startsWith("cccapsaws")).map((e) => e.id);
    expect(new Set(summaryIds)).toEqual(new Set(second.ids));
  });

  it("a kind without per-collection summaries runs no summary step", async () => {
    const t = await tempCase();
    const fs = faultFs();
    const session = lineageSession(1);
    await start(t, fs, session, ["gd"]);
    const importer = pipelineImporter(t);
    const cp = await runCollection({ fs, session, importer, sources: GD_SOURCES, now }, t.dir, {
      resume: false,
    });
    expect(importer.summaries).toEqual([]);
    expect(cp.summarized ?? {}).toEqual({});
  });
});
