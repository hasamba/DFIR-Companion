// #2538: a live cloud collection is ONE Cloud Coverage row per (provider, scope), grown page by page,
// never one row per page. Per-page rows used to fill the 200-upload store and evict every manually
// uploaded export (and the collection's own early pages) with no disclosure.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  CloudCoverageStore,
  UPLOADS_TRACKED_PER_CASE_MAX,
  renderCloudCoverage,
  summarizeCloudCoverage,
  type CloudCoverageDraft,
  type CloudCoverageRecord,
  cloudCoverageRecordSchema,
} from "../../src/analysis/cloudCoverage.js";
import { describeCloudStreamDisclosure } from "../../src/analysis/cloudStreamDisclosure.js";
import { streamDisclosure } from "../helpers/cloudStreamDisclosureFixture.js";
import {
  collectionCoverageGroup,
  foldCollectionRecords,
  persistCollectionCoverage,
  persistImportCoverage,
} from "../../src/analysis/cloudCoverageFold.js";

const ACCOUNT = "111122223333";

const page = (over: Partial<CloudCoverageDraft> = {}): CloudCoverageDraft => ({
  provider: "aws-cloudtrail",
  scope: { kind: "account", value: ACCOUNT },
  uploadId: "page-text-hash",
  recordCount: 50,
  first: "2026-01-05T00:00:00.000Z",
  last: "2026-01-06T00:00:00.000Z",
  categories: [{ name: "Management", count: 50, readOnly: { true: 30, false: 20, unknown: 0 } }],
  ...over,
});

const manual = (
  uploadId: string,
  provider: CloudCoverageDraft["provider"],
  recordCount: number,
): CloudCoverageDraft => ({
  provider,
  scope: { kind: provider === "azure" ? "subscription" : "account", value: `${uploadId}-scope` },
  uploadId,
  recordCount,
  first: "2025-12-01T00:00:00.000Z",
  last: "2025-12-02T00:00:00.000Z",
  categories: [{ name: provider === "azure" ? "Administrative" : "Management", count: recordCount }],
});

describe("foldCollectionRecords (pure)", () => {
  it("three folds give one item per scope: counts summed, range widened, categories merged, pages counted", () => {
    const g = "collection:abc";
    const r1 = foldCollectionRecords([], g, [page()], "2026-02-01T00:00:00.000Z");
    const r2 = foldCollectionRecords(
      r1,
      g,
      [page({ first: "2026-01-01T00:00:00.000Z", last: "2026-01-02T00:00:00.000Z" })],
      "2026-02-02T00:00:00.000Z",
    );
    const r3 = foldCollectionRecords(
      r2,
      g,
      [
        page({
          recordCount: 7,
          first: "2026-01-09T00:00:00.000Z",
          last: "2026-01-31T00:00:00.000Z",
          categories: [
            { name: "Management", count: 5, readOnly: { true: 1, false: 3, unknown: 1 } },
            { name: "Data", count: 2 },
          ],
        }),
      ],
      "2026-02-03T00:00:00.000Z",
    );
    expect(r3).toHaveLength(1);
    const [row] = r3;
    expect(row.uploadId).toBe(g);
    expect(row.recordCount).toBe(107);
    expect(row.first).toBe("2026-01-01T00:00:00.000Z");
    expect(row.last).toBe("2026-01-31T00:00:00.000Z");
    expect(row.pages).toBe(3);
    expect(row.uploadFirstSeenAt).toBe("2026-02-01T00:00:00.000Z");
    expect(row.importedAt).toBe("2026-02-03T00:00:00.000Z");
    const mgmt = row.categories.find((c) => c.name === "Management");
    expect(mgmt).toEqual({ name: "Management", count: 105, readOnly: { true: 61, false: 43, unknown: 1 } });
    expect(row.categories.find((c) => c.name === "Data")?.count).toBe(2);
  });

  it("two scopes in one collection are two items under the one group id, with one page count", () => {
    const g = "collection:abc";
    const r1 = foldCollectionRecords([], g, [page()], "2026-02-01T00:00:00.000Z");
    const r2 = foldCollectionRecords(
      r1,
      g,
      [page({ scope: { kind: "account", value: "444455556666" } })],
      "2026-02-02T00:00:00.000Z",
    );
    expect(r2).toHaveLength(2);
    expect(r2.every((r) => r.uploadId === g)).toBe(true);
    // A scope first seen on page 2 says the collection's page count, not "1".
    expect(r2.map((r) => r.pages)).toEqual([2, 2]);
  });

  // #2546: replaces "disclosures are unioned without duplicates and stop at 24", which pinned the
  // defect — the row showed the first ~6 pages' per-page sentences beside a whole-collection total,
  // and a later page's cap sentence was silently dropped.
  it("a 200-page fold states one summed disclosure: its record count is the row total, page 150's cap is present", () => {
    const g = "collection:abc";
    let rows: CloudCoverageRecord[] = [];
    let duplicates = 0;
    let medium = 0;
    for (let i = 0; i < 200; i++) {
      const records = 50 + (i % 7);
      const dup = i % 3 === 0 ? 2 : 0;
      duplicates += dup;
      medium += 4 + (i % 2);
      const d = streamDisclosure({
        records,
        duplicates: dup,
        individual: { critical: 0, high: 1, medium: 4 + (i % 2) },
        superEvicted: i === 150 ? 999 : 0,
      });
      const draft = page({
        recordCount: records,
        importDisclosure: describeCloudStreamDisclosure(d),
        streamDisclosure: d,
      });
      rows = foldCollectionRecords(rows, g, [draft], "2026-02-01T00:00:00.000Z");
    }
    const [row] = rows;
    const d = row.importDisclosure ?? [];
    expect(d.filter((s) => s.startsWith("streamed from disk"))).toHaveLength(1);
    expect(d[0]).toBe(
      `streamed from disk: ${row.recordCount.toLocaleString("en-US")} record(s), cloudtrail-json`,
    );
    expect(d.filter((s) => s.startsWith("kept in detail"))).toEqual([
      `kept in detail: 0 Critical, 200 High, ${medium.toLocaleString("en-US")} Medium row(s)`,
    ]);
    expect(d).toContain("the super-timeline cap evicted 999 older row(s)");
    expect(d).toContain(`${duplicates} duplicate record(s) skipped`);
    expect(row.streamDisclosure?.records).toBe(row.recordCount);
  });

  it("a row stored before #2546 (strings, no sum) is replaced by the new page's sum and still parses", () => {
    const g = "collection:abc";
    const legacy: CloudCoverageRecord = {
      ...page({
        uploadId: g,
        importDisclosure: ["streamed from disk: 50 record(s), cloudtrail-json", "old page 2"],
      }),
      uploadFirstSeenAt: "2026-01-01T00:00:00.000Z",
      importedAt: "2026-01-01T00:00:00.000Z",
      pages: 2,
    };
    expect(cloudCoverageRecordSchema.safeParse(legacy).success).toBe(true);
    const d = streamDisclosure({ records: 7 });
    const draft = page({
      recordCount: 7,
      importDisclosure: describeCloudStreamDisclosure(d),
      streamDisclosure: d,
    });
    const [row] = foldCollectionRecords([legacy], g, [draft], "2026-02-01T00:00:00.000Z");
    expect(row.importDisclosure).toEqual(describeCloudStreamDisclosure(d));
    expect(row.streamDisclosure).toEqual(d);
    expect(row.pages).toBe(3);
    expect(cloudCoverageRecordSchema.safeParse(row).success).toBe(true);
  });

  it("two scopes on one page carry the page's sum once, not once per scope", () => {
    const d = streamDisclosure({ records: 10 });
    const rows = foldCollectionRecords(
      [],
      "collection:abc",
      [
        page({ streamDisclosure: d }),
        page({ scope: { kind: "account", value: "444455556666" }, streamDisclosure: d }),
      ],
      "2026-02-01T00:00:00.000Z",
    );
    expect(rows.map((r) => r.streamDisclosure?.records)).toEqual([10, 10]);
  });

  it("never mutates its inputs", () => {
    const existing = foldCollectionRecords([], "collection:abc", [page()], "2026-02-01T00:00:00.000Z");
    const snapshotExisting = JSON.stringify(existing);
    const drafts = [page({ recordCount: 3 })];
    const snapshotDrafts = JSON.stringify(drafts);
    foldCollectionRecords(existing, "collection:abc", drafts, "2026-02-02T00:00:00.000Z");
    expect(JSON.stringify(existing)).toBe(snapshotExisting);
    expect(JSON.stringify(drafts)).toBe(snapshotDrafts);
  });
});

describe("persistCollectionCoverage (store)", () => {
  let store: CloudCoverageStore;
  beforeEach(async () => {
    const cases = new CaseStore(await mkdtemp(join(tmpdir(), "cov-fold-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new CloudCoverageStore(cases);
  });

  it("2 manual uploads + 201 collection pages: the manual uploads stay, the collection is one row", async () => {
    await store.record("c1", [manual("manual-azure", "azure", 40)], "2026-01-01T00:00:00.000Z");
    await store.record("c1", [manual("manual-ct", "aws-cloudtrail", 9000)], "2026-01-01T00:00:01.000Z");
    const group = collectionCoverageGroup("cc-1");
    for (let i = 0; i < 201; i++) {
      // Out of order, so the row's range proves widening rather than "last page wins".
      const day = String(((i * 11) % 28) + 1).padStart(2, "0");
      await persistCollectionCoverage(store, "c1", group, [
        page({ first: `2026-03-${day}T00:00:00.000Z`, last: `2026-03-${day}T12:00:00.000Z` }),
      ]);
    }
    const records = await store.load("c1");
    const ids = new Set(records.map((r) => r.uploadId));
    expect(ids).toEqual(new Set(["manual-azure", "manual-ct", "collection:cc-1"]));
    const col = records.filter((r) => r.uploadId === "collection:cc-1");
    expect(col).toHaveLength(1);
    expect(col[0].pages).toBe(201);
    expect(col[0].recordCount).toBe(201 * 50);
    expect(col[0].first).toBe("2026-03-01T00:00:00.000Z");
    expect(col[0].last).toBe("2026-03-28T12:00:00.000Z");
  });

  it("the AI coverage block lists the collection on one line beside the manual uploads", async () => {
    await store.record("c1", [manual("manual-azure", "azure", 40)], "2026-01-01T00:00:00.000Z");
    await store.record("c1", [manual("manual-ct", "aws-cloudtrail", 9000)], "2026-01-01T00:00:01.000Z");
    for (let i = 0; i < 12; i++)
      await persistCollectionCoverage(store, "c1", collectionCoverageGroup("cc-1"), [page()]);
    const text = renderCloudCoverage(
      summarizeCloudCoverage(await store.load("c1"), await store.loadEverSeen("c1")),
      10,
    );
    const lines = text.split("\n");
    expect(lines.filter((l) => l.includes(`account ${ACCOUNT}`))).toHaveLength(1);
    expect(lines.find((l) => l.includes(`account ${ACCOUNT}`))).toContain(
      "600 records across 12 collected pages",
    );
    expect(lines.some((l) => l.startsWith("Azure — subscription manual-azure-scope"))).toBe(true);
    expect(lines.some((l) => l.includes("account manual-ct-scope: 9,000 records ("))).toBe(true);
    expect(text).not.toContain("further upload");
  });

  it("201 distinct collections still evict the oldest collection whole: the cap holds", async () => {
    for (let i = 0; i <= UPLOADS_TRACKED_PER_CASE_MAX; i++) {
      await persistCollectionCoverage(store, "c1", collectionCoverageGroup(`cc-${i}`), [
        page(),
        page({ scope: { kind: "account", value: "444455556666" } }),
      ]);
    }
    const records = await store.load("c1");
    const ids = new Set(records.map((r) => r.uploadId));
    expect(ids.size).toBe(UPLOADS_TRACKED_PER_CASE_MAX);
    expect(ids.has("collection:cc-0")).toBe(false);
    expect(records).toHaveLength(UPLOADS_TRACKED_PER_CASE_MAX * 2);
  });

  it("a category seen only in a folded page reaches the ever-seen registry", async () => {
    await persistCollectionCoverage(store, "c1", "collection:cc-1", [
      page({ categories: [{ name: "Insight", count: 1 }] }),
    ]);
    expect((await store.loadEverSeen("c1"))["aws-cloudtrail"]).toContain("Insight");
  });

  it("a manual re-import with no group still replaces its own row in place", async () => {
    await persistImportCoverage(store, "c1", [manual("manual-ct", "aws-cloudtrail", 10)]);
    await persistImportCoverage(store, "c1", [manual("manual-ct", "aws-cloudtrail", 12)]);
    const records = await store.load("c1");
    expect(records).toHaveLength(1);
    expect(records[0].recordCount).toBe(12);
    expect(records[0].pages).toBeUndefined();
  });

  it("a manual upload never stores the running sum: it is a collection row's field only (#2546)", async () => {
    const draft = { ...manual("manual-ct", "aws-cloudtrail", 10), streamDisclosure: streamDisclosure() };
    await persistImportCoverage(store, "c1", [draft]);
    const records = await store.load("c1");
    expect(records).toHaveLength(1);
    expect(records[0].streamDisclosure).toBeUndefined();
  });

  it("with a group, persistImportCoverage folds; empty coverage writes nothing", async () => {
    await persistImportCoverage(store, "c1", [], "collection:cc-1");
    expect(await store.load("c1")).toEqual([]);
    await persistImportCoverage(store, "c1", [page()], "collection:cc-1");
    await persistImportCoverage(store, "c1", [page({ uploadId: "another-hash" })], "collection:cc-1");
    const records = await store.load("c1");
    expect(records).toHaveLength(1);
    expect(records[0].pages).toBe(2);
  });

  it("is best-effort: a failing store never throws into the import", async () => {
    const broken = {
      replaceGroup: async () => {
        throw new Error("disk gone");
      },
    } as unknown as CloudCoverageStore;
    await expect(persistCollectionCoverage(broken, "c1", "collection:x", [page()])).resolves.toBeUndefined();
  });
});
