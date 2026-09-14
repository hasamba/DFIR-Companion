// #1063 (931.14 coverage half, part B): the per-upload cloud coverage store. Eviction is at
// UPLOAD granularity, never per scope record — a large multi-scope upload must never silently
// starve unrelated uploads, and re-importing one upload must never move its age or evict others.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  CloudCoverageStore,
  SCOPES_PER_UPLOAD_MAX,
  UPLOADS_TRACKED_PER_CASE_MAX,
  summarizeCloudCoverage,
  renderCloudCoverage,
  type CloudCoverageDraft,
  type CloudCoverageRecord,
} from "../../src/analysis/cloudCoverage.js";

const rec = (over: Partial<CloudCoverageRecord>): CloudCoverageRecord => ({
  provider: "aws-cloudtrail",
  scope: { kind: "account", value: "111111111111" },
  uploadId: "u1",
  uploadFirstSeenAt: "2026-01-01T00:00:00.000Z",
  recordCount: 10,
  first: "2026-01-01T00:00:00.000Z",
  last: "2026-01-02T00:00:00.000Z",
  categories: [{ name: "Management", count: 10 }],
  importedAt: "2026-01-01T00:00:00.000Z",
  ...over,
});

const draft = (value: string, categories = 1): CloudCoverageDraft => ({
  provider: "aws-cloudtrail",
  scope: { kind: "account", value },
  uploadId: `upload-${value}`,
  recordCount: 10,
  first: "2026-01-01T00:00:00.000Z",
  last: "2026-01-02T00:00:00.000Z",
  categories: Array.from({ length: categories }, (_, i) => ({ name: `cat${i}`, count: 1 })),
});

describe("CloudCoverageStore", () => {
  let store: CloudCoverageStore;
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-cloudcoverage-"));
    const cases = new CaseStore(root);
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    store = new CloudCoverageStore(cases);
  });

  it("returns an empty list when none exists", async () => {
    expect(await store.load("c1")).toEqual([]);
  });

  it("records one upload's drafts, stamping uploadFirstSeenAt and importedAt", async () => {
    const d = draft("111111111111");
    const result = await store.record("c1", [d], "2026-01-05T00:00:00.000Z");
    expect(result).toHaveLength(1);
    expect(result[0].uploadFirstSeenAt).toBe("2026-01-05T00:00:00.000Z");
    expect(result[0].importedAt).toBe("2026-01-05T00:00:00.000Z");
  });

  it("re-importing the SAME upload replaces its records in place, preserving the original uploadFirstSeenAt", async () => {
    const d = draft("111111111111");
    await store.record("c1", [d], "2026-01-05T00:00:00.000Z");
    const updated = { ...d, recordCount: 99 };
    const result = await store.record("c1", [updated], "2026-01-06T00:00:00.000Z");
    expect(result).toHaveLength(1);
    expect(result[0].recordCount).toBe(99);
    expect(result[0].uploadFirstSeenAt).toBe("2026-01-05T00:00:00.000Z");
    expect(result[0].importedAt).toBe("2026-01-06T00:00:00.000Z");
  });

  it("an upload's own coverage is truncated to SCOPES_PER_UPLOAD_MAX", async () => {
    const drafts = Array.from({ length: SCOPES_PER_UPLOAD_MAX + 10 }, (_, i) => ({
      ...draft(`acct-${i}`),
      uploadId: "one-big-upload",
    }));
    const result = await store.record("c1", drafts);
    expect(result).toHaveLength(SCOPES_PER_UPLOAD_MAX);
  });

  it("a new upload past the tracked-uploads bound evicts the single oldest upload's ENTIRE record set atomically", async () => {
    let t = Date.parse("2026-01-01T00:00:00.000Z");
    const at = () => new Date(t++).toISOString();
    for (let i = 0; i < UPLOADS_TRACKED_PER_CASE_MAX; i++) {
      await store.record("c1", [{ ...draft(`acct-${i}`), uploadId: `upload-${i}` }], at());
    }
    let list = await store.load("c1");
    expect(new Set(list.map((r) => r.uploadId)).size).toBe(UPLOADS_TRACKED_PER_CASE_MAX);

    // One more upload -> the OLDEST (upload-0) is evicted completely, everyone else untouched.
    await store.record("c1", [{ ...draft("acct-new"), uploadId: "upload-new" }], at());
    list = await store.load("c1");
    const ids = new Set(list.map((r) => r.uploadId));
    expect(ids.size).toBe(UPLOADS_TRACKED_PER_CASE_MAX);
    expect(ids.has("upload-0")).toBe(false);
    expect(ids.has("upload-1")).toBe(true);
    expect(ids.has("upload-new")).toBe(true);
  });

  it("re-importing an already-tracked upload never evicts anything, even at the bound", async () => {
    let t = Date.parse("2026-01-01T00:00:00.000Z");
    const at = () => new Date(t++).toISOString();
    for (let i = 0; i < UPLOADS_TRACKED_PER_CASE_MAX; i++) {
      await store.record("c1", [{ ...draft(`acct-${i}`), uploadId: `upload-${i}` }], at());
    }
    // Re-import upload-0 (the oldest) repeatedly — it must never move to the back and never evict
    // anything, since it adds no new upload group.
    for (let n = 0; n < 5; n++) {
      await store.record("c1", [{ ...draft("acct-0"), uploadId: "upload-0", recordCount: 100 + n }], at());
    }
    const list = await store.load("c1");
    const ids = new Set(list.map((r) => r.uploadId));
    expect(ids.size).toBe(UPLOADS_TRACKED_PER_CASE_MAX);
    expect(ids.has("upload-0")).toBe(true);
    const upload0 = list.find((r) => r.uploadId === "upload-0")!;
    expect(upload0.uploadFirstSeenAt).toBe(new Date(Date.parse("2026-01-01T00:00:00.000Z")).toISOString());
    expect(upload0.recordCount).toBe(104);
  });

  it("two different scopes of ONE upload are two records, and both are replaced together on re-import", async () => {
    const a = { ...draft("acct-a"), uploadId: "multi-scope-upload" };
    const b = { ...draft("acct-b"), uploadId: "multi-scope-upload" };
    const first = await store.record("c1", [a, b]);
    expect(first).toHaveLength(2);
    const second = await store.record("c1", [a]);
    expect(second).toHaveLength(1);
  });

  it("a mixed-provider upload (one call, two providers, same uploadId) is one eviction slot, never split", async () => {
    let t = Date.parse("2026-01-01T00:00:00.000Z");
    const at = () => new Date(t++).toISOString();
    // One physical upload carrying BOTH a gcp row and an azure row under the same uploadId.
    await store.record(
      "c1",
      [
        { ...draft("proj-a"), provider: "gcp", uploadId: "mixed-upload" },
        { ...draft("sub-a"), provider: "azure", uploadId: "mixed-upload" },
      ],
      at(),
    );
    for (let i = 0; i < UPLOADS_TRACKED_PER_CASE_MAX - 1; i++) {
      await store.record("c1", [{ ...draft(`acct-${i}`), uploadId: `upload-${i}` }], at());
    }
    let list = await store.load("c1");
    expect(new Set(list.map((r) => r.uploadId)).size).toBe(UPLOADS_TRACKED_PER_CASE_MAX);
    expect(list.some((r) => r.uploadId === "mixed-upload" && r.provider === "gcp")).toBe(true);
    expect(list.some((r) => r.uploadId === "mixed-upload" && r.provider === "azure")).toBe(true);

    // One more NEW upload pushes past the bound -> "mixed-upload" (the oldest) is evicted WHOLE,
    // both its gcp and azure rows together, never just one half.
    await store.record("c1", [{ ...draft("acct-new"), uploadId: "upload-new" }], at());
    list = await store.load("c1");
    expect(list.some((r) => r.uploadId === "mixed-upload")).toBe(false);
    expect(list.some((r) => r.uploadId === "upload-new")).toBe(true);
  });

  it("loadEverSeen accumulates category names per provider and never shrinks on eviction", async () => {
    let t = Date.parse("2026-01-01T00:00:00.000Z");
    const at = () => new Date(t++).toISOString();
    await store.record(
      "c1",
      [
        {
          ...draft("acct-data", 1),
          provider: "aws-cloudtrail",
          uploadId: "upload-data",
          categories: [{ name: "Data", count: 1 }],
        },
      ],
      at(),
    );
    for (let i = 0; i < UPLOADS_TRACKED_PER_CASE_MAX; i++) {
      await store.record("c1", [{ ...draft(`acct-${i}`), uploadId: `upload-${i}` }], at());
    }
    // "upload-data" (the oldest) is now evicted from the retained records...
    const list = await store.load("c1");
    expect(list.some((r) => r.uploadId === "upload-data")).toBe(false);
    // ...but the "Data" category it carried is still remembered for the provider.
    const everSeen = await store.loadEverSeen("c1");
    expect(everSeen["aws-cloudtrail"]).toContain("Data");
  });
});

describe("summarizeCloudCoverage — read-time caveats", () => {
  it("states a caveat for every AWS documented category absent across ALL the case's CloudTrail records", () => {
    const summary = summarizeCloudCoverage([rec({ categories: [{ name: "Management", count: 10 }] })]);
    expect(summary.caveats.some((c) => c.includes("no Data-category records"))).toBe(true);
    expect(summary.caveats.some((c) => c.includes("no Insight-category records"))).toBe(true);
    expect(summary.caveats.some((c) => c.includes("no Management-category records"))).toBe(false);
  });

  it("a category present in ANY upload of the case suppresses that caveat, even if absent from another upload", () => {
    const summary = summarizeCloudCoverage([
      rec({ uploadId: "u1", categories: [{ name: "Management", count: 10 }] }),
      rec({ uploadId: "u2", categories: [{ name: "Data", count: 5 }] }),
    ]);
    expect(summary.caveats.some((c) => c.includes("no Data-category records"))).toBe(false);
  });

  it("a category recorded in the everSeen registry suppresses its caveat even with no matching CURRENT record (post-eviction honesty)", () => {
    // The upload that carried "Data" has since been evicted -- no aws-cloudtrail record here
    // carries it -- but the registry still remembers it was once seen.
    const summary = summarizeCloudCoverage([rec({ categories: [{ name: "Management", count: 10 }] })], {
      "aws-cloudtrail": ["Data"],
    });
    expect(summary.caveats.some((c) => c.includes("no Data-category records"))).toBe(false);
    expect(summary.caveats.some((c) => c.includes("no Insight-category records"))).toBe(true);
  });

  it("everSeen alone (no current record for that provider) still gates the provider's caveats on", () => {
    const summary = summarizeCloudCoverage([], { gcp: ["activity"] });
    expect(summary.caveats.some((c) => c.includes("no data_access-category records"))).toBe(true);
    expect(summary.caveats.some((c) => c.includes("no activity-category records"))).toBe(false);
  });

  it("Google Workspace always states the anonymous-views caveat, unconditionally", () => {
    const summary = summarizeCloudCoverage([
      rec({
        provider: "google-workspace",
        scope: { kind: "tenant", value: "C1" },
        categories: [{ name: "drive", count: 5 }],
      }),
    ]);
    expect(summary.caveats).toEqual(["anonymous views are not logged; anonymous edits and downloads are"]);
  });

  it("items are sorted deterministically: provider asc, then record count desc, then scope value asc", () => {
    const summary = summarizeCloudCoverage([
      rec({ provider: "gcp", scope: { kind: "project", value: "b" }, recordCount: 5, categories: [] }),
      rec({
        provider: "aws-cloudtrail",
        scope: { kind: "account", value: "z" },
        recordCount: 1,
        categories: [],
      }),
      rec({
        provider: "aws-cloudtrail",
        scope: { kind: "account", value: "a" },
        recordCount: 100,
        categories: [],
      }),
    ]);
    expect(summary.items.map((i) => `${i.provider}:${i.scope.value}`)).toEqual([
      "aws-cloudtrail:a",
      "aws-cloudtrail:z",
      "gcp:b",
    ]);
  });

  it("renderCloudCoverage caps by item count and states the overflow, never token-trims", () => {
    const records = Array.from({ length: 5 }, (_, i) =>
      rec({ uploadId: `u${i}`, scope: { kind: "account", value: `acct${i}` } }),
    );
    const summary = summarizeCloudCoverage(records);
    const text = renderCloudCoverage(summary, 2);
    expect(text.split("\n").filter((l) => l.startsWith("AWS CloudTrail"))).toHaveLength(2);
    expect(text).toContain("+3 further uploads not shown");
  });

  it("renderCloudCoverage with max 0 or no items returns an empty string", () => {
    expect(renderCloudCoverage(summarizeCloudCoverage([rec({})]), 0)).toBe("");
    expect(renderCloudCoverage(summarizeCloudCoverage([]), 10)).toBe("");
  });
});
