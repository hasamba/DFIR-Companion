// #1063: the cloud-coverage AI block — capped by item count (DFIR_SYNTH_CLOUD_COVERAGE_MAX),
// never token-trimmed; degrades to "" when the store is absent or fails, like every other
// optional block in promptBlocks.ts.
import { describe, it, expect, afterEach } from "vitest";
import {
  cloudCoverageBlock,
  cloudCoverageForCase,
  type PromptBlockContext,
} from "../../../src/analysis/ai/promptBlocks.js";
import type { CloudCoverageRecord, CloudCoverageStore } from "../../../src/analysis/cloudCoverage.js";

const fakeStore = (load: () => Promise<CloudCoverageRecord[]>): CloudCoverageStore =>
  ({ load, loadEverSeen: async () => ({}) }) as unknown as CloudCoverageStore;

const rec = (value: string): CloudCoverageRecord => ({
  provider: "aws-cloudtrail",
  scope: { kind: "account", value },
  uploadId: `u-${value}`,
  uploadFirstSeenAt: "2026-01-01T00:00:00.000Z",
  recordCount: 5,
  first: "2026-01-01T00:00:00.000Z",
  last: "2026-01-02T00:00:00.000Z",
  categories: [{ name: "Management", count: 5 }],
  importedAt: "2026-01-01T00:00:00.000Z",
});

function ctxWith(records: CloudCoverageRecord[]): PromptBlockContext {
  return {
    opts: { cloudCoverageStore: fakeStore(async () => records) },
  } as PromptBlockContext;
}

afterEach(() => {
  delete process.env.DFIR_SYNTH_CLOUD_COVERAGE_MAX;
});

describe("cloudCoverageBlock", () => {
  it("returns an empty string when no store is configured", async () => {
    const ctx = { opts: {} } as PromptBlockContext;
    expect(await cloudCoverageBlock(ctx, "c1")).toBe("");
  });

  it("returns an empty string when the store throws (defensive — never breaks synthesis)", async () => {
    const ctx = {
      opts: {
        cloudCoverageStore: fakeStore(async () => {
          throw new Error("disk error");
        }),
      },
    } as PromptBlockContext;
    expect(await cloudCoverageBlock(ctx, "c1")).toBe("");
  });

  it("caps rendered items by DFIR_SYNTH_CLOUD_COVERAGE_MAX, not by token size", async () => {
    const records = Array.from({ length: 5 }, (_, i) => rec(`acct${i}`));
    process.env.DFIR_SYNTH_CLOUD_COVERAGE_MAX = "2";
    const text = await cloudCoverageBlock(ctxWith(records), "c1");
    expect(text.split("\n").filter((l) => l.startsWith("AWS CloudTrail"))).toHaveLength(2);
    expect(text).toContain("+3 further uploads not shown");
  });

  it("DFIR_SYNTH_CLOUD_COVERAGE_MAX=0 disables the block", async () => {
    process.env.DFIR_SYNTH_CLOUD_COVERAGE_MAX = "0";
    expect(await cloudCoverageBlock(ctxWith([rec("a")]), "c1")).toBe("");
  });
});

describe("cloudCoverageForCase", () => {
  it("is the same structured summary the block renders from (one source, two callers)", async () => {
    const ctx = ctxWith([rec("111111111111")]);
    const summary = await cloudCoverageForCase(ctx, "c1");
    expect(summary.items).toHaveLength(1);
    expect(summary.items[0].scope.value).toBe("111111111111");
  });
});
