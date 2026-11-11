// #2546: a live collection's Cloud Coverage row states ONE summed disclosure for the whole
// collection, so the per-page disclosures are summed as numbers before they become sentences.
import { describe, it, expect } from "vitest";
import {
  cloudStreamDisclosureSchema,
  sumCloudStreamDisclosure,
} from "../../src/analysis/cloudStreamDisclosure.js";
import { streamDisclosure } from "../helpers/cloudStreamDisclosureFixture.js";

describe("sumCloudStreamDisclosure (#2546)", () => {
  it("adds counts, ORs booleans and keeps the latest page's budgets", () => {
    const a = streamDisclosure({
      records: 50,
      duplicates: 2,
      superEvicted: 0,
      gzip: false,
      summaryWindow: { max: 100, records: 50, truncated: false },
      budgets: { ...streamDisclosure().budgets, mediumMax: 400 },
    });
    const b = streamDisclosure({
      records: 51,
      duplicates: 0,
      superEvicted: 999,
      gzip: true,
      sprayHistoryTruncated: true,
      individual: { critical: 1, high: 2, medium: 3 },
      summaryWindow: { max: 200, records: 51, truncated: true },
      iocsMax: 7000,
    });
    const s = sumCloudStreamDisclosure(a, b);
    expect(s.records).toBe(101);
    expect(s.duplicates).toBe(2);
    expect(s.superEvicted).toBe(999);
    expect(s.superWritten).toBe(80);
    expect(s.gzip).toBe(true);
    expect(s.sprayHistoryTruncated).toBe(true);
    expect(s.individual).toEqual({ critical: 1, high: 3, medium: 7 });
    expect(s.aggregatedRows).toEqual({ medium: 0, low: 20, info: 60 });
    expect(s.groups).toEqual({ detailed: 6, coarse: 0, catchAll: 0 });
    expect(s.summaryWindow).toEqual({ max: 200, records: 101, truncated: true });
    expect(s.budgets.mediumMax).toBe(500);
    expect(s.iocsMax).toBe(7000);
    expect(cloudStreamDisclosureSchema.safeParse(s).success).toBe(true);
  });

  it("unions distinct formats and stays within the schema's length bound", () => {
    const s1 = sumCloudStreamDisclosure(streamDisclosure(), streamDisclosure({ format: "cloudtrail-json" }));
    expect(s1.format).toBe("cloudtrail-json");
    const s2 = sumCloudStreamDisclosure(s1, streamDisclosure({ format: "jsonl" }));
    expect(s2.format).toBe("cloudtrail-json+jsonl");
    const s3 = sumCloudStreamDisclosure(s2, streamDisclosure({ format: "a-very-long-format-name-here" }));
    expect(s3.format.length).toBeLessThanOrEqual(40);
    expect(cloudStreamDisclosureSchema.safeParse(s3).success).toBe(true);
  });

  it("treats optional fields missing from older stored shapes (pre-#2481/#2502) as 0", () => {
    const old = streamDisclosure({
      mediumMerged: undefined,
      failedReads: undefined,
      mediumOverflow: { ruleActorBudget: 1, importBudget: 2 },
    });
    const s = sumCloudStreamDisclosure(
      old,
      streamDisclosure({
        mediumMerged: 3,
        failedReads: { folded: 4, toSuper: 1 },
        mediumOverflow: { ruleActorBudget: 0, importBudget: 0, failedReadBudget: 6 },
      }),
    );
    expect(s.mediumMerged).toBe(3);
    expect(s.failedReads).toEqual({ folded: 4, toSuper: 1 });
    expect(s.mediumOverflow).toEqual({ ruleActorBudget: 1, importBudget: 2, failedReadBudget: 6 });
  });

  it("never mutates its inputs", () => {
    const a = streamDisclosure({ records: 5 });
    const b = streamDisclosure({ records: 7, superEvicted: 3 });
    const sa = JSON.stringify(a);
    const sb = JSON.stringify(b);
    sumCloudStreamDisclosure(a, b);
    expect(JSON.stringify(a)).toBe(sa);
    expect(JSON.stringify(b)).toBe(sb);
  });
});
