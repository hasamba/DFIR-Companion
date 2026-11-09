import { describe, it, expect } from "vitest";
import { parseRun } from "../../../scripts/bench-collect-import.js";

// #2478 — the collection import-stage benchmark sizes its runs from the providers' real page sizes.

describe("bench-collect-import parseRun", () => {
  it("sizes an AWS run in LookupEvents' 50-record pages", () => {
    expect(parseRun("aws-100k")).toEqual({ name: "aws-100k", provider: "aws", perPage: 50, pages: 2000 });
  });

  it("sizes a GCP run in entries.list's 1,000-entry pages", () => {
    expect(parseRun("gcp-100k")).toEqual({ name: "gcp-100k", provider: "gcp", perPage: 1000, pages: 100 });
  });

  it("refuses a run name it does not know", () => {
    expect(() => parseRun("azure-100k")).toThrow(/unknown run/);
    expect(() => parseRun("aws-100")).toThrow(/unknown run/);
  });
});
