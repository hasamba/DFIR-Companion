import { describe, it } from "vitest";
import { checkRow } from "./harness.js";
import { rowsFor } from "./matrix.js";

// AWS CloudTrail: an S3 object decompressed and as downloaded (.json.gz), and the console CSV
// (synthetic fixtures — see matrix.ts). The gzip is built here from the JSON fixture.
describe("cloud compat — AWS CloudTrail (#2300)", () => {
  it.each(rowsFor("AWS CloudTrail").map((r) => [r.output, r] as const))("%s", async (_o, row) => {
    await checkRow(row);
  });
});
