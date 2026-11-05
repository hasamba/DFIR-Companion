import { describe, it } from "vitest";
import { checkRow } from "./harness.js";
import { rowsFor } from "./matrix.js";

// GCP Cloud Audit Logs: `gcloud logging read --format=json` and a GCS sink object (synthetic
// fixtures — see matrix.ts).
describe("cloud compat — GCP Cloud Audit Logs (#2300)", () => {
  it.each(rowsFor("GCP Cloud Audit Logs").map((r) => [r.output, r] as const))("%s", async (_o, row) => {
    await checkRow(row);
  });
});
