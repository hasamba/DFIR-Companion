import { describe, expect, it } from "vitest";
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tempCase } from "../../helpers/cloudCollectFakes.js";
import { detectImportKind } from "../../../src/analysis/importDetect.js";
import { extractRecords } from "../../../src/analysis/siemImport.js";
import { gcpAuditEntry } from "./gcpCollectMocks.js";

// #2314: a Logging entries:list response is saved byte for byte — {"entries":[…],"nextPageToken"} —
// and must import through the existing GCP importer (#2303 streaming, kind "cloud") as it is.

async function importBody(body: string) {
  const t = await tempCase();
  await mkdir(t.dir, { recursive: true });
  const path = join(t.dir, "page.json");
  await writeFile(path, body);
  const { disclosure } = await t.pipeline.importCloudFile("c1", "cloud", path, {
    label: "evidence/cloud/cc-test-abc123/page.json",
    idPrefix: "ccgcp",
    importedAt: "2026-11-02T00:00:00.000Z",
  });
  const state = await t.stateStore.load("c1");
  const superMeta = await t.superTimelineStore.meta("c1");
  return { state, superRows: superMeta.rows, disclosure };
}

describe("an entries:list page imports through the GCP importer", () => {
  it("reads the records inside the entries wrapper and grades them with the existing rules", async () => {
    const body = JSON.stringify({
      entries: [
        gcpAuditEntry(1, "google.iam.admin.v1.CreateServiceAccountKey"),
        gcpAuditEntry(2, "SetIamPolicy"),
        gcpAuditEntry(3, "google.logging.v2.ConfigServiceV2.DeleteSink"),
      ],
      nextPageToken: "opaque-token-1",
    });
    const { state, superRows } = await importBody(body);
    const graded = state.forensicTimeline.filter((e) => e.severity !== "Info");
    expect(graded.length).toBeGreaterThan(0);
    expect(state.forensicTimeline.length + superRows).toBeGreaterThanOrEqual(3);
    expect(JSON.stringify(state.forensicTimeline)).toContain("CreateServiceAccountKey");
  });

  it("imports an empty page ({} or a bare nextPageToken) as nothing, without failing", async () => {
    for (const body of ["{}", '{"nextPageToken":"opaque-token-2"}', '{"entries":[]}']) {
      const { state, superRows } = await importBody(body);
      expect(state.forensicTimeline.filter((e) => /gcp|google/i.test(JSON.stringify(e)))).toEqual([]);
      expect(superRows).toBe(0);
    }
  });

  it("imports a GCS sink object (JSON lines of LogEntry) as it is", async () => {
    const body = [
      gcpAuditEntry(4, "google.iam.admin.v1.CreateServiceAccountKey"),
      gcpAuditEntry(5, "SetIamPolicy"),
    ]
      .map((e) => JSON.stringify(e))
      .join("\n");
    const { state, superRows } = await importBody(body);
    expect(state.forensicTimeline.length + superRows).toBeGreaterThanOrEqual(2);
    expect(JSON.stringify(state.forensicTimeline)).toContain("CreateServiceAccountKey");
  });
});

describe("a saved entries:list page uploaded by hand", () => {
  it("is detected as the GCP importer's and its records are unwrapped", () => {
    const body = JSON.stringify({ entries: [gcpAuditEntry(1), gcpAuditEntry(2)], nextPageToken: "t" });
    expect(detectImportKind("p000001-gcp-audit.json", body)).toBe("cloud");
    expect(extractRecords(body).records).toHaveLength(2);
  });
});
