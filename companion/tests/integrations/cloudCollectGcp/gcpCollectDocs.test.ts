import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { gcpAuditFilter, GCP_AUDIT_LOGS } from "../../../src/integrations/cloudCollectGcp/gcpFilter.js";
import { SINK_LATE_SHARD_MS } from "../../../src/integrations/cloudCollectGcp/gcpSink.js";

// #2314: the manual's GCP section states what the collector actually does.

const docs = readFileSync(
  new URL("../../../../mkdocs-docs/reference/cloud-collection.md", import.meta.url),
  "utf8",
).replace(/\r\n/g, "\n"); // Windows CI checks the docs out with CRLF

const section = docs.slice(docs.indexOf("## Collect GCP audit logs"));

describe("cloud-collection.md — Collect GCP audit logs", () => {
  it("exists and publishes the exact filter the collector sends", () => {
    expect(docs).toContain("## Collect GCP audit logs");
    const filter = gcpAuditFilter("<p>", { start: "<start>", end: "<end>" }, GCP_AUDIT_LOGS);
    expect(section).toContain(filter);
  });

  it("names the roles, the sink checks and the late-shard settle delay", () => {
    for (const role of [
      "roles/logging.viewer",
      "roles/logging.privateLogViewer",
      "roles/storage.objectViewer",
    ])
      expect(section).toContain(role);
    expect(section).toContain("**three hours**");
    expect(SINK_LATE_SHARD_MS).toBe(3 * 3_600_000);
    expect(section).toMatch(/Data Access logs are off\s+by default/);
    expect(section).toContain("**24 hours**");
  });
});
