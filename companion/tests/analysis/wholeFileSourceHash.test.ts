import { describe, expect, it } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import { sourceArtifactHash } from "../../src/analysis/canonicalEvent.js";

// #2353 (a): whole-file M365 and Cloud Activity imports stamp the hash of the text they parsed on
// every canonical row, as whole-file CloudTrail and every streamed cloud import already do, so a
// Sigma re-grade can tell a stored file that changed since the import.

const ual = JSON.stringify([
  {
    Id: "u-1",
    CreationTime: "2026-03-01T10:00:00",
    Operation: "New-InboxRule",
    Workload: "Exchange",
    UserId: "alice@example.test",
    ClientIP: "198.51.100.7",
    OrganizationId: "t1",
    RecordType: 1,
  },
  {
    Id: "u-2",
    CreationTime: "2026-03-01T10:00:01",
    Operation: "MailItemsAccessed",
    Workload: "Exchange",
    UserId: "alice@example.test",
    ClientIP: "198.51.100.7",
    OrganizationId: "t1",
    RecordType: 50,
  },
]);

const gcp = JSON.stringify([
  {
    timestamp: "2026-03-01T10:00:01Z",
    insertId: "g-1",
    logName: "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
    resource: { type: "service_account", labels: { project_id: "p1" } },
    protoPayload: {
      "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
      methodName: "google.iam.admin.v1.DisableServiceAccount",
      serviceName: "iam.googleapis.com",
      resourceName: "projects/-/serviceAccounts/123456789012345678901",
      authenticationInfo: { principalEmail: "alice@example.com" },
      requestMetadata: { callerIp: "198.51.100.7" },
    },
  },
]);

const azure = JSON.stringify([
  {
    eventTimestamp: "2026-03-01T10:00:02Z",
    operationName: { value: "Microsoft.Compute/virtualMachines/runCommand/action" },
    caller: "alice@example.test",
    callerIpAddress: "198.51.100.7",
    resourceId: "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
    status: { value: "Succeeded" },
    eventDataId: "az-1",
  },
]);

const hashes = (events: Array<{ canonical?: { evidence: { sourceArtifactHash?: string } } }>) => {
  const canonical = events.filter((e) => e.canonical);
  expect(canonical.length).toBeGreaterThan(0);
  return new Set(canonical.map((e) => e.canonical!.evidence.sourceArtifactHash));
};

describe("whole-file source hash (#2353)", () => {
  it("M365: every canonical row carries the hash of the parsed text", () => {
    expect(hashes(parseM365Audit(ual).events)).toEqual(new Set([sourceArtifactHash(ual)]));
  });

  it("Cloud Activity (GCP and Azure): every canonical row carries the hash of the parsed text", () => {
    expect(hashes(parseCloudActivity(gcp).events)).toEqual(new Set([sourceArtifactHash(gcp)]));
    expect(hashes(parseCloudActivity(azure).events)).toEqual(new Set([sourceArtifactHash(azure)]));
  });

  it("a parse with no text (the streaming providers) stamps no hash of the empty string", () => {
    const { records } = { records: JSON.parse(gcp) as Record<string, unknown>[] };
    const events = parseCloudActivity("", { records }).events.filter((e) => e.canonical);
    expect(events.length).toBeGreaterThan(0);
    for (const e of events) expect(e.canonical!.evidence.sourceArtifactHash).toBeUndefined();
  });
});
