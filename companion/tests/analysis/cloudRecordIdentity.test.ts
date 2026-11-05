import { describe, it, expect } from "vitest";
import {
  canonicalJson,
  cloudRecordIdentity,
  cloudActivityRecordProvider,
  m365RecordProvider,
} from "../../src/analysis/cloudRecordIdentity.js";

describe("canonicalJson (#2301)", () => {
  it("sorts keys recursively so key order never changes the hash", () => {
    const a = { b: 1, a: { d: [1, { y: 2, x: 1 }], c: "s" } };
    const b = { a: { c: "s", d: [1, { x: 1, y: 2 }] }, b: 1 };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
    expect(canonicalJson(a)).toBe('{"a":{"c":"s","d":[1,{"x":1,"y":2}]},"b":1}');
  });

  it("keeps array order — a different order is a different record", () => {
    expect(canonicalJson([1, 2])).not.toBe(canonicalJson([2, 1]));
  });

  it("drops undefined members like JSON does", () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});

describe("cloudRecordIdentity per provider (#2301)", () => {
  it("CloudTrail: recipientAccountId + eventID", () => {
    const id = cloudRecordIdentity("cloudtrail", {
      eventID: "ev-0001",
      recipientAccountId: "111122223333",
      eventName: "GetObject",
    });
    expect(id.key).toBe("cloudtrail|111122223333|ev-0001");
    expect(id.hashIdentified).toBe(false);
  });

  it("CloudTrail: the same eventID in two accounts is two records", () => {
    const a = cloudRecordIdentity("cloudtrail", { eventID: "ev-1", recipientAccountId: "111122223333" });
    const b = cloudRecordIdentity("cloudtrail", { eventID: "ev-1", recipientAccountId: "444455556666" });
    expect(a.key).not.toBe(b.key);
  });

  it("UAL: OrganizationId + Id", () => {
    const id = cloudRecordIdentity("ual", { Id: "ual-1", OrganizationId: "tenant-a", Operation: "Send" });
    expect(id.key).toBe("ual|tenant-a|ual-1");
  });

  it("Graph auditLogRecord: organizationId + id", () => {
    const rec = { id: "g-1", organizationId: "tenant-a", auditLogRecordType: "ExchangeItem" };
    expect(m365RecordProvider("ual", rec)).toBe("graph-audit");
    expect(cloudRecordIdentity("graph-audit", rec).key).toBe("graph-audit|tenant-a|g-1");
  });

  it("Entra sign-in: resource tenant + id, home tenant as fallback", () => {
    expect(cloudRecordIdentity("entra-signin", { id: "s-1", resourceTenantId: "t-r" }).key).toBe(
      "entra-signin|t-r|s-1",
    );
    expect(cloudRecordIdentity("entra-signin", { id: "s-1", homeTenantId: "t-h" }).key).toBe(
      "entra-signin|t-h|s-1",
    );
    expect(m365RecordProvider("signin", {})).toBe("entra-signin");
  });

  it("GCP: project + timestamp + insertId — insertId alone is not the identity", () => {
    const base = {
      insertId: "abc123",
      timestamp: "2026-06-01T00:00:00.000Z",
      logName: "projects/proj-a/logs/cloudaudit.googleapis.com%2Factivity",
      protoPayload: {},
    };
    const id = cloudRecordIdentity("gcp", base);
    expect(id.key).toBe("gcp|proj-a|2026-06-01T00:00:00.000Z|abc123");
    const otherProject = cloudRecordIdentity("gcp", {
      ...base,
      logName: "projects/proj-b/logs/cloudaudit.googleapis.com%2Factivity",
    });
    const otherTime = cloudRecordIdentity("gcp", { ...base, timestamp: "2026-06-01T00:00:01.000Z" });
    expect(otherProject.key).not.toBe(id.key);
    expect(otherTime.key).not.toBe(id.key);
    expect(cloudActivityRecordProvider(base)).toBe("gcp");
  });

  it("GCP: falls back to resource.labels.project_id", () => {
    const id = cloudRecordIdentity("gcp", {
      insertId: "x",
      timestamp: "t",
      resource: { labels: { project_id: "proj-c" } },
    });
    expect(id.key).toBe("gcp|proj-c|t|x");
  });

  it("Azure Activity: subscription + eventDataId", () => {
    const rec = {
      eventDataId: "ed-1",
      resourceId: "/subscriptions/00000000-AAAA-0000-0000-000000000001/resourceGroups/rg",
      operationName: "Microsoft.Compute/virtualMachines/write",
    };
    expect(cloudActivityRecordProvider(rec)).toBe("azure-activity");
    expect(cloudRecordIdentity("azure-activity", rec).key).toBe(
      "azure-activity|00000000-aaaa-0000-0000-000000000001|ed-1",
    );
  });

  it("Azure Activity: correlationId + operationId + eventTimestamp when eventDataId is missing", () => {
    const rec = {
      subscriptionId: "sub-1",
      correlationId: "c-1",
      operationId: "o-1",
      eventTimestamp: "2026-06-01T00:00:00Z",
    };
    expect(cloudRecordIdentity("azure-activity", rec).key).toBe(
      "azure-activity|sub-1|c-1|o-1|2026-06-01T00:00:00Z",
    );
  });

  it("no id: SHA-256 of the canonical record, flagged hash-identified, key-order independent", () => {
    const a = cloudRecordIdentity("cloudtrail", { eventName: "GetObject", eventSource: "s3.amazonaws.com" });
    const b = cloudRecordIdentity("cloudtrail", { eventSource: "s3.amazonaws.com", eventName: "GetObject" });
    expect(a.hashIdentified).toBe(true);
    expect(a.key).toMatch(/^cloudtrail\|sha256:[a-f0-9]{64}$/);
    expect(a.key).toBe(b.key);
    expect(a.payloadHash).toBe(b.payloadHash);
  });

  it("same id, different payload: same key, different payloadHash (a conflict)", () => {
    const a = cloudRecordIdentity("ual", { Id: "u-1", OrganizationId: "t", Operation: "Send" });
    const b = cloudRecordIdentity("ual", { Id: "u-1", OrganizationId: "t", Operation: "Delete" });
    expect(a.key).toBe(b.key);
    expect(a.payloadHash).not.toBe(b.payloadHash);
  });
});
