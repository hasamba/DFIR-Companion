// #1063: the per-provider coverage builders. Each reads only what its provider's export
// documents; anything else is an `unknown` bucket, never guessed into an existing category.
import { describe, it, expect } from "vitest";
import {
  awsCloudTrailCoverage,
  gcpCoverage,
  azureCoverage,
  m365Coverage,
  workspaceCoverage,
} from "../../src/analysis/cloudCoverageBuilders.js";

describe("awsCloudTrailCoverage", () => {
  it("buckets Management/Data/Insight from a >=1.07 eventVersion, with a read-only tri-state", () => {
    const records = [
      {
        recipientAccountId: "111111111111",
        eventTime: "2026-01-01T00:00:00Z",
        eventVersion: "1.08",
        eventCategory: "Management",
        readOnly: true,
      },
      {
        recipientAccountId: "111111111111",
        eventTime: "2026-01-02T00:00:00Z",
        eventVersion: "1.08",
        eventCategory: "Data",
        readOnly: false,
      },
      {
        recipientAccountId: "111111111111",
        eventTime: "2026-01-03T00:00:00Z",
        eventVersion: "1.08",
        eventCategory: "Data",
      }, // readOnly absent -> unknown
    ];
    const [acct] = awsCloudTrailCoverage(records);
    expect(acct.scope).toEqual({ kind: "account", value: "111111111111" });
    expect(acct.recordCount).toBe(3);
    const data = acct.categories.find((c) => c.name === "Data")!;
    expect(data.count).toBe(2);
    expect(data.readOnly).toEqual({ true: 0, false: 1, unknown: 1 });
    const mgmt = acct.categories.find((c) => c.name === "Management")!;
    expect(mgmt.readOnly).toEqual({ true: 1, false: 0, unknown: 0 });
  });

  it("a pre-1.07 eventVersion (or missing) buckets eventCategory as unknown, never assumed Management", () => {
    const records = [
      {
        recipientAccountId: "1",
        eventTime: "2026-01-01T00:00:00Z",
        eventVersion: "1.05",
        eventCategory: "Management",
      },
      { recipientAccountId: "1", eventTime: "2026-01-01T00:00:00Z", eventCategory: "Management" }, // no eventVersion at all
    ];
    const [acct] = awsCloudTrailCoverage(records);
    expect(acct.categories.map((c) => c.name)).toEqual(["unknown"]);
    expect(acct.categories[0].count).toBe(2);
  });

  it("records with no recipientAccountId bucket under the unknown scope", () => {
    const [acct] = awsCloudTrailCoverage([
      { eventTime: "2026-01-01T00:00:00Z", eventVersion: "1.08", eventCategory: "Management" },
    ]);
    expect(acct.scope.kind).toBe("unknown");
  });

  it("two accounts are two scopes, sorted by record count desc", () => {
    const records = [
      { recipientAccountId: "small", eventTime: "2026-01-01T00:00:00Z" },
      { recipientAccountId: "big", eventTime: "2026-01-01T00:00:00Z" },
      { recipientAccountId: "big", eventTime: "2026-01-01T00:00:00Z" },
    ];
    const result = awsCloudTrailCoverage(records);
    expect(result.map((r) => r.scope.value)).toEqual(["big", "small"]);
  });
});

describe("gcpCoverage", () => {
  const rec = (logName: string, projectId = "") => ({
    logName,
    timestamp: "2026-01-01T00:00:00Z",
    resource: { labels: { project_id: projectId } },
    protoPayload: { "@type": "x" },
  });

  it("reads all four documented log types plus an unrecognised one as unknown", () => {
    const records = [
      rec("projects/acme/logs/cloudaudit.googleapis.com%2Factivity"),
      rec("projects/acme/logs/cloudaudit.googleapis.com%2Fdata_access"),
      rec("projects/acme/logs/cloudaudit.googleapis.com%2Fsystem_event"),
      rec("projects/acme/logs/cloudaudit.googleapis.com%2Fpolicy"),
      rec("projects/acme/logs/somethingelse.googleapis.com%2Fweird"),
    ];
    const [scope] = gcpCoverage(records);
    const names = scope.categories.map((c) => c.name).sort();
    expect(names).toEqual(["activity", "data_access", "policy", "system_event", "unknown"]);
  });

  it("scope may be rooted at a folder or organization, not just a project", () => {
    const records = [rec("folders/999/logs/cloudaudit.googleapis.com%2Factivity")];
    const [scope] = gcpCoverage(records);
    expect(scope.scope).toEqual({ kind: "folders", value: "999" });
  });
});

describe("azureCoverage", () => {
  const rec = (over: Record<string, unknown>) => ({
    operationName: "Microsoft.Storage/x/write",
    eventTimestamp: "2026-01-01T00:00:00Z",
    ...over,
  });

  it("reads an explicit subscriptionId field before falling back to resourceId", () => {
    const records = [
      rec({
        subscriptionId: "sub-explicit",
        resourceId: "/subscriptions/sub-from-resource/resourceGroups/rg",
      }),
    ];
    const [scope] = azureCoverage(records);
    expect(scope.scope.value).toBe("sub-explicit");
  });

  it("falls back to parsing resourceId (either casing) when no explicit field exists", () => {
    const lower = azureCoverage([rec({ resourceId: "/subscriptions/sub-lower/resourceGroups/rg" })]);
    expect(lower[0].scope.value).toBe("sub-lower");
    const upper = azureCoverage([rec({ ResourceId: "/subscriptions/sub-upper/resourceGroups/rg" })]);
    expect(upper[0].scope.value).toBe("sub-upper");
  });

  it("no subscription field or resourceId -> unknown scope", () => {
    const [scope] = azureCoverage([rec({})]);
    expect(scope.scope.kind).toBe("unknown");
  });

  it("reads category.value, plain string category, Category, and CategoryValue", () => {
    const objForm = azureCoverage([rec({ subscriptionId: "s", category: { value: "Security" } })]);
    expect(objForm[0].categories.map((c) => c.name)).toEqual(["Security"]);
    const stringForm = azureCoverage([rec({ subscriptionId: "s", category: "Administrative" })]);
    expect(stringForm[0].categories.map((c) => c.name)).toEqual(["Administrative"]);
    const pascalForm = azureCoverage([rec({ subscriptionId: "s", Category: "Policy" })]);
    expect(pascalForm[0].categories.map((c) => c.name)).toEqual(["Policy"]);
    const flatForm = azureCoverage([rec({ subscriptionId: "s", CategoryValue: "Alert" })]);
    expect(flatForm[0].categories.map((c) => c.name)).toEqual(["Alert"]);
  });

  it("an unrecognised category value is unknown, never guessed", () => {
    const result = azureCoverage([rec({ subscriptionId: "s", category: "SomethingNew" })]);
    expect(result[0].categories.map((c) => c.name)).toEqual(["unknown"]);
  });
});

describe("m365Coverage", () => {
  it("reads Workload/Operation as the category, keeping the numeric RecordType as a separate tally", () => {
    const records = [
      {
        OrganizationId: "tenant-1",
        CreationTime: "2026-01-01T00:00:00Z",
        Workload: "Exchange",
        Operation: "MailItemsAccessed",
        RecordType: "50",
      },
    ];
    const [scope] = m365Coverage(records);
    expect(scope.scope).toEqual({ kind: "tenant", value: "tenant-1" });
    const cat = scope.categories[0];
    expect(cat.name).toBe("Exchange/MailItemsAccessed");
    expect(cat.recordTypeIds).toEqual([50]);
  });

  it("missing OrganizationId is an unknown scope; missing Workload or Operation is unknown/unknown", () => {
    const noOrg = m365Coverage([{ Workload: "Exchange", Operation: "X", RecordType: "1" }]);
    expect(noOrg[0].scope.kind).toBe("unknown");
    const noOp = m365Coverage([{ OrganizationId: "t", Workload: "Exchange", RecordType: "1" }]);
    expect(noOp[0].categories.map((c) => c.name)).toEqual(["Exchange/unknown"]);
  });

  it("a record missing Workload or RecordType is not counted as an M365 audit record at all", () => {
    expect(m365Coverage([{ Operation: "x" }])).toHaveLength(0);
  });
});

describe("workspaceCoverage", () => {
  const rec = (app: string, over: Record<string, unknown> = {}) => ({
    id: { time: "2026-01-01T00:00:00Z", customerId: "C01abc", applicationName: app, ...over },
    events: [{ name: "x" }],
  });

  it("tallies applicationName per tenant, with an unknown bucket when the field is absent", () => {
    const records = [rec("drive"), rec("login"), rec("drive"), rec("", { applicationName: undefined })];
    const [scope] = workspaceCoverage(records);
    expect(scope.scope).toEqual({ kind: "tenant", value: "C01abc" });
    const names = scope.categories.map((c) => c.name).sort();
    expect(names).toEqual(["drive", "login", "unknown"]);
  });

  it("a record with no customerId is an unknown-scope tenant", () => {
    const [scope] = workspaceCoverage([
      { id: { time: "2026-01-01T00:00:00Z", applicationName: "login" }, events: [{}] },
    ]);
    expect(scope.scope.kind).toBe("unknown");
  });
});
