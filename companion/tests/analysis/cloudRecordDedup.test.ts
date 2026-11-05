import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AuthObservationStore } from "../../src/analysis/authObservationStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { RECORD_CONFLICT_NOTE } from "../../src/analysis/cloudRecordGate.js";
import type { InvestigationState } from "../../src/analysis/stateTypes.js";

// #2301 acceptance: the same file twice adds no event and says "N duplicates skipped"; a different
// payload under a known id is kept and flagged; an aggregated event lists its source records.

async function makePipeline(withLedger = true) {
  const root = await mkdtemp(join(tmpdir(), "dfir-clouddedup-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const cloudRecordStore = new CloudRecordStore(cases);
  const authObservationStore = new AuthObservationStore(cases, 168);
  const pipeline = new AnalysisPipeline({
    stateStore: new StateStore(cases),
    authObservationStore,
    ...(withLedger ? { cloudRecordStore } : {}),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  return { pipeline, cloudRecordStore, authObservationStore };
}

// Mailbox forwarding rules: graded above Info, so they reach the forensic timeline.
function ualRule(id: string, mailbox = "victim@example.com", forwardTo = "drop@example.net") {
  return {
    Id: id,
    OrganizationId: "tenant-a",
    CreationTime: "2026-06-01T10:00:00",
    Operation: "New-InboxRule",
    Workload: "Exchange",
    RecordType: 1,
    UserId: mailbox,
    ClientIP: "203.0.113.7",
    Parameters: [
      { Name: "Name", Value: "x" },
      { Name: "ForwardTo", Value: forwardTo },
    ],
  };
}

const lastNote = (s: InvestigationState): string => s.timeline[s.timeline.length - 1]?.description ?? "";
const opts = (idPrefix: string) => ({
  label: `${idPrefix}.json`,
  idPrefix,
  importedAt: "2026-06-02T00:00:00Z",
});

describe("cloud record dedup through the M365 import (#2301)", () => {
  it("importing the same file twice leaves the event count unchanged and says how many were skipped", async () => {
    const { pipeline } = await makePipeline();
    const file = JSON.stringify([ualRule("u-1"), ualRule("u-2", "other@example.com"), ualRule("u-3")]);
    const s1 = await pipeline.importM365("c1", file, opts("m1"));
    const before = s1.forensicTimeline.length;
    expect(before).toBeGreaterThan(0);
    const s2 = await pipeline.importM365("c1", file, opts("m2"));
    expect(s2.forensicTimeline.length).toBe(before);
    expect(s2.forensicTimeline.map((e) => e.id)).toEqual(s1.forensicTimeline.map((e) => e.id));
    expect(lastNote(s2)).toContain("3 duplicate record(s) skipped");
  });

  it("without a ledger the behavior is unchanged (no dedup, no provenance)", async () => {
    const { pipeline } = await makePipeline(false);
    const file = JSON.stringify([ualRule("u-1")]);
    const s1 = await pipeline.importM365("c1", file, opts("m1"));
    expect(s1.forensicTimeline.every((e) => e.sourceRecords === undefined)).toBe(true);
    expect(lastNote(s1)).not.toContain("duplicate");
  });

  it("an overlapping export adds only its new records", async () => {
    const { pipeline } = await makePipeline();
    await pipeline.importM365("c1", JSON.stringify([ualRule("u-1")]), opts("m1"));
    const s2 = await pipeline.importM365(
      "c1",
      JSON.stringify([ualRule("u-1"), ualRule("u-9", "third@example.com", "x@example.net")]),
      opts("m2"),
    );
    expect(lastNote(s2)).toContain("1 duplicate record(s) skipped");
    const fromSecond = s2.forensicTimeline.filter((e) => e.id.startsWith("m2"));
    expect(fromSecond.length).toBeGreaterThan(0);
    expect(fromSecond.every((e) => e.sourceRecords?.refs.every((r) => r === "ual|tenant-a|u-9"))).toBe(true);
  });

  it("a different payload under a known id is kept, flagged on the row and in the import note", async () => {
    const { pipeline } = await makePipeline();
    await pipeline.importM365("c1", JSON.stringify([ualRule("u-1")]), opts("m1"));
    const altered = JSON.stringify([ualRule("u-1", "victim@example.com", "elsewhere@example.net")]);
    const s2 = await pipeline.importM365("c1", altered, opts("m2"));
    expect(lastNote(s2)).toContain("1 conflicting record(s) kept and flagged");
    const flagged = s2.forensicTimeline.filter((e) => e.sourceRecords?.conflict);
    expect(flagged).toHaveLength(1);
    expect(flagged[0].description).toContain(RECORD_CONFLICT_NOTE.trim());
    // Both payloads are now known: uploading the altered file again is a pure duplicate.
    const s3 = await pipeline.importM365("c1", altered, opts("m3"));
    expect(s3.forensicTimeline.length).toBe(s2.forensicTimeline.length);
    expect(lastNote(s3)).toContain("1 duplicate record(s) skipped");
  });

  it("an aggregated event carries a bounded sample and its full member list pages from the relation", async () => {
    const { pipeline, cloudRecordStore } = await makePipeline();
    // Failed UAL logons by one user from one IP fold into one counted row.
    const rules = Array.from({ length: 25 }, (_, i) => ({
      Id: `agg-${i}`,
      OrganizationId: "tenant-a",
      CreationTime: "2026-06-01T10:00:00",
      Operation: "UserLoginFailed",
      Workload: "AzureActiveDirectory",
      RecordType: 15,
      UserId: "victim@example.com",
      ClientIP: "203.0.113.7",
    }));
    const s = await pipeline.importM365("c1", JSON.stringify(rules), opts("m1"));
    const agg = s.forensicTimeline.find((e) => (e.sourceRecords?.count ?? 0) > 1);
    expect(agg).toBeDefined();
    const sr = agg!.sourceRecords!;
    expect(sr.count).toBe(25);
    expect(sr.refs).toHaveLength(10);
    const p1 = await cloudRecordStore.pageMembers("c1", sr.group, { limit: 20 });
    const p2 = await cloudRecordStore.pageMembers("c1", sr.group, { after: p1.next!, limit: 20 });
    expect(p1.total).toBe(25);
    expect([...p1.members, ...p2.members].map((m) => m.ref)).toEqual(
      rules.map((r) => `ual|tenant-a|${r.Id}`),
    );
    expect(p2.next).toBeNull();
  });
});

describe("cloud record dedup through the AWS and cloud-activity imports (#2301)", () => {
  const trail = (id: string, account = "111122223333") => ({
    eventVersion: "1.08",
    eventID: id,
    eventTime: "2026-06-01T10:00:00Z",
    eventSource: "iam.amazonaws.com",
    eventName: "CreateAccessKey",
    awsRegion: "us-east-1",
    sourceIPAddress: "203.0.113.9",
    recipientAccountId: account,
    userIdentity: { type: "IAMUser", arn: `arn:aws:iam::${account}:user/alice`, accountId: account },
    requestParameters: { userName: "bob" },
  });

  it("CloudTrail: the same file twice adds nothing", async () => {
    const { pipeline } = await makePipeline();
    const file = JSON.stringify({ Records: [trail("ev-1"), trail("ev-2")] });
    const s1 = await pipeline.importAws("c1", file, opts("a1"));
    const s2 = await pipeline.importAws("c1", file, opts("a2"));
    expect(s2.forensicTimeline.length).toBe(s1.forensicTimeline.length);
    expect(lastNote(s2)).toContain("2 duplicate record(s) skipped");
  });

  const gcp = (insertId: string) => ({
    insertId,
    timestamp: "2026-06-01T10:00:00.000Z",
    logName: "projects/proj-a/logs/cloudaudit.googleapis.com%2Factivity",
    protoPayload: {
      methodName: "SetIamPolicy",
      serviceName: "cloudresourcemanager.googleapis.com",
      authenticationInfo: { principalEmail: "admin@example.com" },
      requestMetadata: { callerIp: "198.51.100.4" },
      resourceName: "projects/proj-a",
    },
  });

  it("GCP audit: the same file twice adds nothing", async () => {
    const { pipeline } = await makePipeline();
    const file = JSON.stringify([gcp("i-1"), gcp("i-2")]);
    const s1 = await pipeline.importCloudActivity("c1", file, opts("g1"));
    const s2 = await pipeline.importCloudActivity("c1", file, opts("g2"));
    expect(s2.forensicTimeline.length).toBe(s1.forensicTimeline.length);
    expect(lastNote(s2)).toContain("2 duplicate record(s) skipped");
  });
});

describe("sign-in observations through the M365 import (#2301)", () => {
  const signin = (id: string, code: number, detail: string, minute: number) => ({
    id,
    createdDateTime: `2026-06-01T10:${String(minute).padStart(2, "0")}:00Z`,
    userPrincipalName: "victim@example.com",
    appDisplayName: "Office 365",
    ipAddress: "203.0.113.50",
    resourceTenantId: "tenant-a",
    correlationId: `corr-${id}`,
    status: { errorCode: code, additionalDetails: detail },
    authenticationDetails: [
      { authenticationMethod: "Mobile app notification", authenticationStepResultDetail: detail },
    ],
  });

  it("stores MFA interruptions with their detail, and never as spray attempts", async () => {
    const { pipeline, authObservationStore } = await makePipeline();
    const file = JSON.stringify([
      signin("s-1", 500121, "MFA denied; user declined the authentication", 0),
      signin("s-2", 500121, "MFA denied; user did not respond to mobile app notification", 1),
      signin("s-3", 50074, "MFA required in Azure AD", 2),
      signin("s-4", 0, "MFA successfully completed", 3),
    ]);
    await pipeline.importM365("c1", file, opts("m1"));
    const page = await authObservationStore.queryPage("c1", {
      tenant: "tenant-a",
      account: "victim@example.com",
    });
    expect(page.observations.map((o) => [o.mfaDetail, o.outcome])).toEqual([
      ["denied", "interrupted"],
      ["timed out", "interrupted"],
      ["required", "interrupted"],
      ["approved", "success"],
    ]);
    expect(page.observations[0]).toMatchObject({
      resultCode: "500121",
      authMethod: "Mobile app notification",
      correlationId: "corr-s-1",
      app: "Office 365",
      recordId: "entra-signin|tenant-a|s-1",
    });
    // Re-importing the same export stores nothing new.
    await pipeline.importM365("c1", file, opts("m2"));
    expect((await authObservationStore.queryPage("c1", {})).observations).toHaveLength(4);
  });
});
