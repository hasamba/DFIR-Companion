import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { StateLock } from "../../src/analysis/stateLock.js";
import { pollFor } from "../helpers/poll.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { CloudRecordStore } from "../../src/analysis/cloudRecordStore.js";
import { AuthObservationStore } from "../../src/analysis/authObservationStore.js";
import { CloudCoverageStore } from "../../src/analysis/cloudCoverage.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { compileRuleset } from "../../src/analysis/taggerRules.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { sourceArtifactHash } from "../../src/analysis/canonicalEvent.js";

// #2303 — the streaming cloud import end to end: whole-export enrichment parity, dedup across
// batches, bounded output with disclosure, Info to the super-timeline, gzip, and a failed import
// leaving no record "seen".

async function setup(withLock = false) {
  const root = await mkdtemp(join(tmpdir(), "dfir-cloudstreamimp-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const superTimelineStore = new SuperTimelineStore(cases);
  const cloudRecordStore = new CloudRecordStore(cases);
  const cloudCoverageStore = new CloudCoverageStore(cases);
  const pipeline = new AnalysisPipeline({
    stateStore: new StateStore(cases),
    superTimelineStore,
    cloudRecordStore,
    cloudCoverageStore,
    authObservationStore: new AuthObservationStore(cases, 168),
    ...(withLock ? { stateLock: new StateLock() } : {}),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const write = async (name: string, body: string | Buffer) => {
    const p = join(root, name);
    await writeFile(p, body);
    return p;
  };
  return { pipeline, superTimelineStore, cloudRecordStore, cloudCoverageStore, write };
}

const opts = (idPrefix: string, over: Record<string, unknown> = {}) => ({
  label: `${idPrefix}.json`,
  idPrefix,
  importedAt: "2026-10-02T00:00:00Z",
  batchRecords: 2,
  ...over,
});

const ual = (i: number, op: string, user = `user${i}@example.com`, ip = "192.0.2.10") => ({
  Id: `00000000-0000-4000-9000-${String(i).padStart(12, "0")}`,
  OrganizationId: "00000000-0000-4000-8000-000000000001",
  CreationTime: `2026-10-01T10:${String(i % 60).padStart(2, "0")}:00`,
  Operation: op,
  Workload: op === "New-InboxRule" ? "Exchange" : "AzureActiveDirectory",
  RecordType: 15,
  UserId: user,
  ClientIP: ip,
  ...(op === "New-InboxRule"
    ? {
        Parameters: [
          { Name: "Name", Value: "x" },
          { Name: "ForwardTo", Value: "drop@example.net" },
        ],
      }
    : {}),
});

describe("streaming cloud import (#2303)", () => {
  it("enrichment parity: a consent record resolves an API named by a record in a LATER batch", async () => {
    const SP = "2b7f3c1a-1111-4aaa-8bbb-000000000001";
    const GRAPH_SP = "3c8e4d2b-2222-4bbb-9ccc-000000000002";
    const GRAPH_APP = "00000003-0000-0000-c000-000000000000";
    const audit = (id: string, activity: string, target: Record<string, unknown>) => ({
      id,
      activityDateTime: "2024-05-01T10:00:00Z",
      activityDisplayName: activity,
      result: "success",
      initiatedBy: { user: { id: "u1", userPrincipalName: "admin@example.com", ipAddress: "203.0.113.60" } },
      targetResources: [target],
    });
    const prop = (displayName: string, newValue: unknown) => ({ displayName, oldValue: null, newValue });
    const consent = audit("a1", "Consent to application", {
      type: "ServicePrincipal",
      id: SP,
      displayName: "Sync",
      modifiedProperties: [
        prop("ConsentContext.IsAdminConsent", "True"),
        prop("ConsentContext.IsAppOnly", "False"),
        prop(
          "ConsentAction.Permissions",
          `[] => [[Id: g1, ClientId: ${SP}, PrincipalId: , ResourceId: ${GRAPH_SP}, ConsentType: AllPrincipals, Scope: Mail.ReadWrite, CreatedDateTime: 2024-05-01, ExpiryTime: ]]`,
        ),
      ],
    });
    const filler = [1, 2, 3].map((i) =>
      audit(`f${i}`, "Update user", { type: "User", id: `x${i}`, modifiedProperties: [] }),
    );
    const grant = audit("a2", "Add app role assignment to service principal", {
      type: "ServicePrincipal",
      id: GRAPH_SP,
      displayName: "Microsoft Graph",
      modifiedProperties: [
        prop("AppRole.Value", "User.Read.All"),
        prop("ServicePrincipal.ObjectID", SP),
        prop("TargetId.ServicePrincipalNames", [GRAPH_APP, "https://graph.microsoft.com"]),
      ],
    });
    const text = JSON.stringify([consent, ...filler, grant]);
    const whole = await setup();
    const stream = await setup();
    const a = await whole.pipeline.importM365("c1", text, {
      label: "w.json",
      idPrefix: "w1",
      importedAt: "2026-10-02T00:00:00Z",
    });
    const b = await stream.pipeline.importCloudFile(
      "c1",
      "m365",
      await stream.write("s.json", text),
      opts("s1"),
    );
    const graded = (evs: typeof a.forensicTimeline) =>
      evs
        .filter((e) => e.severity !== "Info")
        .map((e) => `${e.severity}|${e.description.replace(/ \[aggregated.*$/, "")}`)
        .sort();
    expect(graded(b.state.forensicTimeline)).toEqual(graded(a.forensicTimeline));
    const mail = b.state.forensicTimeline.find((e) => e.description.includes("Mail.ReadWrite"))!;
    expect(mail.description).toContain("on Microsoft Graph");
    expect(mail.severity).toBe("High");
  });

  it("deduplicates a record repeated in a later batch, and says so", async () => {
    const { pipeline, write } = await setup();
    const rows = [
      ual(1, "New-InboxRule"),
      ual(2, "UserLoggedIn"),
      ual(3, "UserLoggedIn"),
      ual(1, "New-InboxRule"),
    ];
    const { state, disclosure } = await pipeline.importCloudFile(
      "c1",
      "m365",
      await write("d.json", JSON.stringify(rows)),
      opts("d1"),
    );
    expect(disclosure.duplicates).toBe(1);
    expect(state.forensicTimeline.filter((e) => e.severity === "High")).toHaveLength(1);
    expect(state.timeline.at(-1)!.description).toContain("1 duplicate record(s) skipped");
  });

  it("re-importing the same file adds nothing: the ledger was committed batch by batch", async () => {
    const { pipeline, write } = await setup();
    const path = await write(
      "r.jsonl",
      [ual(1, "New-InboxRule"), ual(2, "New-InboxRule")].map((r) => JSON.stringify(r)).join("\n"),
    );
    await pipeline.importCloudFile("c1", "m365", path, opts("r1"));
    const { disclosure } = await pipeline.importCloudFile("c1", "m365", path, opts("r2"));
    expect(disclosure.duplicates).toBe(2);
    expect(disclosure.individual.high).toBe(0);
  });

  it("sends Info rows to the super-timeline, keeps High individual, and discloses it in coverage", async () => {
    const { pipeline, superTimelineStore, cloudCoverageStore, write } = await setup();
    const rows = [
      ual(1, "New-InboxRule"),
      ...Array.from({ length: 6 }, (_, i) => ual(10 + i, "UserLoggedIn")),
    ];
    const { state, disclosure } = await pipeline.importCloudFile(
      "c1",
      "m365",
      await write("i.json", JSON.stringify(rows)),
      opts("i1"),
    );
    expect(disclosure.superWritten).toBe(6);
    expect(state.forensicTimeline.some((e) => e.id.startsWith("i1s"))).toBe(false);
    const sup = await superTimelineStore.query("c1", { limit: 50 });
    expect(sup.events.filter((e) => e.id.startsWith("i1s"))).toHaveLength(6);
    expect(sup.events.every((e) => e.severity === "Info" && e.sourceScreenshots.includes("i1.json"))).toBe(
      true,
    );
    const coverage = await cloudCoverageStore.load("c1");
    expect(coverage[0].importDisclosure?.join(" ")).toContain("written to the super-timeline individually");
  });

  it("a tagger severity rule raises an Info row BEFORE it is aggregated or sent past the forensic timeline", async () => {
    const { pipeline, write } = await setup();
    const rules = compileRuleset({
      watch_user: {
        any: [{ field: "description", contains: "watched@example.com" }],
        severity: "High",
        tags: ["x"],
      },
    });
    const rows = [ual(1, "UserLoggedIn", "watched@example.com"), ual(2, "UserLoggedIn")];
    const { state, disclosure } = await pipeline.importCloudFile(
      "c1",
      "m365",
      await write("t.json", JSON.stringify(rows)),
      opts("t1", { preGradeRules: rules }),
    );
    expect(disclosure.preGradeRaised).toBe(1);
    const raised = state.forensicTimeline.find((e) => e.description.includes("watched@example.com"))!;
    expect(raised.severity).toBe("High");
  });

  it("imports a CloudTrail .json.gz object as downloaded", async () => {
    const { pipeline, write } = await setup();
    const rec = (i: number, name: string) => ({
      eventVersion: "1.09",
      eventID: `00000000-0000-4000-b000-${String(i).padStart(12, "0")}`,
      eventTime: "2026-10-01T10:00:00Z",
      eventSource: "iam.amazonaws.com",
      eventName: name,
      awsRegion: "us-east-1",
      sourceIPAddress: "198.51.100.7",
      userIdentity: {
        type: "IAMUser",
        arn: `arn:aws:iam::123456789012:user/ops${i}`,
        accountId: "123456789012",
        userName: `ops${i}`,
      },
    });
    const body = gzipSync(
      JSON.stringify({ Records: [rec(1, "CreateAccessKey"), rec(2, "ListUsers"), rec(3, "StopLogging")] }),
    );
    const { state, disclosure } = await pipeline.importCloudFile(
      "c1",
      "aws",
      await write("ct.json.gz", body),
      opts("g1"),
    );
    expect(disclosure.gzip).toBe(true);
    expect(disclosure.records).toBe(3);
    expect(state.forensicTimeline.some((e) => /StopLogging/.test(e.description))).toBe(true);
  });

  // #2337 — the streamed rows carry the same source-artifact hash the whole-file path stamps, so a
  // Sigma re-grade can tell a stored file that changed since the import.
  it("stamps the whole-file path's source-artifact hash on streamed forensic events", async () => {
    const { pipeline, write } = await setup();
    const rec = (i: number, name: string) => ({
      eventVersion: "1.09",
      eventID: `00000000-0000-4000-c000-${String(i).padStart(12, "0")}`,
      eventTime: "2026-10-01T10:00:00Z",
      eventSource: name === "StopLogging" ? "cloudtrail.amazonaws.com" : "iam.amazonaws.com",
      eventName: name,
      awsRegion: "us-east-1",
      sourceIPAddress: "198.51.100.7",
      userIdentity: { type: "IAMUser", arn: `arn:aws:iam::123456789012:user/ops${i}`, userName: `ops${i}` },
    });
    const text = JSON.stringify({ Records: [rec(1, "StopLogging"), rec(2, "CreateAccessKey")] });
    const whole = parseCloudTrail(text, {});
    const wholeHash = whole.events.find((e) => e.canonical)?.canonical?.evidence.sourceArtifactHash;
    expect(wholeHash).toBe(sourceArtifactHash(text));

    // Each in its own case: the same records in one case would dedup the second import to nothing.
    const plain = await pipeline.importCloudFile("c1", "aws", await write("ct.json", text), opts("h1"));
    const other = await setup();
    const gzPath = await other.write("ct2.json.gz", gzipSync(text));
    const gz = await other.pipeline.importCloudFile("c1", "aws", gzPath, opts("h2"));
    expect(gz.disclosure.gzip).toBe(true);
    for (const [prefix, { state }] of [
      ["h1", plain],
      ["h2", gz],
    ] as const) {
      const streamed = state.forensicTimeline.filter((e) => e.canonical && e.id.startsWith(prefix));
      expect(streamed.length, prefix).toBeGreaterThan(0);
      for (const e of streamed) expect(e.canonical?.evidence.sourceArtifactHash).toBe(wholeHash);
    }
  });

  // #2485 — a collected plain UAL row and a plain Azure Activity row now carry an envelope, so the
  // streamed import cites their record and stamps the file's hash on them like every other row.
  it("collected plain UAL and Azure rows cite their record and carry the source-artifact hash", async () => {
    const { pipeline, write } = await setup();
    const ualText = JSON.stringify([
      {
        Id: "ual-s-1",
        OrganizationId: "00000000-0000-4000-8000-000000000001",
        CreationTime: "2026-10-01T10:00:00",
        Operation: "FileMalwareDetected",
        Workload: "SharePoint",
        RecordType: 6,
        UserId: "user1@example.com",
        ClientIP: "192.0.2.10",
      },
    ]);
    const m365 = await pipeline.importCloudFile("c1", "m365", await write("u.json", ualText), opts("u1"));
    const ualRow = m365.state.forensicTimeline.find((e) => /FileMalwareDetected/.test(e.description))!;
    expect(ualRow.canonical?.evidence.rawRecords[0]).toMatchObject({
      source: "m365-ual",
      locator: "record:0",
      recordId: "ual-s-1",
    });
    expect(ualRow.canonical?.evidence.sourceArtifactHash).toBe(sourceArtifactHash(ualText));

    const other = await setup();
    const azText = JSON.stringify([
      {
        eventTimestamp: "2026-10-01T10:00:02Z",
        operationName: { value: "Microsoft.Compute/virtualMachines/delete" },
        caller: "ops@example.com",
        callerIpAddress: "198.51.100.7",
        resourceId: "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        status: { value: "Failed" },
        eventDataId: "az-s-1",
      },
    ]);
    const cloud = await other.pipeline.importCloudFile(
      "c1",
      "cloud",
      await other.write("a.json", azText),
      opts("a1"),
    );
    const azRow = cloud.state.forensicTimeline.find((e) => /virtualMachines\/delete/.test(e.description))!;
    expect(azRow.canonical?.evidence.rawRecords[0]).toMatchObject({
      source: "azure-activity",
      locator: "record:0",
      recordId: "s1|az-s-1",
    });
    expect(azRow.canonical?.evidence.sourceArtifactHash).toBe(sourceArtifactHash(azText));
  });

  it("a cancelled import leaves none of its records seen", async () => {
    const { pipeline, write } = await setup();
    const path = await write("x.json", JSON.stringify([1, 2, 3, 4, 5].map((i) => ual(i, "New-InboxRule"))));
    const ctrl = new AbortController();
    let calls = 0;
    await expect(
      pipeline.importCloudFile("c1", "m365", path, {
        ...opts("x1"),
        onProgress: () => {
          if (++calls === 1) ctrl.abort();
        },
        signal: ctrl.signal,
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
    const { disclosure } = await pipeline.importCloudFile("c1", "m365", path, opts("x2"));
    expect(disclosure.duplicates).toBe(0);
    expect(disclosure.individual.high).toBe(5);
  });

  it("discloses IOCs over the per-import cap instead of dropping them silently (review)", async () => {
    const { pipeline, cloudCoverageStore, write } = await setup();
    const rows = Array.from({ length: 7 }, (_, i) =>
      ual(i + 1, "New-InboxRule", `a${i}@example.com`, `192.0.2.${i + 1}`),
    );
    const { state, disclosure } = await pipeline.importCloudFile(
      "c1",
      "m365",
      await write("ioc.json", JSON.stringify(rows)),
      opts("ic", { iocsMax: 3 }),
    );
    expect(disclosure.iocsDropped).toBeGreaterThanOrEqual(4);
    expect(state.timeline.at(-1)!.description).toMatch(/IOC\(s\) over the per-import cap of 3 not kept/);
    const coverage = await cloudCoverageStore.load("c1");
    expect(coverage[0].importDisclosure?.join(" ")).toMatch(/over the per-import cap of 3/);
  });

  it("a cancel while waiting for the final state lock merges nothing and leaves no record seen (review)", async () => {
    const { pipeline, cloudRecordStore, write } = await setup(true);
    const path = await write("lk.json", JSON.stringify([ual(1, "New-InboxRule"), ual(2, "New-InboxRule")]));
    const ctx = (
      pipeline as unknown as { importCtx: { withStateLock<T>(c: string, f: () => Promise<T>): Promise<T> } }
    ).importCtx;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    const holder = ctx.withStateLock("c1", () => held);
    const ctrl = new AbortController();
    const run = pipeline.importCloudFile("c1", "m365", path, { ...opts("lk"), signal: ctrl.signal });
    // Wait until the batches are committed (the import is now queued behind the held lock).
    const { cloudRecordIdentity } = await import("../../src/analysis/cloudRecordIdentity.js");
    const { normalizeRecord } = await import("../../src/analysis/m365Import.js");
    const id = cloudRecordIdentity("ual", normalizeRecord(ual(1, "New-InboxRule")));
    await pollFor("the batches committed to the ledger", async () =>
      (await cloudRecordStore.classify("c1", [id])).duplicates ? true : null,
    );
    ctrl.abort();
    release();
    await holder;
    await expect(run).rejects.toMatchObject({ name: "AbortError" });
    const state = await (pipeline as unknown as { opts: { stateStore: StateStore } }).opts.stateStore.load(
      "c1",
    );
    expect(state.forensicTimeline).toHaveLength(0);
    const again = await pipeline.importCloudFile("c1", "m365", path, opts("lk2"));
    expect(again.disclosure.duplicates).toBe(0);
  });
});
