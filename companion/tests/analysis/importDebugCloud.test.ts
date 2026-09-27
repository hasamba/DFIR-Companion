import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import {
  createImportDebugRecorder,
  type DebugTarget,
  type ImportDebugRecorder,
} from "../../src/analysis/importDebug.js";
import { parseOktaSystemLog } from "../../src/analysis/oktaImport.js";
import { parseK8sAudit } from "../../src/analysis/k8sAuditImport.js";
import { parseHindsight } from "../../src/analysis/hindsightImport.js";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { parseOsqueryLog } from "../../src/analysis/osqueryImport.js";

// #1736: the cloud importers record what they DECIDED — which key fed a field, which rows they
// skipped and why, what the floor and cap removed — and never a value from a row. Every fixture
// carries unique marker values (RFC 5737 addresses, example.com names); none may reach the summary.

const MARKERS = [
  "198.51.100.77",
  "203.0.113.55",
  "192.0.2.201",
  "marker-user@example.com",
  "Marker Display Name",
  "marker-host.example.com",
  "eni-markerzz",
  "markervm",
  "https://marker.example.com",
];

function expectNoMarkers(r: ImportDebugRecorder): void {
  const text = JSON.stringify(r.summary());
  for (const m of MARKERS) expect(text).not.toContain(m);
}

/** A real recorder that also remembers the raw (target, key) of every field() call. */
function spyRecorder(): ImportDebugRecorder & { picks: Array<[DebugTarget, string]> } {
  const real = createImportDebugRecorder();
  const picks: Array<[DebugTarget, string]> = [];
  return {
    ...real,
    field(target, source, n) {
      picks.push([target, source]);
      real.field(target, source, n);
    },
    picks,
  };
}

const picked = (picks: Array<[DebugTarget, string]>, target: DebugTarget) =>
  picks.filter(([t]) => t === target).map(([, k]) => k);

async function makePipeline(caseId: string): Promise<AnalysisPipeline> {
  const root = await mkdtemp(join(tmpdir(), "dfir-importdebug-cloud-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  return new AnalysisPipeline({
    stateStore: new StateStore(cases),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

const base = (debug: ImportDebugRecorder, extra: Record<string, unknown> = {}) => ({
  label: "upload.json",
  idPrefix: "dx",
  importedAt: "2026-09-27T00:00:00.000Z",
  debug,
  ...extra,
});

describe("AWS VPC flow log debug (#1736)", () => {
  it("skips NODATA, SKIPDATA and malformed lines by name and counts the fold", async () => {
    const ok =
      "2 123456789010 eni-markerzz 198.51.100.77 203.0.113.55 443 51000 6 10 840 1418530010 1418530070 ACCEPT OK";
    const text = [
      ok,
      ok, // the same 5-tuple in the same hour folds into the first row
      "2 123456789010 eni-markerzz - - - - - - - 1418530010 1418530070 - NODATA",
      "2 123456789010 eni-markerzz - - - - - - - 1418530010 1418530070 - SKIPDATA",
      "2 123456789010 eni-markerzz 198.51.100.77 not-a-row",
    ].join("\n");
    const debug = createImportDebugRecorder();
    await (await makePipeline("aws1")).importAwsFlowLog("aws1", text, base(debug));
    const s = debug.summary();
    expect(s.skipped).toEqual({ flow_nodata: 1, flow_skipdata: 1, malformed_record: 1 });
    expect(s.omitted).toEqual({ aggregated: 1 });
    expect(s.counts).toEqual({ total: 5, kept: 1, dropped: 0 });
    expectNoMarkers(debug);
  });
});

describe("Azure VNet flow log debug (#1736)", () => {
  it("skips refused and malformed input, and keeps a no-target record as an observation", async () => {
    const blob = JSON.stringify({
      records: [
        {
          category: "FlowLogFlowEvent",
          flowLogVersion: 4,
          macAddress: "112233445566",
          // no targetResourceID: the rows are kept without a subscription
          flowRecords: {
            flows: [
              {
                flowGroups: [
                  {
                    rule: "unspecified",
                    flowTuples: [
                      "1663146003606,198.51.100.77,203.0.113.55,23956,443,6,O,E,NX,3,767,2,1580",
                      "not,a,tuple",
                    ],
                  },
                ],
              },
            ],
          },
        },
        { category: "NetworkSecurityGroupFlowEvent", properties: { flows: [] } },
        { category: "FlowLogFlowEvent", flowLogVersion: 3, flowRecords: { flows: [] } },
        { category: "SomethingElse", note: "marker-host.example.com" },
      ],
    });
    const debug = createImportDebugRecorder();
    await (await makePipeline("az1")).importAzureFlowLog("az1", blob, base(debug));
    const s = debug.summary();
    expect(s.skipped).toEqual({
      legacy_nsg_format: 1,
      unsupported_version: 1,
      non_flow_category: 1,
      malformed_record: 1,
    });
    expect(s.observations).toEqual({ no_target: 1, unspecified_rule: 1 });
    expect(s.skipped).not.toHaveProperty("no_target");
    expect(s.counts).toEqual({ total: 2, kept: 1, dropped: 0 });
    expectNoMarkers(debug);
  });
});

describe("GCP VPC flow log debug (#1736)", () => {
  const entry = (payload: Record<string, unknown>) => ({
    insertId: "id1",
    logName: "projects/my-proj/logs/compute.googleapis.com%2Fvpc_flows",
    resource: { type: "gce_subnetwork", labels: { project_id: "my-proj" } },
    jsonPayload: {
      connection: {
        src_ip: "198.51.100.77",
        dest_ip: "203.0.113.55",
        src_port: 51234,
        dest_port: 443,
        protocol: 6,
      },
      reporter: "SRC",
      start_time: "2024-05-01T09:59:58Z",
      end_time: "2024-05-01T10:00:03Z",
      src_instance: {
        project_id: "my-proj",
        region: "us-central1",
        zone: "us-central1-a",
        vm_name: "markervm",
      },
      ...payload,
    },
  });

  it("keeps a DROPPED flow as a network observation, never a skip", async () => {
    const text = JSON.stringify([
      entry({ bytes_sent: "10", packets_sent: "1" }),
      entry({
        disposition: "DROPPED",
        bytes_dropped: "5",
        packets_dropped: "1",
        start_time: "2024-05-01T11:00:00Z",
      }),
      { logName: "projects/my-proj/logs/other", jsonPayload: { note: "marker-host.example.com" } },
      entry({ connection: "broken" }),
    ]);
    const debug = createImportDebugRecorder();
    await (await makePipeline("gcp1")).importGcpFlowLog("gcp1", text, base(debug));
    const s = debug.summary();
    expect(s.observations).toEqual({ network_dropped_flow: 1 });
    expect(s.skipped).toEqual({ non_flow_entry: 1, malformed_record: 1 });
    expect(s.skipped).not.toHaveProperty("network_dropped_flow");
    expect(s.counts).toEqual({ total: 4, kept: 2, dropped: 0 });
    expectNoMarkers(debug);
  });
});

describe("AWS CloudTrail debug (#1736)", () => {
  it("records the floor and an unmapped record", async () => {
    const rec = (eventName: string, extra: Record<string, unknown> = {}) => ({
      eventName,
      eventSource: "iam.amazonaws.com",
      eventTime: "2024-01-01T00:00:00Z",
      sourceIPAddress: "198.51.100.77",
      userIdentity: { type: "IAMUser", userName: "marker-user@example.com", accountId: "123" },
      ...extra,
    });
    const text = JSON.stringify({
      Records: [
        rec("CreateAccessKey"),
        rec("GetUser", { readOnly: true }),
        { eventTime: "2024-01-01T00:00:00Z", sourceIPAddress: "203.0.113.55" },
      ],
    });
    const debug = createImportDebugRecorder();
    await (await makePipeline("ct1")).importAws("ct1", text, base(debug, { minSeverity: "High" }));
    const s = debug.summary();
    expect(s.skipped).toEqual({ missing_required_field: 1 });
    expect(s.omitted.below_severity_floor).toBeGreaterThanOrEqual(1);
    expect(s.counts.total).toBe(3);
    expectNoMarkers(debug);
  });
});

describe("Okta debug (#1736)", () => {
  it("records which actor key named the user, and skips non-Okta records", () => {
    const debug = spyRecorder();
    parseOktaSystemLog(
      JSON.stringify([
        {
          eventType: "user.session.start",
          published: "2024-01-01T00:00:00Z",
          actor: { alternateId: "marker-user@example.com" },
          client: { ipAddress: "198.51.100.77" },
        },
        {
          eventType: "user.session.start",
          published: "2024-01-01T00:01:00Z",
          actor: { displayName: "Marker Display Name" },
        },
        { note: "marker-host.example.com" },
      ]),
      { debug },
    );
    expect(picked(debug.picks, "user")).toEqual(["actor.alternateId", "actor.displayName"]);
    const s = debug.summary();
    expect(s.skipped).toEqual({ unrecognized_record: 1 });
    expectNoMarkers(debug);
  });
});

describe("Kubernetes audit debug (#1736)", () => {
  it("records the timestamp key and skips a record with no verb", () => {
    const debug = spyRecorder();
    parseK8sAudit(
      JSON.stringify([
        {
          verb: "get",
          objectRef: { resource: "secrets", name: "markervm" },
          user: { username: "marker-user@example.com" },
          sourceIPs: ["198.51.100.77"],
          requestReceivedTimestamp: "2024-01-01T00:00:00Z",
        },
        { verb: "list", objectRef: { resource: "pods" }, stageTimestamp: "2024-01-01T00:00:01Z" },
        { objectRef: { resource: "pods" } },
      ]),
      { debug },
    );
    expect(picked(debug.picks, "timestamp")).toEqual(["requestReceivedTimestamp", "stageTimestamp"]);
    expect(debug.summary().skipped).toEqual({ missing_required_field: 1 });
    expectNoMarkers(debug);
  });
});

describe("Hindsight debug (#1736)", () => {
  it("records the time and URL columns it chose and names why a row was skipped", () => {
    const debug = spyRecorder();
    const csv = [
      "type,visit_time,location,title",
      "url,2024-01-01 00:00:00,https://marker.example.com/a,Marker Display Name",
      "url,,https://marker.example.com/b,x",
      "url,2024-01-01 00:00:00,,x",
    ].join("\n");
    parseHindsight(csv, { debug });
    expect(picked(debug.picks, "timestamp")).toEqual(["visit_time"]);
    expect(picked(debug.picks, "url")).toEqual(["location"]);
    expect(debug.summary().skipped).toEqual({ missing_timestamp: 1, missing_url: 1 });
    expectNoMarkers(debug);
  });
});

describe("Cloud activity (GCP / Azure) debug (#1736)", () => {
  it("records the Azure keys it chose and skips an unrecognized record", () => {
    const debug = spyRecorder();
    parseCloudActivity(
      JSON.stringify([
        {
          operationName: { value: "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE" },
          Caller: "marker-user@example.com",
          callerIpAddress: "198.51.100.77",
          eventTimestamp: "2024-01-01T00:00:00Z",
          resourceId:
            "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/markervm",
        },
        { unrelated: "marker-host.example.com" },
      ]),
      { debug },
    );
    expect(picked(debug.picks, "action")).toEqual(["operationName.value"]);
    // Keys match case-insensitively; the recorder names the candidate that matched.
    expect(picked(debug.picks, "user")).toEqual(["caller"]);
    expect(picked(debug.picks, "source_ip")).toEqual(["CallerIpAddress"]);
    expect(picked(debug.picks, "timestamp")).toEqual(["eventTimestamp"]);
    expect(debug.summary().skipped).toEqual({ unrecognized_record: 1 });
    expectNoMarkers(debug);
  });
});

describe("Microsoft 365 debug (#1736)", () => {
  it("records the UAL keys it chose and skips an unclassified record", () => {
    const debug = spyRecorder();
    parseM365Audit(
      JSON.stringify([
        {
          CreationTime: "2024-01-01T00:00:00",
          Operation: "FileAccessed",
          Workload: "SharePoint",
          UserKey: "marker-user@example.com",
          ClientIPAddress: "198.51.100.77",
        },
        { unrelated: "marker-host.example.com" },
      ]),
      { debug },
    );
    expect(picked(debug.picks, "user")).toEqual(["UserKey"]);
    expect(picked(debug.picks, "source_ip")).toEqual(["ClientIPAddress"]);
    expect(picked(debug.picks, "timestamp")).toEqual(["CreationTime"]);
    expect(debug.summary().skipped).toEqual({ unrecognized_record: 1 });
    expectNoMarkers(debug);
  });
});

describe("osquery debug (#1736)", () => {
  it("records the host and time keys, and skips a record with no query name", () => {
    const debug = spyRecorder();
    parseOsqueryLog(
      [
        JSON.stringify({
          name: "processes",
          host_identifier: "marker-host.example.com",
          calendarTime: "Mon Jan  1 00:00:00 2024 UTC",
          columns: { path: "/tmp/markervm", cmdline: "markervm --x" },
          action: "added",
        }),
        JSON.stringify({ columns: { path: "/tmp/x" } }),
      ].join("\n"),
      { debug },
    );
    expect(picked(debug.picks, "host")).toEqual(["host_identifier"]);
    expect(picked(debug.picks, "timestamp")).toEqual(["calendarTime"]);
    expect(debug.summary().skipped).toEqual({ missing_required_field: 1 });
    expectNoMarkers(debug);
  });
});

describe("no recorder (#1736)", () => {
  it("parses exactly as before when no recorder is passed", () => {
    const text = JSON.stringify([
      {
        eventType: "user.session.start",
        published: "2024-01-01T00:00:00Z",
        actor: { alternateId: "a@example.com" },
      },
    ]);
    expect(parseOktaSystemLog(text)).toEqual(
      parseOktaSystemLog(text, { debug: createImportDebugRecorder() }),
    );
  });
});
