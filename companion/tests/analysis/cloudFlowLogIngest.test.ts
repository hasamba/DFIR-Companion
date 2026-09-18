import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import {
  correlateAwsFlowResourceAttribution,
  FLOW_ATTRIBUTION_MARKER,
} from "../../src/analysis/awsFlowResourceAttribution.js";
import { correlateAwsFlowIdentityExecution } from "../../src/analysis/awsFlowIdentityExecutionJoin.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #1294: the two non-AWS flow-log importers, end to end through the real pipeline, plus the
// detection-order and provider-gate guarantees the design doc pins.

const AZURE_BLOB = JSON.stringify({
  records: [
    {
      time: "2022-09-14T09:00:52.5625085Z",
      flowLogVersion: 4,
      flowLogGUID: "66aa66aa-bb77-cc88-dd99-00ee00ee00ee",
      macAddress: "112233445566",
      category: "FlowLogFlowEvent",
      flowLogResourceID:
        "/SUBSCRIPTIONS/AAAA0A0A-BB1B-CC2C-DD3D-EEEEEE4E4E4E/RESOURCEGROUPS/NW/PROVIDERS/MICROSOFT.NETWORK/NETWORKWATCHERS/NW_E/FLOWLOGS/VNETFLOWLOG",
      targetResourceID:
        "/subscriptions/aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/myVNet",
      operationName: "FlowLogFlowEvent",
      flowRecords: {
        flows: [
          {
            aclID: "00aa00aa-bb11-cc22-dd33-44ee44ee44ee",
            flowGroups: [
              {
                rule: "DefaultRule_AllowInternetOutBound",
                flowTuples: ["1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,3,767,2,1580"],
              },
              {
                rule: "BlockHighRiskTCPPortsFromInternet",
                flowTuples: ["1663145998065,101.33.218.153,10.0.0.6,55188,22,6,I,D,NX,0,0,0,0"],
              },
            ],
          },
        ],
      },
    },
  ],
});

const NSG_BLOB = JSON.stringify({
  records: [
    {
      time: "2018-11-13T12:00:35.3899262Z",
      systemId: "a0fca5ce-022c-47b1-9735-89943b42f2fa",
      category: "NetworkSecurityGroupFlowEvent",
      resourceId: "/SUBSCRIPTIONS/X/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/NSG",
      operationName: "NetworkSecurityGroupFlowEvents",
      properties: {
        Version: 2,
        flows: [
          {
            rule: "DefaultRule_DenyAllInBound",
            flows: [
              {
                mac: "000D3AF87856",
                flowTuples: ["1542110402,94.102.49.190,10.5.16.4,28746,443,U,I,D,B,,,,"],
              },
            ],
          },
        ],
      },
    },
  ],
});

const GCP_ENTRY = {
  insertId: "abc123",
  logName: "projects/my-proj/logs/compute.googleapis.com%2Fvpc_flows",
  resource: { type: "gce_subnetwork", labels: { project_id: "my-proj", subnetwork_name: "default" } },
  timestamp: "2024-05-01T10:00:05.000Z",
  jsonPayload: {
    connection: {
      src_ip: "10.128.0.2",
      dest_ip: "203.0.113.9",
      src_port: 51234,
      dest_port: 443,
      protocol: 6,
    },
    reporter: "SRC",
    bytes_sent: "8420",
    packets_sent: "12",
    start_time: "2024-05-01T09:59:58.123456Z",
    end_time: "2024-05-01T10:00:03.000000Z",
    src_instance: { project_id: "my-proj", region: "us-central1", zone: "us-central1-a", vm_name: "web-1" },
  },
};

async function makePipeline(caseId: string) {
  const root = await mkdtemp(join(tmpdir(), "dfir-cloudflow-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  const stateStore = new StateStore(cases);
  return new AnalysisPipeline({
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

describe("detection (#1294)", () => {
  it("claims an Azure VNet flow blob and a GCP vpc_flows export by their own kinds", () => {
    expect(detectImportKind("PT1H.json", AZURE_BLOB)).toBe("azureflowlog");
    expect(detectImportKind("flows.json", JSON.stringify([GCP_ENTRY]))).toBe("gcpflowlog");
  });
  it("a retired NSG blob is claimed by the Azure flow importer — so it can be refused BY NAME, not misparsed", () => {
    expect(detectImportKind("PT1H.json", NSG_BLOB)).toBe("azureflowlog");
  });
  it("neither flow predicate claims an Azure Activity, Azure Storage, AWS CloudTrail or GCP audit fixture", () => {
    const activity = JSON.stringify({
      records: [
        {
          operationName: "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
          caller: "a@b.c",
          resourceId: "/x",
          correlationId: "c",
        },
      ],
    });
    const storage = JSON.stringify([
      {
        category: "StorageRead",
        operationName: "GetBlob",
        identity: { type: "OAuth" },
        time: "2024-01-01T00:00:00Z",
      },
    ]);
    const cloudtrail = JSON.stringify({
      Records: [
        { eventName: "RunInstances", eventSource: "ec2.amazonaws.com", eventTime: "2024-01-01T00:00:00Z" },
      ],
    });
    const audit = JSON.stringify([
      { logName: "projects/p/logs/cloudaudit.googleapis.com%2Factivity", protoPayload: { methodName: "x" } },
    ]);
    for (const [fixture, expected] of [
      [activity, "cloud"],
      [storage, "azurestoragelog"],
      [cloudtrail, "aws"],
      [audit, "cloud"],
    ] as const) {
      expect(detectImportKind("x.json", fixture)).toBe(expected);
    }
  });
  it("the AWS text line still detects", () => {
    expect(
      detectImportKind(
        "f.txt",
        "2 123456789010 eni-1235b8ca 172.31.16.139 203.0.113.10 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK",
      ),
    ).toBe("awsflowlog");
  });
});

describe("ingest round-trip (#1294)", () => {
  it("Azure: two tuples land as two Low flow rows with the subscription and a public IOC", async () => {
    const pipeline = await makePipeline("az1");
    const state = await pipeline.importAzureFlowLog("az1", AZURE_BLOB, {
      label: "PT1H.json",
      idPrefix: "a1",
      importedAt: "2026-06-01T01:05:00Z",
    });
    const rows = state.forensicTimeline.filter((e) => e.canonical?.event.type === "flow");
    expect(rows).toHaveLength(2);
    expect(rows.every((e) => e.canonical?.cloud?.provider === "azure")).toBe(true);
    expect(rows.every((e) => e.canonical?.cloud?.accountId === "aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e")).toBe(
      true,
    );
    expect(state.iocs.map((i) => i.value)).toEqual(expect.arrayContaining(["192.0.2.180", "101.33.218.153"]));
    expect(state.iocs.map((i) => i.value)).not.toContain("10.0.0.6");
    expect(rows.some((e) => e.description.includes("inbound to NIC 112233445566, denied"))).toBe(true);
    expect(rows.some((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER))).toBe(false);
  });

  it("Azure: a retired NSG blob imports zero rows and the note names the refusal", async () => {
    const pipeline = await makePipeline("az2");
    const state = await pipeline.importAzureFlowLog("az2", NSG_BLOB, {
      label: "PT1H.json",
      idPrefix: "a2",
      importedAt: "2026-06-01T01:05:00Z",
    });
    expect(state.forensicTimeline.filter((e) => e.canonical?.event.type === "flow")).toHaveLength(0);
    const note = JSON.stringify(state);
    expect(note).toContain("retired NSG-format record(s) refused by name");
  });

  it("GCP: an entry lands as a Low flow row with the emitting project, the annotation, and the sampling caveat in the note", async () => {
    const pipeline = await makePipeline("g1");
    const state = await pipeline.importGcpFlowLog("g1", JSON.stringify([GCP_ENTRY]), {
      label: "flows.json",
      idPrefix: "g1",
      importedAt: "2026-06-01T01:05:00Z",
    });
    const rows = state.forensicTimeline.filter((e) => e.canonical?.event.type === "flow");
    expect(rows).toHaveLength(1);
    expect(rows[0].canonical?.cloud).toEqual({
      provider: "gcp",
      accountId: "my-proj",
      region: "us-central1",
      resource: "web-1",
    });
    expect(rows[0].description).toContain("Google's annotation");
    expect(state.iocs.map((i) => i.value)).toEqual(["203.0.113.9"]);
    expect(JSON.stringify(state)).toContain("VPC Flow Logs are sampled");
  });
});

describe("the AWS passes are provider-gated (#1294)", () => {
  let seq = 0;
  const T = "2024-05-14T12:00:00Z";
  const awsLaunch = (account: string): ForensicEvent =>
    ({
      id: `l${++seq}`,
      timestamp: T,
      description: "AWS compute lifecycle",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      canonical: {
        event: { category: "cloud", type: "compute-lifecycle" },
        cloud: { provider: "aws", accountId: account },
        awsCompute: { instanceId: "i-aaa", launch: { privateAddress: "10.0.0.6", time: T } },
      },
    }) as unknown as ForensicEvent;
  const flowFrom = (provider: string, account: string): ForensicEvent =>
    ({
      id: `f${++seq}`,
      timestamp: "2024-05-14T14:00:00Z",
      description: `${provider} flow`,
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      srcIp: "10.0.0.6",
      dstIp: "203.0.113.10",
      canonical: { event: { category: "network", type: "flow" }, cloud: { provider, accountId: account } },
    }) as unknown as ForensicEvent;

  it("an Azure or GCP flow row whose account id collides with an AWS account is never attributed to the AWS instance", () => {
    const events = [
      awsLaunch("123456789012"),
      flowFrom("azure", "123456789012"),
      flowFrom("gcp", "123456789012"),
      flowFrom("aws", "123456789012"),
    ];
    const out = correlateAwsFlowIdentityExecution(correlateAwsFlowResourceAttribution(events));
    const attributed = out.filter((e) => e.description.includes(FLOW_ATTRIBUTION_MARKER));
    expect(attributed).toHaveLength(1);
    expect(attributed[0].canonical?.cloud?.provider).toBe("aws");
  });
});
