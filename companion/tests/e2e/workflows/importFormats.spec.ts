import { test, expect } from "../fixtures/test.js";
import type { APIRequestContext } from "@playwright/test";

// Covers: US-017, US-018, US-019, US-020, US-021, US-022, US-023, US-024, US-025, US-026, US-027,
// Covers: US-028, US-029, US-030, US-031, US-034
// (feature-user-stories.csv) — the remaining tool-specific evidence importers.
//
// One row per format, each carrying a payload in that tool's real output shape. The assertion is
// that ingested CONTENT reaches the case state, not that the route answered 202: an importer that
// accepts a file and maps nothing is the failure mode worth catching, and it is invisible to a
// status-code check.
//
// Table-driven rather than sixteen near-identical tests, so adding a format is a row. Each case
// still fails independently and names itself.

interface FormatCase {
  story: string;
  route: string;
  /** Body field this route reads the payload from. */
  field: "text" | "json" | "csv";
  payload: string;
  /** Text that must reach the case state once the payload is mapped. */
  needle: string;
}

const CHAINSAW = JSON.stringify([
  {
    group: "Sigma",
    kind: "individual",
    name: "PsExec Service Installation",
    level: "high",
    timestamp: "2026-05-16T08:22:00Z",
    document: {
      kind: "evtx",
      path: "dc01-system.evtx",
      data: {
        Event: {
          System: {
            EventID: 7045,
            Computer: "DC01",
            Channel: "System",
            TimeCreated: { "#attributes": { SystemTime: "2026-05-16T08:22:00Z" } },
          },
          EventData: { ServiceName: "PSEXESVC", ImagePath: "C:\\Windows\\PSEXESVC.exe" },
        },
      },
    },
  },
]);

const HAYABUSA_CSV = [
  '"Timestamp","Computer","Channel","EventID","Level","MitreTactics","RuleTitle","Details"',
  '"2026-05-16 08:22:00.000 +00:00","DC01","Sec","4688","high","Execution","Suspicious PsExec Execution","Cmdline: PSEXESVC.exe"',
].join("\n");

const VELOCIRAPTOR = [
  {
    Timestamp: "2026-05-16T08:30:00Z",
    Name: "Windows.Persistence.PermanentWMIEvent",
    RuleName: "WMI Event Consumer Persistence",
    FullPath: "C:\\Windows\\System32\\wbem\\scrcons.exe",
    Level: "high",
    Executable: "scrcons.exe",
  },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

// Suricata EVE JSON — one alert per line.
const NETWORK = [
  {
    timestamp: "2026-05-18T02:30:00.000000+0000",
    event_type: "alert",
    src_ip: "10.0.0.5",
    dest_ip: "185.220.101.47",
    dest_port: 443,
    proto: "TCP",
    alert: { signature: "ET MALWARE Observed DNS Query to Cobalt Strike Domain", severity: 1 },
  },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

// KAPE / EZ Tools Prefetch CSV — the importer detects the tool from the header.
const KAPE_CSV = [
  "SourceFilename,ExecutableName,RunCount,LastRun,Size,Hash",
  "C:\\Windows\\Prefetch\\EVIL.EXE-1234ABCD.pf,EVIL.EXE,7,2026-05-16 08:25:00,123456,1234ABCD",
].join("\n");

// Cyber Triage JSONL. Three things the shape has to get right, each of which silently produced a
// row that vanished: the time field is event_timestamp/datetime (not "time"); the description
// comes from message; and the verdict is `score` containing "Notable" — threat_level is the CSV
// form only, and a NUMERIC score is not a verdict at all. Without a notable verdict the row is
// treated as unscored telemetry and lands as an Info evidence event rather than in the timeline,
// so the import reports events:1 while the case state never mentions it.
//
// The needle is the artifact name rather than the message because a row carrying a `path` is
// described BY that path — with path present the message never reaches the description. Verified
// against the running importer, not assumed.
const CYBERTRIAGE = [
  {
    event_timestamp: "2026-05-16T09:00:00Z",
    item_type: "Startup Item",
    name: "updater.exe",
    message: "Unsigned binary registered to run at logon",
    score: "Notable",
    scoreDescription: "Bad list item detected",
    path: "C:\\Users\\jsmith\\AppData\\Roaming\\updater.exe",
    hostName: "WKSTN-JSMITH",
  },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

const M365 = [
  {
    CreationTime: "2026-05-17T11:05:00",
    Operation: "Add-MailboxPermission",
    UserId: "attacker@contoso.com",
    ClientIP: "185.220.101.47",
    Workload: "Exchange",
    ResultStatus: "Success",
  },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

const AWS = JSON.stringify({
  Records: [
    {
      eventTime: "2026-05-17T12:00:00Z",
      eventName: "ConsoleLogin",
      eventSource: "signin.amazonaws.com",
      sourceIPAddress: "185.220.101.47",
      awsRegion: "us-east-1",
      userIdentity: { type: "IAMUser", userName: "svc-backup" },
      additionalEventData: { MFAUsed: "No" },
    },
  ],
});

// GCP Cloud Audit Log shape.
const CLOUD_ACTIVITY = [
  {
    timestamp: "2026-05-17T13:00:00Z",
    protoPayload: {
      methodName: "google.iam.admin.v1.CreateServiceAccountKey",
      authenticationInfo: { principalEmail: "attacker@contoso.com" },
      requestMetadata: { callerIp: "185.220.101.47" },
    },
    resource: { type: "service_account" },
  },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

// Plaso psort "dynamic" CSV export. The importer rejects JSON outright: it wants
// datetime,message,… (dynamic) or date,time,…,desc,… (l2tcsv).
const PLASO = [
  "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag",
  "2026-05-16T08:22:00.000000+00:00,Content Modification Time,REG,Registry Key,PSEXESVC.exe service installed on DC01,winreg,OS:/Windows/System32/PSEXESVC.exe,",
].join("\n");

const SANDBOX = JSON.stringify({
  info: { id: 1337, score: 9.2, category: "file" },
  target: {
    file: {
      name: "invoice.exe",
      sha256: "9f2c1a5b7d3e4f6089ab12cd34ef56789abcdef0123456789abcdef012345678",
    },
  },
  signatures: [
    { name: "injection_runpe", description: "Executed a process using RunPE injection", severity: 3 },
  ],
});

// Volatility 3 JSON renderer output: a flat array of row objects.
const MEMORY = JSON.stringify([
  {
    PID: 4821,
    PPID: 812,
    ImageFileName: "rundll32.exe",
    Path: "C:\\Windows\\System32\\rundll32.exe",
    CreateTime: "2026-05-16 08:30:00.000000",
    Protection: "PAGE_EXECUTE_READWRITE",
  },
]);

const EMAIL = [
  "From: billing@contoso-invoices.com",
  "To: jsmith@contoso.com",
  "Subject: Overdue invoice INV-88231",
  "Date: Mon, 18 May 2026 02:20:00 +0000",
  "Message-ID: <abc123@contoso-invoices.com>",
  "",
  "Please review the attached invoice.",
].join("\n");

const THEHIVE = JSON.stringify([
  {
    _type: "alert",
    title: "Suspicious PowerShell on WKSTN-JSMITH",
    description: "Encoded command observed",
    severity: 3,
    date: 1779000000000,
    observables: [{ dataType: "ip", data: "185.220.101.47" }],
  },
]);

// Falco / sysdig JSON events.
const SYSDIG = [
  {
    time: "2026-05-18T03:00:00.000000000Z",
    rule: "Terminal shell in container",
    priority: "Critical",
    output: "A shell was spawned in a container (user=root container=web-01)",
    output_fields: { "proc.name": "bash", "container.name": "web-01" },
  },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

const SIEM = JSON.stringify([
  {
    "@timestamp": "2026-05-16T08:22:00Z",
    event: { code: "4688", provider: "Microsoft-Windows-Security-Auditing" },
    host: { name: "DC01" },
    winlog: {
      channel: "Security",
      event_id: 4688,
      event_data: { NewProcessName: "C:\\Windows\\PSEXESVC.exe", SubjectUserName: "jsmith" },
    },
    message: "A new process has been created: PSEXESVC.exe",
  },
]);

const FORMATS: readonly FormatCase[] = [
  { story: "US-017", route: "import-siem", field: "json", payload: SIEM, needle: "PSEXESVC" },
  { story: "US-018", route: "import-chainsaw", field: "json", payload: CHAINSAW, needle: "PSEXESVC" },
  { story: "US-019", route: "import-hayabusa", field: "text", payload: HAYABUSA_CSV, needle: "PsExec" },
  {
    story: "US-020",
    route: "import-velociraptor",
    field: "text",
    payload: VELOCIRAPTOR,
    needle: "WMI Event Consumer",
  },
  { story: "US-021", route: "import-network", field: "text", payload: NETWORK, needle: "185.220.101.47" },
  { story: "US-022", route: "import-kape", field: "text", payload: KAPE_CSV, needle: "EVIL.EXE" },
  {
    story: "US-023",
    route: "import-cybertriage",
    field: "text",
    payload: CYBERTRIAGE,
    needle: "updater.exe",
  },
  { story: "US-024", route: "import-m365", field: "text", payload: M365, needle: "Add-MailboxPermission" },
  { story: "US-025", route: "import-aws", field: "text", payload: AWS, needle: "ConsoleLogin" },
  {
    story: "US-026",
    route: "import-cloud-activity",
    field: "text",
    payload: CLOUD_ACTIVITY,
    needle: "CreateServiceAccountKey",
  },
  { story: "US-027", route: "import-plaso", field: "text", payload: PLASO, needle: "PSEXESVC" },
  { story: "US-028", route: "import-sandbox", field: "text", payload: SANDBOX, needle: "invoice.exe" },
  { story: "US-029", route: "import-memory", field: "text", payload: MEMORY, needle: "rundll32.exe" },
  { story: "US-030", route: "import-email", field: "text", payload: EMAIL, needle: "Overdue invoice" },
  {
    story: "US-031",
    route: "import-thehive",
    field: "text",
    payload: THEHIVE,
    needle: "Suspicious PowerShell",
  },
  {
    story: "US-034",
    route: "import-sysdig",
    field: "text",
    payload: SYSDIG,
    needle: "Terminal shell in container",
  },
];

async function stateContains(request: APIRequestContext, caseId: string, needle: string): Promise<boolean> {
  const res = await request.get(`/cases/${caseId}/state`);
  if (!res.ok()) return false;
  return (await res.text()).includes(needle);
}

for (const fmt of FORMATS) {
  test(`${fmt.story}: ${fmt.route} maps its payload into the case`, async ({ page, demoCase }) => {
    await page.goto(`/dashboard?caseId=${encodeURIComponent(demoCase)}`);

    const res = await page.request.post(`/cases/${demoCase}/${fmt.route}`, {
      data: { [fmt.field]: fmt.payload, filename: `${fmt.route}-fixture` },
    });
    expect(res.status(), await res.text()).toBe(202);

    // The content check, not the status code: an importer that accepts a file and maps nothing
    // still answers 202.
    await expect
      .poll(() => stateContains(page.request, demoCase, fmt.needle), {
        timeout: 60_000,
        intervals: [500],
      })
      .toBe(true);
  });
}
