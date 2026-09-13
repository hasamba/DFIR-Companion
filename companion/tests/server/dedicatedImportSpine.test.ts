import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { AnalysisRunStore } from "../../src/analysis/analysisRunStore.js";
import { ImportLock } from "../../src/analysis/importLock.js";
import type { AIProvider, AnalyzeRequest, AnalyzeResult } from "../../src/providers/provider.js";
import { pollFor, POLL_TIMEOUT_MS } from "../helpers/poll.js";

// #956. Every dedicated `import-*` route used to call its importer and resynthesize — no lock, no
// snapshot, no super-timeline dual-write, no tagger window, no demote, no import record, no undo
// checkpoint — so an Info row imported through one stayed in the forensic timeline the model reads
// and never reached the super-timeline. The generic route, `/import-file` and (since #962)
// `/import-leapp` ran the spine; these did not. Now every route commits through the same
// orchestrator (routes/importCommit.ts). This suite drives each route with the smallest artifact
// its preview parser accepts and asserts the PERSISTED stores, not the importer's return value.

interface RouteCase {
  route: string;
  kind: string;
  filename: string;
  text: string;
  /** Body field the route reads the artifact from. */
  field?: "text" | "csv";
  /** Lab evidence never enters the delta (#932 item 5): the importer writes the super-timeline
   *  itself, so the seam sees nothing to add and the count it reports stays 0. */
  seamAddsNothing?: boolean;
  /** The importer is an LLM call — needs the text provider and AI switched on. */
  ai?: boolean;
}

const ISO = "2026-05-02T10:00:00Z";
const ndjson = (...rows: unknown[]): string => rows.map((r) => JSON.stringify(r)).join("\n") + "\n";

const CASES: RouteCase[] = [
  {
    route: "import-thor",
    kind: "thor",
    filename: "thor.json",
    text: ndjson(
      {
        level: "Warning",
        module: "Filescan",
        message: "Suspicious file",
        time: ISO,
        file: "C:\\Temp\\a.exe",
      },
      { level: "Notice", module: "Filescan", message: "Noticed file", time: ISO, file: "C:\\Temp\\b.exe" },
    ),
  },
  {
    route: "import-siem",
    kind: "siem",
    filename: "elastic.json",
    text: JSON.stringify({
      data: [
        {
          _source: {
            "@timestamp": "2017-03-20T06:33:40Z",
            log_name: "Security",
            computer_name: "DC1",
            event_id: 4624,
            event_data: { TargetUserName: "martin", LogonType: "3", IpAddress: "10.10.200.11" },
          },
        },
        {
          _source: {
            "@timestamp": "2017-03-20T06:34:40Z",
            log_name: "Security",
            computer_name: "DC1",
            event_id: 4634,
            event_data: { TargetUserName: "martin", LogonType: "3" },
          },
        },
      ],
    }),
  },
  {
    route: "import-chainsaw",
    kind: "chainsaw",
    filename: "chainsaw.json",
    text: JSON.stringify([
      {
        name: "Suspicious Logon",
        level: "medium",
        timestamp: ISO,
        document: {
          data: {
            Event: { System: { EventID: 4624, Computer: "WS1" }, EventData: { TargetUserName: "bob" } },
          },
        },
      },
    ]),
  },
  {
    route: "import-hayabusa",
    kind: "hayabusa",
    filename: "hayabusa.csv",
    text:
      "Timestamp,Computer,Channel,EventID,Level,RuleTitle,Details\n" +
      "2026-05-02 10:00:00.000 +00:00,WS1,Sec,4624,info,Logon,User: bob\n" +
      "2026-05-02 10:01:00.000 +00:00,WS1,Sec,4688,low,Proc Exec,Cmd: whoami\n",
  },
  {
    route: "import-velociraptor",
    kind: "velociraptor",
    filename: "pslist.json",
    text: JSON.stringify([
      {
        _Source: "Windows.System.Pslist",
        Name: "notepad.exe",
        Pid: 12,
        Ppid: 4,
        CommandLine: "notepad.exe",
        Exe: "C:\\Windows\\notepad.exe",
        CreateTime: ISO,
      },
    ]),
  },
  {
    route: "import-network",
    kind: "network",
    filename: "eve.json",
    text: ndjson({
      timestamp: "2026-05-02T10:00:00.000000+0000",
      event_type: "alert",
      src_ip: "10.0.0.5",
      src_port: 4444,
      dest_ip: "10.0.0.9",
      dest_port: 80,
      proto: "TCP",
      alert: {
        signature: "ET POLICY curl User-Agent",
        category: "Attempted Information Leak",
        severity: 3,
        signature_id: 1,
      },
    }),
  },
  {
    route: "import-kape",
    kind: "kape",
    filename: "MFT.csv",
    text:
      "EntryNumber,SequenceNumber,InUse,ParentPath,FileName,Extension,FileSize,Created0x10,LastModified0x10\n" +
      "1,1,True,.\\Users\\bob,notes.txt,.txt,12,2026-05-02 10:00:00.0000000,2026-05-02 10:00:00.0000000\n",
  },
  {
    route: "import-cybertriage",
    kind: "cybertriage",
    filename: "cybertriage.json",
    text: JSON.stringify([
      {
        type: "process",
        name: "notepad.exe",
        path: "C:\\Windows\\notepad.exe",
        startTime: ISO,
        score: "unknown",
      },
    ]),
  },
  {
    route: "import-m365",
    kind: "m365",
    filename: "ual.json",
    text: JSON.stringify([
      {
        CreationTime: "2026-05-02T10:00:00",
        Operation: "UserLoggedIn",
        UserId: "bob@corp.example",
        ClientIP: "10.0.0.5",
        ResultStatus: "Success",
        Workload: "AzureActiveDirectory",
      },
    ]),
  },
  {
    route: "import-aws",
    kind: "aws",
    filename: "cloudtrail.json",
    text: JSON.stringify({
      Records: [
        {
          eventTime: ISO,
          eventName: "DescribeInstances",
          eventSource: "ec2.amazonaws.com",
          userIdentity: { type: "IAMUser", userName: "bob" },
          sourceIPAddress: "10.0.0.5",
          awsRegion: "us-east-1",
        },
      ],
    }),
  },
  {
    route: "import-cloud-activity",
    kind: "cloud",
    filename: "gcp.json",
    text: JSON.stringify([
      {
        protoPayload: {
          methodName: "v1.compute.instances.list",
          authenticationInfo: { principalEmail: "bob@corp.example" },
          requestMetadata: { callerIp: "10.0.0.5" },
        },
        timestamp: ISO,
        resource: { type: "gce_instance" },
      },
    ]),
  },
  {
    route: "import-plaso",
    kind: "plaso",
    filename: "plaso.csv",
    text:
      "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n" +
      "2026-05-02T10:00:00+00:00,Content Modification Time,FILE,NTFS USN change,C:\\Users\\bob\\notes.txt,usnjrnl,OS:/C:/Users/bob/notes.txt,\n",
  },
  {
    route: "import-sandbox",
    kind: "sandbox",
    filename: "report.json",
    seamAddsNothing: true,
    text: JSON.stringify({
      info: { id: 1, started: "2026-05-02 10:00:00", ended: "2026-05-02 10:02:00" },
      target: { file: { name: "a.exe", sha256: "a".repeat(64), md5: "b".repeat(32) } },
      signatures: [{ name: "persistence_autorun", severity: 3, description: "Installs an autorun" }],
      behavior: { summary: { files: ["C:\\Temp\\a.exe"] } },
    }),
  },
  {
    route: "import-memory",
    kind: "memory",
    filename: "pslist.json",
    text: JSON.stringify([
      {
        PID: 12,
        PPID: 4,
        ImageFileName: "notepad.exe",
        CreateTime: ISO,
        Offset: 1,
        Threads: 1,
        Handles: 1,
        SessionId: 1,
        Wow64: false,
      },
    ]),
  },
  {
    route: "import-email",
    kind: "email",
    filename: "mail.eml",
    text:
      "From: alice@corp.example\nTo: bob@corp.example\nSubject: hello\n" +
      "Date: Sat, 02 May 2026 10:00:00 +0000\nMessage-ID: <1@corp.example>\n\nhi\n",
  },
  {
    route: "import-thehive",
    kind: "thehive",
    filename: "cases.json",
    text: JSON.stringify([
      { _type: "case", number: 1, title: "Phish", severity: 1, createdAt: 1777716000000, status: "Open" },
    ]),
  },
  {
    route: "import-auditd",
    kind: "auditd",
    filename: "audit.log",
    text:
      'type=SYSCALL msg=audit(1777716000.000:1): arch=c000003e syscall=59 success=yes exit=0 comm="ls" exe="/usr/bin/ls" uid=1000 auid=1000\n' +
      'type=EXECVE msg=audit(1777716000.000:1): argc=1 a0="ls"\n',
  },
  {
    route: "import-journald",
    kind: "journald",
    filename: "journal.json",
    text: ndjson({
      __REALTIME_TIMESTAMP: "1777716000000000",
      _HOSTNAME: "srv1",
      SYSLOG_IDENTIFIER: "systemd",
      MESSAGE: "Started Session 1 of user bob.",
      PRIORITY: "6",
    }),
  },
  {
    route: "import-sysdig",
    kind: "sysdig",
    filename: "falco.json",
    text: ndjson({
      time: "2026-05-02T10:00:00.000000000Z",
      rule: "Terminal shell in container",
      priority: "Notice",
      output: "10:00:00 Notice A shell was spawned (user=bob)",
      output_fields: { "proc.name": "bash", "user.name": "bob" },
    }),
  },
  {
    route: "import-wazuh",
    kind: "wazuh",
    filename: "alerts.json",
    text: ndjson({
      timestamp: "2026-05-02T10:00:00.000+0000",
      rule: { level: 3, description: "PAM: Login session opened.", id: "5501" },
      agent: { name: "srv1", id: "001" },
      full_log: "pam_unix(sshd:session): session opened for user bob",
    }),
  },
  {
    route: "import-log",
    kind: "log",
    filename: "auth.log",
    ai: true,
    text: "May  2 10:00:00 srv1 sshd[100]: Accepted password for bob from 10.0.0.5 port 5000 ssh2\n",
  },
  {
    route: "import-csv",
    kind: "csv",
    filename: "rows.csv",
    field: "csv",
    ai: true,
    text: "time,host,event\n2026-05-02T10:00:00Z,srv1,login\n",
  },
];

// The text model answers every call — extraction and synthesis — with one Info event and no
// findings, so an AI-path import lands exactly one row for the seam to grade.
class InfoRowProvider implements AIProvider {
  readonly name = "text";
  readonly model = "mock-model";
  async analyze(_req: AnalyzeRequest): Promise<AnalyzeResult> {
    return {
      rawText: JSON.stringify({
        findings: [],
        iocs: [],
        mitreTechniques: [],
        threadsOpened: [],
        threadsClosed: [],
        timelineNote: "read rows",
        summary: "",
        attackerPath: "",
        forensicEvents: [
          {
            id: "e1",
            timestamp: ISO,
            description: "login from CSV row",
            severity: "Info",
            mitreTechniques: [],
            relatedFindingIds: [],
          },
        ],
      }),
    };
  }
}

async function makeApp(opts: { ai?: boolean; importLock?: ImportLock } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-956-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const analysisRunStore = new AnalysisRunStore(store, { appVersion: "test" });
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: opts.ai ? new InfoRowProvider() : undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    superTimelineStore,
    importMetaStore,
    analysisRunStore,
    // Without the gate-control store demote is a no-op (composition/importIngest.ts).
    forensicGateControlStore: new ForensicGateControlStore(store),
    activityLogStore: new ActivityLogStore(store),
    ...(opts.importLock ? { importLock: opts.importLock } : {}),
  });
  await request(app)
    .post("/cases")
    .send({ caseId: "c1", name: "n", investigator: "i", aiProvider: opts.ai ? "mock" : null });
  if (opts.ai) await request(app).post("/cases/c1/ai-control").send({ enabled: true });
  return { app, stateStore, superTimelineStore, analysisRunStore };
}

interface Meta {
  lastImportKind: string;
  lastImportFile: string;
  superTimelineAddedCount: number;
  path: string;
}

async function waitForImportRecord(app: ReturnType<typeof createApp>, file: string): Promise<Meta> {
  return pollFor(`the import ${file} to record its import-meta`, async () => {
    const meta = (await request(app).get("/cases/c1/import-meta")).body as Meta;
    return meta.lastImportFile === file ? meta : undefined;
  });
}

describe("dedicated import routes run the commit spine (#956)", () => {
  for (const c of CASES) {
    it(
      `POST /cases/:id/${c.route} records the import, keeps Info out of the forensic timeline and dual-writes the super-timeline`,
      async () => {
        const { app, stateStore, superTimelineStore, analysisRunStore } = await makeApp({ ai: c.ai });
        const res = await request(app)
          .post(`/cases/c1/${c.route}`)
          .send({ [c.field ?? "text"]: c.text, filename: c.filename });
        expect(res.status, JSON.stringify(res.body)).toBe(202);

        const meta = await waitForImportRecord(app, res.body.file as string);
        expect(meta.lastImportKind).toBe(c.kind);
        expect(meta.path).toBe(c.ai ? "ai" : "deterministic");

        // Demote ran: nothing Info is left where the model reads.
        const state = await stateStore.load("c1");
        const info = state.forensicTimeline.filter((e) => e.severity === "Info");
        expect(
          info,
          `Info rows left in the forensic timeline: ${info.map((e) => e.description).join(" | ")}`,
        ).toEqual([]);

        // Dual-write ran: every row the import added is searchable in the super-timeline.
        const superTotal = (await superTimelineStore.query("c1", {})).total;
        expect(superTotal).toBeGreaterThanOrEqual(1);
        if (c.seamAddsNothing) expect(meta.superTimelineAddedCount).toBe(0);
        else expect(meta.superTimelineAddedCount).toBe(superTotal);

        // The analysis-run record names this artifact, like the generic route's does. It is written
        // AFTER import-meta, so poll rather than read once.
        const run = await pollFor(`the ${c.kind} analysis-run record`, async () =>
          (await analysisRunStore.list("c1")).find(
            (r) => r.kind === "import" && r.versions.importer?.startsWith(`${c.kind}/`),
          ),
        );
        expect(run).toBeTruthy();
      },
      POLL_TIMEOUT_MS * 2,
    );
  }

  it("waits for the case's import lock, like the generic route", async () => {
    const importLock = new ImportLock();
    const release = await importLock.acquire("c1");
    try {
      const { app, superTimelineStore } = await makeApp({ importLock });
      const siem = CASES.find((c) => c.route === "import-siem")!;
      const res = await request(app)
        .post("/cases/c1/import-siem")
        .send({ text: siem.text, filename: siem.filename });
      expect(res.status).toBe(202); // accepted before the section is taken
      await new Promise((r) => setTimeout(r, 300));
      expect((await superTimelineStore.query("c1", {})).total).toBe(0); // nothing lands while another import holds the case
      release();
      await waitForImportRecord(app, res.body.file as string);
      expect((await superTimelineStore.query("c1", {})).total).toBe(2);
    } finally {
      release();
    }
  });

  it("records a failed importer as an import failure and releases the section", async () => {
    const { app, stateStore, superTimelineStore } = await makeApp();
    const thor = CASES.find((c) => c.route === "import-thor")!;
    // Break the merge under the first import: the importer throws, the route must record the
    // failure (not swallow it) and release the section so the NEXT import still lands.
    const save = stateStore.save.bind(stateStore);
    stateStore.save = async () => {
      throw new Error("disk full (staged)");
    };
    const first = await request(app)
      .post("/cases/c1/import-thor")
      .send({ text: thor.text, filename: thor.filename });
    expect(first.status).toBe(202);
    const failure = await pollFor("the failure to reach the diagnostics ring", async () => {
      const { report } = (await request(app).get("/diagnostics")).body as {
        report: {
          importers: {
            recentFailures: Array<{ caseId: string; kind: string; filename: string; error: string }>;
          };
        };
      };
      return report.importers.recentFailures.find((f) => f.caseId === "c1");
    });
    expect(failure).toMatchObject({
      kind: "thor",
      filename: first.body.file,
      error: expect.stringContaining("disk full"),
    });
    expect((await superTimelineStore.query("c1", {})).total).toBe(0);

    stateStore.save = save;
    const second = await request(app)
      .post("/cases/c1/import-thor")
      .send({ text: thor.text, filename: thor.filename });
    expect(second.status).toBe(202);
    const meta = await waitForImportRecord(app, second.body.file as string);
    expect(meta.lastImportKind).toBe("thor");
    expect((await superTimelineStore.query("c1", {})).total).toBe(2);
  });
});
