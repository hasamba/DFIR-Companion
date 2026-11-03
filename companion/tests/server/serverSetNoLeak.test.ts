import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, getServerLogger, buildRuntimePipeline } from "../../src/server.js";
import { ServerSetStore } from "../../src/integrations/serverSets/serverSetStore.js";
import { deriveServerSetKey } from "../../src/integrations/serverSets/secretBox.js";
import type {
  IrisSettings,
  TimesketchSettings,
  VelociraptorSettings,
} from "../../src/integrations/serverSets/types.js";
import { createServerClients, type ServerClientBuilders } from "../../src/composition/serverSetClients.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { VeloMonitorStore } from "../../src/analysis/veloMonitorStore.js";
import { VeloHuntStore } from "../../src/analysis/veloHuntStore.js";
import { IrisExportStore } from "../../src/integrations/iris/irisExportStore.js";
import { VelociraptorClient, type VqlRunner } from "../../src/integrations/velociraptor/velociraptorApi.js";
import { AuditExportStore } from "../../src/analysis/auditExportStore.js";
import { AuditCursorStore } from "../../src/analysis/auditExportCursor.js";
import { createAuditExporter } from "../../src/integrations/audit/auditExporter.js";
import { decryptBuffer } from "../../src/analysis/caseEncryption.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import type { IrisClient } from "../../src/integrations/iris/irisClient.js";
import type { TimesketchClient } from "../../src/integrations/timesketch/timesketchClient.js";

// Task 8: a stored key never leaves the server set store. Three sentinels, one per tool, are pushed
// through every surface that could carry them; each surface is searched as raw bytes (and, for zips
// and the .dfircase container, as the unpacked entries as well).
const IRIS_KEY = "iris-key-sentinel-alpha";
const TS_PASS = "ts-pass-sentinel-bravo";
const VELO_CERT = "velo-cert-sentinel-charlie";
const SENTINELS = [IRIS_KEY, TS_PASS, VELO_CERT];

let dir: string;
let casesRoot: string;
let sets: ServerSetStore;
let cases: CaseStore;
let activity: ActivityLogStore;
let capture: string[];
let auditBodies: string[];
let veloConfigPath: string;

// A tiny stateful Client Monitoring table: add_client_monitoring puts the artifact in, rm takes it out.
const monitored = new Set<string>();
const veloRunner: VqlRunner = async (statements) => {
  const vql = statements.join("\n");
  const art = /artifact='([^']+)'/.exec(vql)?.[1];
  if (art && vql.includes("add_client_monitoring")) monitored.add(art);
  if (art && vql.includes("rm_client_monitoring")) monitored.delete(art);
  return { rows: [], raw: "" };
};

const builders: ServerClientBuilders = {
  iris: (_s: IrisSettings) =>
    ({
      ping: async () => undefined,
      findCaseByName: async () => null,
      createCase: async (b: { case_name: string }) => ({ caseId: 2, caseName: b.case_name }),
      setSummary: async () => undefined,
      iocTypeMap: async () => new Map(),
      assetTypeMap: async () => new Map(),
      eventCategoryMap: async () => new Map(),
      taskStatusMap: async () => new Map([["to do", 1]]),
      listAssets: async () => [],
      addAsset: async () => 1,
      listIocs: async () => [],
      addIoc: async () => 1,
      listEvents: async () => [],
      addEvent: async () => 1,
      listTasks: async () => [],
      addTask: async () => 1,
      listDirectories: async () => [],
      addDirectory: async () => 1,
      deleteDirectory: async () => undefined,
      addNote: async () => 1,
    }) as unknown as IrisClient,
  timesketch: (_s: TimesketchSettings) =>
    ({ login: async () => undefined, listSketches: async () => [] }) as unknown as TimesketchClient,
  velociraptor: (s: VelociraptorSettings) => {
    const client = new VelociraptorClient(
      {
        apiConfigPath: s.apiConfigPath,
        binary: "velociraptor",
        timeoutMs: 5000,
        maxRows: 1000,
        maxOutputBytes: 1024 * 1024,
      },
      veloRunner,
    );
    client.listMonitoredArtifacts = async () => [...monitored];
    return client;
  },
};

const fullSet = (name: string) => ({
  name,
  iris: { url: "https://iris.example.com", apiKey: IRIS_KEY },
  timesketch: { url: "https://ts.example.com", user: "analyst", password: TS_PASS },
  velociraptor: { apiConfigPath: veloConfigPath },
});

// Every file under a folder, recursively, as bytes.
function walk(root: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(root)) {
    const p = join(root, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

const hasZipMagic = (b: Buffer): boolean => b.length > 4 && b.readUInt32LE(0) === 0x04034b50;

// Raw bytes of the buffer, plus (for a zip) every unpacked entry, recursively. Returns the labels of
// every place a sentinel was found.
function leaksIn(label: string, buf: Buffer): string[] {
  const found: string[] = [];
  for (const s of SENTINELS) if (buf.indexOf(s) >= 0) found.push(`${label} contains ${s}`);
  if (hasZipMagic(buf)) {
    for (const e of readZip(buf)) found.push(...leaksIn(`${label}!${e.path}`, Buffer.from(e.data)));
  }
  return found;
}

const leaksInText = (label: string, text: string): string[] => leaksIn(label, Buffer.from(text, "utf8"));

function binaryParser(res: request.Response, cb: (err: Error | null, body: Buffer) => void): void {
  const chunks: Buffer[] = [];
  res.on("data", (c: Buffer) => chunks.push(c));
  res.on("end", () => cb(null, Buffer.concat(chunks)));
}

const bodyOf = (res: request.Response): Buffer =>
  Buffer.isBuffer(res.body) ? res.body : Buffer.from(res.text ?? JSON.stringify(res.body), "utf8");

async function makeApp() {
  const stateStore = new StateStore(cases);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store: cases,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const auditExportStore = new AuditExportStore(join(dir, "audit-export", "config.json"));
  const auditExportCursors = new AuditCursorStore(join(dir, "audit-export", "cursors.json"));
  const auditExporter = createAuditExporter({
    store: auditExportStore,
    cursors: auditExportCursors,
    activity,
    listCaseIds: async () => (await cases.listCases()).map((c) => c.caseId),
    transport: {
      fetchFn: (async (_url: string, init?: { body?: string }) => {
        auditBodies.push(String(init?.body ?? ""));
        return new Response(JSON.stringify({ text: "Success", code: 0 }), { status: 200 });
      }) as never,
      syslogSend: async (...a: unknown[]) => {
        auditBodies.push(JSON.stringify(a));
      },
      hostname: "h",
    },
  });
  return createApp(cases, {
    pipeline,
    stateStore,
    reportWriter: new ReportWriter(cases, stateStore),
    serverClients: createServerClients(sets, {}, builders),
    serverSetStore: sets,
    irisExportStore: new IrisExportStore(cases),
    veloHuntStore: new VeloHuntStore(cases),
    veloMonitorStore: new VeloMonitorStore(cases),
    activityLogStore: activity,
    auditExportStore,
    auditExportCursors,
    auditExporter,
  });
}

const restores: Array<() => void> = [];
function spyAllLogOutput(): void {
  const push = (...a: unknown[]): void => {
    capture.push(a.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" "));
  };
  const logger = getServerLogger();
  for (const m of ["debug", "info", "warn", "error"] as const) {
    restores.push(vi.spyOn(logger, m).mockImplementation(push).mockRestore);
  }
  for (const m of ["log", "info", "warn", "error", "debug"] as const) {
    restores.push(vi.spyOn(console, m).mockImplementation(push).mockRestore);
  }
  for (const stream of [process.stdout, process.stderr]) {
    const spy = vi.spyOn(stream, "write").mockImplementation((chunk: unknown) => {
      push(Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk));
      return true;
    });
    restores.push(spy.mockRestore);
  }
}

beforeEach(() => {
  capture = [];
  monitored.clear();
  auditBodies = [];
  dir = mkdtempSync(join(tmpdir(), "ss-noleak-"));
  casesRoot = join(dir, "cases");
  mkdirSync(casesRoot, { recursive: true });
  veloConfigPath = join(dir, "velo-api.config.yaml");
  writeFileSync(
    veloConfigPath,
    `ca_certificate: |\n  -----BEGIN CERTIFICATE-----\n  ${VELO_CERT}\n  -----END CERTIFICATE-----\nclient_private_key: |\n  -----BEGIN RSA PRIVATE KEY-----\n  ${VELO_CERT}\n  -----END RSA PRIVATE KEY-----\napi_connection_string: velo.example.com:8001\n`,
  );
  sets = new ServerSetStore(join(dir, "server-sets"), deriveServerSetKey(Buffer.alloc(32, 7)));
  cases = new CaseStore(casesRoot);
  activity = new ActivityLogStore(cases);
});
afterEach(() => {
  while (restores.length) restores.pop()!();
  vi.restoreAllMocks();
  rmSync(dir, { recursive: true, force: true });
});

describe("no key ever leaves the server set store", () => {
  it("is absent from every export, report, log, audit record and API response", async () => {
    const found: string[] = [];
    const seen = new Map<string, { status: number; bytes: number }>();
    const check = (label: string, res: request.Response): void => {
      const buf = bodyOf(res);
      seen.set(label, { status: res.status, bytes: buf.length });
      found.push(...leaksIn(label, buf));
    };

    const app = await makeApp();
    spyAllLogOutput();

    // 1. The server-set API: create (the only request that carries the keys), list, edit, test,
    //    default, then a second set to switch to, and delete of an unused one.
    const created = await request(app).post("/server-sets").send(fullSet("Alpha"));
    expect(created.status).toBe(201);
    check("POST /server-sets", created);
    const setA = created.body.id as string;
    const second = await request(app).post("/server-sets").send(fullSet("Bravo"));
    check("POST /server-sets (2)", second);
    const setB = second.body.id as string;
    const spare = await request(app).post("/server-sets").send(fullSet("Spare"));
    check("POST /server-sets (3)", spare);
    check("GET /server-sets", await request(app).get("/server-sets"));
    // An edit that keeps the stored secrets (the masked placeholder) must not echo them either.
    const edited = await request(app)
      .put(`/server-sets/${setA}`)
      .send({
        name: "Alpha",
        iris: { url: "https://iris.example.com", apiKey: "••••••" },
        timesketch: { url: "https://ts.example.com", user: "analyst", password: "••••••" },
        velociraptor: { apiConfigPath: veloConfigPath },
      });
    check("PUT /server-sets/:id", edited);
    check("POST /server-sets/:id/test", await request(app).post(`/server-sets/${setA}/test`).send({}));
    check("POST /server-sets/:id/default", await request(app).post(`/server-sets/${setA}/default`).send({}));
    check("DELETE /server-sets/:id", await request(app).delete(`/server-sets/${spare.body.id}`));

    // 2. A case on set A: push to IRIS, start and stop a monitor, change the set once.
    const make = await request(app)
      .post("/cases")
      .send({ caseId: "c1", name: "Case c1", investigator: "i", aiProvider: null, serverSetId: setA });
    check("POST /cases", make);
    check("GET /cases/c1/server-set", await request(app).get("/cases/c1/server-set"));
    const push = await request(app).post("/cases/c1/push/iris").send({});
    expect(push.status).toBe(200);
    check("POST /cases/c1/push/iris", push);
    const mon = await request(app)
      .post("/cases/c1/velociraptor/monitors")
      .send({ clientId: "C.1", artifact: "Windows.Events.ProcessCreation", pollSeconds: 60 });
    expect(mon.status).toBe(202);
    check("POST monitors", mon);
    const mid = mon.body.monitor.id as string;
    check("POST monitors/:mid/stop", await request(app).post(`/cases/c1/velociraptor/monitors/${mid}/stop`));
    const change = await request(app).post("/cases/c1/server-set").send({ setId: setB, confirm: true });
    expect(change.status).toBe(200);
    check("POST /cases/c1/server-set", change);
    check("GET /cases/c1/server-set (2)", await request(app).get("/cases/c1/server-set"));

    // 3. Reports, in every format the server writes or serves.
    check("POST report", await request(app).post("/cases/c1/report").send({}));
    for (const f of ["report.md", "report.html"]) {
      check(`GET ${f}`, await request(app).get(`/cases/c1/report/${f}`).buffer(true).parse(binaryParser));
    }
    for (const p of [
      "report.docx",
      "report/interactive",
      "export/stix",
      "iris-export",
      "clickup-export",
      "incident-timeline.csv",
      "timeline.jsonl",
      "super-timeline.jsonl",
      "handoff",
      "activity-log",
    ]) {
      check(`GET ${p}`, await request(app).get(`/cases/c1/${p}`).buffer(true).parse(binaryParser));
    }
    found.push(...leaksInText("activity store", JSON.stringify(await activity.load("c1"))));

    // 4. Redacted export, support bundle, audit export (a destination plus a back-fill of the case).
    check(
      "GET export/redacted",
      await request(app).get("/cases/c1/export/redacted").buffer(true).parse(binaryParser),
    );
    check(
      "POST support-bundle",
      await request(app)
        .post("/diagnostics/support-bundle")
        .send({ caseId: "c1", includeCaseLog: true })
        .buffer(true)
        .parse(binaryParser),
    );
    const dest = await request(app)
      .post("/audit-export")
      .send({
        type: "splunk",
        name: "SOC",
        splunk: { url: "https://splunk.example.com:8088", token: "hec-token-word" },
      });
    check("POST /audit-export", dest);
    check("POST audit backfill", await request(app).post(`/audit-export/${dest.body.id}/backfill`).send({}));
    expect(auditBodies.length).toBeGreaterThan(0);
    found.push(...leaksInText("audit export transport", auditBodies.join("\n")));

    // 5. The .dfircase export (decrypted here) and the case archive (zip).
    const enc = await request(app)
      .post("/cases/c1/export/encrypted")
      .send({ password: "a long enough password" })
      .buffer(true)
      .parse(binaryParser);
    expect(enc.status).toBe(200);
    check("POST export/encrypted (container)", enc);
    found.push(...leaksIn(".dfircase decrypted", await decryptBuffer(bodyOf(enc), "a long enough password")));
    const arch = await request(app).post("/cases/c1/archive").send({});
    expect(arch.status).toBe(200);
    check("POST archive", arch);
    found.push(...leaksIn("archive zip", readFileSync(arch.body.archivePath as string)));

    // 6. Server log output and every file under the cases root.
    found.push(...leaksInText("server log output", capture.join("\n")));
    expect(capture.length).toBeGreaterThan(0);
    const files = walk(casesRoot);
    expect(files.length).toBeGreaterThan(3);
    for (const f of files) found.push(...leaksIn(f.slice(dir.length), readFileSync(f)));

    // The search is only worth something if each surface really answered with content.
    const empty = [...seen]
      .filter(([, v]) => v.status >= 400 || v.bytes === 0)
      .map(([k, v]) => `${k}=${v.status}`);
    const mustAnswer = [
      "POST report",
      "GET report.md",
      "GET report.html",
      "GET report.docx",
      "GET handoff",
      "GET activity-log",
      "GET export/redacted",
      "POST support-bundle",
      "POST /audit-export",
      "POST audit backfill",
      "POST export/encrypted (container)",
      "POST archive",
    ];
    for (const label of mustAnswer) {
      expect(seen.get(label), label).toBeDefined();
      expect(
        empty.filter((e) => e.startsWith(`${label}=`)),
        label,
      ).toEqual([]);
    }
    // The activity log names the change, so the leak search covered a real entry.
    expect(seen.get("GET activity-log")!.bytes).toBeGreaterThan(50);

    expect(found).toEqual([]);
  });

  it("the set store keeps its keys encrypted at rest", () => {
    sets.create(fullSet("Alpha"));
    const storeDir = join(dir, "server-sets");
    const files = walk(storeDir);
    expect(files.map((f) => f.slice(storeDir.length + 1)).sort()).toEqual(
      expect.arrayContaining(["sets.json"]),
    );
    sets.linkCase("c1", sets.list()[0].id);
    for (const f of walk(storeDir)) expect(leaksIn(f, readFileSync(f)), f).toEqual([]);
    // The control: the same walk does find a sentinel when one is there.
    writeFileSync(join(storeDir, "probe.txt"), IRIS_KEY);
    expect(walk(storeDir).flatMap((f) => leaksIn(f, readFileSync(f)))).toHaveLength(1);
  });
});
