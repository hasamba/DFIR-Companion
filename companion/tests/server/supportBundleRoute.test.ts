import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp, setServerLogger, buildRuntimePipeline } from "../../src/server.js";
import { LoggerImpl, createConsoleLogger } from "../../src/logging/logger.js";
import { createRotatingDebugLog } from "../../src/logging/debugLogSink.js";
import { CustomEntitiesStore } from "../../src/analysis/anonEntities.js";
import { hashCasePassword } from "../../src/analysis/casePassword.js";
import { readZip } from "../../src/analysis/zipArchive.js";
import { resolveRequestPolicy } from "../../src/auth/policy.js";

// #1735 acceptance: at log level `info`, a failed import still leaves debug lines behind, and the
// redacted support bundle carries them — with none of the seeded real values anywhere in the zip.

const CASE_ID = "acme-breach-seed7";
const CASE_NAME = "Acme Seedwidget Breach";
const INVESTIGATOR = "Dana Seedperson";
const HOST = "WKS-SEED-042";
const USER = "SEEDCORP\\jseedsmith";
const INTERNAL_IP = "10.20.30.40";
const PUBLIC_IP = "203.0.113.77";
const URL_HOST = "vr.seed-example.com";
// Assembled at runtime so the secret scanners do not flag a fake key in the source.
const SECRET = ["seed", "only", "for", "tests", "marker"].join("-");
const SECRET_ENV = "DFIR_TEST_SUPPORT_BUNDLE_API_KEY";

const CHAINSAW_HUNT = [
  {
    group: "Sigma",
    kind: "individual",
    document: { kind: "evtx", path: "Sysmon.evtx", data: { Event: { System: { EventID: 1 } } } },
    rule: { name: "Suspicious Command", level: "high", tags: ["attack.execution"] },
    timestamp: "2023-01-02T10:00:00.000Z",
  },
];

let root: string;
let logDir: string;
let store: CaseStore;
let logger: LoggerImpl;

async function bundle(app: ReturnType<typeof createApp>, body: object) {
  const res = await request(app)
    .post("/diagnostics/support-bundle")
    .send(body)
    .buffer(true)
    .parse((r, cb) => {
      const chunks: Buffer[] = [];
      r.on("data", (c: Buffer) => chunks.push(c));
      r.on("end", () => cb(null, Buffer.concat(chunks)));
    });
  return res;
}

function entries(zip: Buffer): Map<string, string> {
  return new Map(readZip(zip).map((e) => [e.path, e.data.toString("utf8")]));
}

async function setup() {
  await store.createCase({ caseId: CASE_ID, name: CASE_NAME, investigator: INVESTIGATOR, aiProvider: null });
  await new CustomEntitiesStore(store).save(CASE_ID, [
    { value: HOST, category: "HOST" },
    { value: "jseedsmith", category: "USER" },
  ]);
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore });
  logger.debug(
    `probe host ${HOST} user ${USER} from ${INTERNAL_IP} to ${PUBLIC_IP} via https://${URL_HOST}/api?token=${SECRET}`,
    { caseId: CASE_ID },
  );
  logger.info(`case ${CASE_NAME} opened by ${INVESTIGATOR} at ${root}`, { caseId: CASE_ID });
  // A real import failure (EEXIST on the evidence copy — see diagnostics.test.ts), so the ring holds
  // one entry and its stored file exists for the shape report.
  const src = join(await mkdtemp(join(tmpdir(), "dfir-sb-src-")), "seedhunt.json");
  await writeFile(src, JSON.stringify(CHAINSAW_HUNT), "utf8");
  await store.saveImport(CASE_ID, "0001_seedhunt.json", "EventID,TimeCreated\n4624,2023-01-02T10:00:00Z\n");
  const failed = await request(app).post(`/cases/${CASE_ID}/import-file`).send({ path: src });
  expect(failed.status).toBe(500);
  return app;
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-sb-"));
  logDir = await mkdtemp(join(tmpdir(), "dfir-sb-logs-"));
  store = new CaseStore(root);
  logger = new LoggerImpl({
    level: "info",
    console: false,
    sessionLogPath: join(logDir, "session-test.log"),
    caseLogPath: (id) => join(store.caseDir(id), "logs", "session-test.log"),
    debugLog: createRotatingDebugLog({ dir: logDir, maxBytes: 4 * 1024 * 1024 }),
  });
  setServerLogger(logger);
  process.env[SECRET_ENV] = SECRET;
});

afterEach(async () => {
  delete process.env[SECRET_ENV];
  await logger.close();
  setServerLogger(createConsoleLogger("error"));
});

describe("POST /diagnostics/support-bundle", () => {
  it("builds a zip with every part and no seeded real value anywhere", async () => {
    const app = await setup();
    const res = await bundle(app, { caseId: CASE_ID, includeCaseLog: true });
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("application/zip");
    expect(res.headers["content-disposition"]).toMatch(/dfir-companion-support-.*\.zip/);
    const files = entries(res.body as Buffer);
    for (const name of [
      "README.txt",
      "diagnostics.txt",
      "support.json",
      "redaction-summary.json",
      "logs/session.log",
      "logs/debug.log",
      "logs/case.log",
      "imports/failure-1.json",
    ]) {
      expect(files.has(name), name).toBe(true);
    }
    const seeded = [
      CASE_ID,
      CASE_NAME,
      INVESTIGATOR,
      HOST,
      "jseedsmith",
      INTERNAL_IP,
      PUBLIC_IP,
      URL_HOST,
      SECRET,
      "seedhunt",
      root,
      logDir,
    ];
    for (const [name, body] of files) {
      for (const value of seeded) {
        expect(name.includes(value), `${value} in entry name ${name}`).toBe(false);
        expect(body.includes(value), `${value} in ${name}`).toBe(false);
      }
    }
    // The debug line was recorded at level info, and it arrives redacted.
    expect(files.get("logs/debug.log")).toContain("probe host ANON_");
    expect(files.get("logs/session.log")).not.toContain("probe host");
    // The shape report carries allowlisted names and types, never a cell value.
    const failure = JSON.parse(files.get("imports/failure-1.json")!);
    expect(failure.shape).toBeTruthy();
    expect(files.get("imports/failure-1.json")).not.toContain("4624");
    expect(failure.fileToken).toMatch(/^ANON_FILE_\d+\.json$/);
  });

  it("gives the same real value the same placeholder in every file", async () => {
    const app = await setup();
    const files = entries((await bundle(app, { caseId: CASE_ID, includeCaseLog: true })).body as Buffer);
    const tokenIn = (text: string) => /ANON_CASE_\d+/.exec(text)?.[0];
    const debugToken = tokenIn(files.get("logs/debug.log")!);
    expect(debugToken).toBeTruthy();
    expect(tokenIn(files.get("logs/case.log")!)).toBe(debugToken);
    expect(JSON.parse(files.get("imports/failure-1.json")!).caseToken).toBe(debugToken);
  });

  it("leaves out a locked case's log and import shape", async () => {
    const app = await setup();
    await store.updateCaseMeta(CASE_ID, { password: await hashCasePassword("seed-pass-123") });
    const files = entries((await bundle(app, { caseId: CASE_ID, includeCaseLog: true })).body as Buffer);
    expect(files.has("logs/case.log")).toBe(false);
    expect(files.get("README.txt")).toContain("locked");
    const failure = JSON.parse(files.get("imports/failure-1.json")!);
    expect(failure.shape).toBeUndefined();
    expect(failure.shapeUnavailable).toContain("locked");
  });

  // #1846: the case log and the stored import are case files that leave in the bundle — a name
  // swapped for a link must not carry another file out.
  it.skipIf(process.platform === "win32")("leaves out a case log or import swapped for a link", async () => {
    const app = await setup();
    const elsewhere = join(await mkdtemp(join(tmpdir(), "dfir-sb-away-")), "other.log");
    await writeFile(elsewhere, "linked-file-marker\n");
    const caseLog = join(store.caseDir(CASE_ID), "logs", "session-test.log");
    await rm(caseLog, { force: true });
    await symlink(elsewhere, caseLog);
    const stored = join(store.importsDir(CASE_ID), "0001_seedhunt.json");
    await rm(stored, { force: true });
    await symlink(elsewhere, stored);
    const res = await bundle(app, { caseId: CASE_ID, includeCaseLog: true });
    expect(res.status).toBe(200);
    const zip = (res.body as Buffer).toString("latin1");
    expect(zip).not.toContain("linked-file-marker");
    const files = entries(res.body as Buffer);
    expect(files.has("logs/case.log")).toBe(false);
    expect(files.get("README.txt")).toMatch(/logs\/case\.log: not included/);
  });

  it("rejects an invalid case id", async () => {
    const app = createApp(store, {});
    const res = await request(app).post("/diagnostics/support-bundle").send({ caseId: "../etc" });
    expect(res.status).toBe(400);
  });

  it("ignores any text a client sends — only the selections are read", async () => {
    const app = createApp(store, {});
    const files = entries(
      (await bundle(app, { diagnosticsText: "INJECTED-SEED-TEXT", supportJson: "INJECTED-SEED-TEXT" }))
        .body as Buffer,
    );
    for (const body of files.values()) expect(body).not.toContain("INJECTED-SEED-TEXT");
  });

  it("is a global-admin route in team mode", () => {
    expect(resolveRequestPolicy("POST", "/diagnostics/support-bundle")).toEqual({
      kind: "global",
      permission: "admin",
    });
  });
});
