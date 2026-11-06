import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { AuthStore } from "../../src/auth/authStore.js";
import { TeamAuth } from "../../src/auth/teamAuth.js";
import { UPLOAD_SPOOL_DIR } from "../../src/routes/importUpload.js";
import { provisionServiceToken } from "../helpers/serviceTokenAuth.js";

// #2336 — the dashboard uploads a large or gzip file as the raw request body. The route checks who
// is asking and which case BEFORE it reads a byte, spools the body to disk under a hard cap, and
// then runs the same flow Import-from-path runs from the head sniff onward. Nothing the client
// sends picks a server path, and a refused, over-cap or aborted upload leaves no spool file.

const OCTET = "application/octet-stream";
const savedCap = process.env.DFIR_MAX_UPLOAD_MB;
afterEach(() => {
  if (savedCap === undefined) delete process.env.DFIR_MAX_UPLOAD_MB;
  else process.env.DFIR_MAX_UPLOAD_MB = savedCap;
});

async function makeApp(opts: { teamAuth?: (root: string) => Promise<TeamAuth> } = {}) {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-upload-"));
  const store = new CaseStore(join(root, "cases"));
  const stateStore = new StateStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const jobManager = new JobManager();
  const custodyStore = new CustodyStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const teamAuth = opts.teamAuth ? await opts.teamAuth(root) : undefined;
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore,
    jobManager,
    custodyStore,
    ...(teamAuth ? { teamAuth } : {}),
  });
  const spoolDir = join(store.caseDir("c1"), UPLOAD_SPOOL_DIR);
  return { app, root, store, stateStore, importMetaStore, jobManager, custodyStore, spoolDir };
}

/** The spool files left behind; a missing spool folder counts as none. */
async function spoolLeft(dir: string): Promise<string[]> {
  return readdir(dir).catch(() => []);
}

/** The spool is removed in the route's `finally`, which can trail the response by a tick. */
async function noSpool(dir: string): Promise<void> {
  await waitFor(async () => ((await spoolLeft(dir)).length === 0 ? true : null), 3000);
}

const record = (i: number, eventName: string) => ({
  eventVersion: "1.09",
  userIdentity: {
    type: "IAMUser",
    arn: `arn:aws:iam::123456789012:user/ops${i}`,
    accountId: "123456789012",
    userName: `ops${i}`,
  },
  eventTime: "2026-10-01T10:00:00Z",
  eventSource: eventName === "StopLogging" ? "cloudtrail.amazonaws.com" : "iam.amazonaws.com",
  eventName,
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  eventID: `00000000-0000-4000-b000-${String(i).padStart(12, "0")}`,
  eventType: "AwsApiCall",
});

const PLASO =
  "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n" +
  "2026-05-02T10:00:00+00:00,Content Modification Time,FILE,NTFS USN change,C:\\Users\\bob\\notes.txt,usnjrnl,OS:/C:/Users/bob/notes.txt,\n";

async function waitFor<T>(fn: () => Promise<T | null | undefined>, ms = 8000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > until) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 50));
  }
}

const upload = (app: Parameters<typeof request>[0], query: string, body: Buffer | string) =>
  request(app)
    .post(`/cases/c1/import-upload?${query}`)
    .set("content-type", OCTET)
    .send(typeof body === "string" ? Buffer.from(body) : body);

describe("POST /cases/:id/import-upload — the raw-body upload (#2336)", () => {
  it("streams a gzip CloudTrail upload into a cancellable job and imports it", async () => {
    const { app, importMetaStore, stateStore, jobManager, store, spoolDir } = await makeApp();
    const gz = gzipSync(JSON.stringify({ Records: [record(1, "StopLogging"), record(2, "ListUsers")] }));
    const res = await upload(app, "filename=ct_us-east-1.json.gz", gz);
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body).toMatchObject({ accepted: true, kind: "aws" });

    const job = jobManager.list("c1").find((j) => j.kind === "import");
    expect(job?.cancellable).toBe(true);
    expect(job?.parameters?.streaming).toBe(true);

    const meta = await waitFor(async () => {
      const m = await importMetaStore.load("c1");
      return m.lastImportKind === "aws" ? m : null;
    });
    expect(meta.streamDisclosure?.join(" ")).toContain("gzip, decompressed on read");
    const state = await stateStore.load("c1");
    expect(state.forensicTimeline.some((e) => /StopLogging/.test(e.description))).toBe(true);

    // The stored copy is byte-identical to the upload, and the spool is gone.
    const stored = await readFile(join(store.importsDir("c1"), res.body.file));
    expect(stored.equals(gz)).toBe(true);
    await noSpool(spoolDir);
  });

  it("streams a plain Plaso CSV upload from disk, as Import-from-path does", async () => {
    const { app, jobManager } = await makeApp();
    const res = await upload(app, "filename=supertimeline.csv", PLASO);
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(res.body.kind).toBe("plaso");
    const job = jobManager.list("c1").find((j) => j.kind === "import");
    expect(job?.parameters?.streaming).toBe(true);
    expect(job?.cancellable).toBe(false); // Plaso streams but does not stop
  });

  it("records the upload on the chain of custody as received, with its hash", async () => {
    const { app, custodyStore } = await makeApp();
    const res = await upload(app, "filename=supertimeline.csv", PLASO);
    expect(res.status).toBe(202);
    const entries = await custodyStore.load("c1");
    const received = entries.find((e) => e.event === "received" && e.trigger === "import-upload");
    expect(received?.bytes).toBe(Buffer.byteLength(PLASO));
    expect(received?.source).toBe("supertimeline.csv");
  });

  it("uses only the file's base name — a client cannot pick a server path", async () => {
    const { app, store } = await makeApp();
    const res = await upload(app, `filename=${encodeURIComponent("../../../etc/plaso.csv")}`, PLASO);
    expect(res.status).toBe(202);
    expect(res.body.file).toMatch(/^\d{4}_plaso\.csv$/);
    expect(await readdir(store.importsDir("c1"))).toContain(res.body.file);
  });

  it("refuses an empty upload and keeps no spool", async () => {
    const { app, spoolDir } = await makeApp();
    const res = await upload(app, "filename=empty.csv", Buffer.alloc(0));
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/empty/);
    await noSpool(spoolDir);
  });

  it("refuses a body that is not application/octet-stream without reading it", async () => {
    const { app, spoolDir } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import-upload?filename=x.json")
      .set("content-type", "text/plain")
      .send("hello");
    expect(res.status).toBe(415);
    await noSpool(spoolDir);
  });

  it("refuses an upload whose declared length is over the cap, before spooling", async () => {
    process.env.DFIR_MAX_UPLOAD_MB = "0.01"; // ~10 KB
    const { app, spoolDir } = await makeApp();
    const res = await upload(app, "filename=big.csv", Buffer.alloc(64 * 1024, 0x41));
    expect(res.status).toBe(413);
    expect(res.body.error).toContain("DFIR_MAX_UPLOAD_MB");
    await noSpool(spoolDir);
  });

  it("stops a chunked upload that streams past the cap and removes the partial spool", async () => {
    process.env.DFIR_MAX_UPLOAD_MB = "0.01";
    const { app, spoolDir } = await makeApp();
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((r) => server.once("listening", () => r()));
    const { port } = server.address() as AddressInfo;
    try {
      const status = await new Promise<number>((resolve, reject) => {
        const req = httpRequest(
          {
            host: "127.0.0.1",
            port,
            method: "POST",
            path: "/cases/c1/import-upload?filename=big.csv",
            headers: { "content-type": OCTET, "transfer-encoding": "chunked" },
          },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.on("error", () => resolve(-1)); // the server may hang up mid-write after answering
        const chunk = Buffer.alloc(4096, 0x41);
        let sent = 0;
        const pump = () => {
          while (sent < 40) {
            sent++;
            if (!req.write(chunk)) return void req.once("drain", pump);
          }
          req.end();
        };
        pump();
        setTimeout(() => reject(new Error("no answer")), 8000);
      });
      expect([413, -1]).toContain(status);
      await waitFor(async () => ((await spoolLeft(spoolDir)).length === 0 ? true : null));
    } finally {
      server.close();
    }
  });

  it("leaves no spool when the client aborts mid-upload", async () => {
    const { app, spoolDir } = await makeApp();
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((r) => server.once("listening", () => r()));
    const { port } = server.address() as AddressInfo;
    try {
      const req = httpRequest({
        host: "127.0.0.1",
        port,
        method: "POST",
        path: "/cases/c1/import-upload?filename=big.csv",
        headers: { "content-type": OCTET, "content-length": String(1024 * 1024) },
      });
      req.on("error", () => undefined);
      req.write(Buffer.alloc(64 * 1024, 0x41));
      // Wait until the spool file exists, so the abort lands mid-spool rather than before it.
      await waitFor(async () => ((await spoolLeft(spoolDir)).length > 0 ? true : null));
      req.destroy();
      await waitFor(async () => ((await spoolLeft(spoolDir)).length === 0 ? true : null));
    } finally {
      server.close();
    }
  });

  it("honours a declared asset host and refuses a malformed one before spooling", async () => {
    const { app, jobManager, spoolDir } = await makeApp();
    const bad = await upload(app, "filename=supertimeline.csv&assetHost=bad..host", PLASO);
    expect(bad.status).toBe(400);
    await noSpool(spoolDir);
    const ok = await upload(app, "filename=supertimeline.csv&assetHost=WS-01", PLASO);
    expect(ok.status, JSON.stringify(ok.body)).toBe(202);
    const job = jobManager.list("c1").find((j) => j.kind === "import");
    expect(job?.parameters?.assetHost).toBe("WS-01");
  });

  it("refuses a closed case with 423 and spools nothing", async () => {
    const { app, store, spoolDir } = await makeApp();
    await store.updateCaseMeta("c1", { status: "closed" });
    const res = await upload(app, "filename=supertimeline.csv", PLASO);
    expect(res.status).toBe(423);
    await noSpool(spoolDir);
  });

  it("404s an unknown case before reading the body", async () => {
    const { app } = await makeApp();
    const res = await request(app)
      .post("/cases/nope/import-upload?filename=x.csv")
      .set("content-type", OCTET)
      .send(Buffer.from(PLASO));
    expect(res.status).toBe(404);
  });
});

describe("POST /cases/:id/import-upload in team mode (#2336)", () => {
  const teamAuth =
    (holder: { token?: string }, permissions: ("read" | "write")[] | null) =>
    async (root: string): Promise<TeamAuth> => {
      const store = new AuthStore(join(root, "auth.sqlite"));
      if (permissions) holder.token = await provisionServiceToken(store, "c1", permissions);
      return new TeamAuth({
        store,
        bootstrapToken: "upload-bootstrap-token-with-entropy",
        cookieSecure: false,
        sessionTtlMs: 60 * 60_000,
      });
    };

  it("401s a caller with no credential, before any byte is spooled", async () => {
    const { app, spoolDir } = await makeApp({ teamAuth: teamAuth({}, null) });
    const res = await upload(app, "filename=supertimeline.csv", PLASO);
    expect(res.status).toBe(401);
    await noSpool(spoolDir);
  });

  it("403s a case reader (not a writer), before any byte is spooled", async () => {
    const holder: { token?: string } = {};
    const { app, spoolDir } = await makeApp({ teamAuth: teamAuth(holder, ["read"]) });
    const res = await request(app)
      .post("/cases/c1/import-upload?filename=supertimeline.csv")
      .set("content-type", OCTET)
      .set("Authorization", `Bearer ${holder.token}`)
      .send(Buffer.from(PLASO));
    expect(res.status).toBe(403);
    await noSpool(spoolDir);
  });

  it("accepts a case writer — case write, not global admin", async () => {
    const holder: { token?: string } = {};
    const { app } = await makeApp({ teamAuth: teamAuth(holder, ["write"]) });
    const res = await request(app)
      .post("/cases/c1/import-upload?filename=supertimeline.csv")
      .set("content-type", OCTET)
      .set("Authorization", `Bearer ${holder.token}`)
      .send(Buffer.from(PLASO));
    expect(res.status, JSON.stringify(res.body)).toBe(202);
  });
});
