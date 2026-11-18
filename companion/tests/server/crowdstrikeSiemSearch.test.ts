import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { ActivityLogStore } from "../../src/analysis/activityLog.js";
import { JobManager } from "../../src/analysis/jobManager.js";
import { ForensicGateControlStore } from "../../src/analysis/forensicGateControl.js";
import { familyOfEvent } from "../../src/analysis/caseMainSource.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { pollFor } from "../helpers/poll.js";

// #2666: Run a CQL hunt on CrowdStrike Next-Gen SIEM — route -> fake Falcon (injected fetch) ->
// evidence file -> CrowdStrike importer -> settle -> activity entry. Synthetic rows only.

const ENV_KEYS = [
  "DFIR_CROWDSTRIKE_SIEM_CLIENT_ID",
  "DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET",
  "DFIR_CROWDSTRIKE_SIEM_BASE_URL",
  "DFIR_CROWDSTRIKE_SIEM_MAX_WINDOW_DAYS",
  "DFIR_CROWDSTRIKE_SIEM_REPOSITORY",
  "DFIR_CROWDSTRIKE_CLIENT_ID",
  "DFIR_CROWDSTRIKE_CLIENT_SECRET",
];
const SECRET = "siem-secret-value";
const HOUR = 3_600_000;

const ENCODED = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AA==";
const ROWS = [
  // A table() projection: no #event_simpleName in the row — the query names ProcessRollup2.
  {
    "@id": "r1",
    "@timestamp": Date.parse("2026-11-16T10:00:00.000Z"),
    ComputerName: "WS-07",
    ImageFileName: "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    CommandLine: ENCODED,
  },
  {
    "@id": "r2",
    "@timestamp": Date.parse("2026-11-16T09:00:00.000Z"),
    ComputerName: "WS-07",
    ImageFileName: "\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe",
    CommandLine: "notepad.exe C:\\Users\\a\\todo.txt",
  },
];
const QUERY = `#event_simpleName=ProcessRollup2 | ComputerName="WS-07" | table([@timestamp, ComputerName, ImageFileName, CommandLine])`;

function fakeFalcon(rows: unknown[]) {
  const paths: string[] = [];
  const fetchFn = (async (input: string | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    paths.push(`${init?.method ?? "GET"} ${url.pathname}`);
    if (url.pathname === "/oauth2/token")
      return Response.json({ access_token: "tok", expires_in: 1799 }, { status: 201 });
    if (init?.method === "POST") return Response.json({ id: "job1" });
    if (init?.method === "DELETE") return new Response(null, { status: 204 });
    return Response.json({
      done: true,
      events: rows,
      metaData: { isAggregate: true, extraData: { hasMoreEvents: "false" } },
    });
  }) as typeof fetch;
  return { fetchFn, paths };
}

async function makeApp(fetchFn: typeof fetch) {
  const root = await mkdtemp(join(tmpdir(), "dfir-ngsiem-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const superTimelineStore = new SuperTimelineStore(store);
  const importMetaStore = new ImportMetaStore(store);
  const activityLogStore = new ActivityLogStore(store);
  const jobManager = new JobManager();
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore,
    superTimelineStore,
    activityLogStore,
    jobManager,
    forensicGateControlStore: new ForensicGateControlStore(store),
    crowdstrikeSiemFetch: fetchFn,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, stateStore, superTimelineStore, activityLogStore, jobManager };
}

const DAY = 24 * HOUR;
const event = (id: string, ms: number, severity: ForensicEvent["severity"]): ForensicEvent => ({
  id,
  timestamp: new Date(ms).toISOString(),
  description: `synthetic ${severity} event ${id}`,
  severity,
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
});

const recent = () => {
  const end = Date.now() - HOUR;
  return { start: new Date(end - 24 * HOUR).toISOString(), end: new Date(end).toISOString() };
};

describe("CrowdStrike NG-SIEM search route (#2666)", () => {
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const k of ENV_KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });
  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });
  const configure = () => {
    process.env.DFIR_CROWDSTRIKE_SIEM_CLIENT_ID = "siem-id";
    process.env.DFIR_CROWDSTRIKE_SIEM_CLIENT_SECRET = SECRET;
    process.env.DFIR_CROWDSTRIKE_SIEM_BASE_URL = "https://falcon.test";
  };

  it("is off without the SIEM credentials: GET says so, POST refuses, nothing reaches /humio/", async () => {
    process.env.DFIR_CROWDSTRIKE_CLIENT_ID = "intel-id"; // the threat-intel client never turns it on
    process.env.DFIR_CROWDSTRIKE_CLIENT_SECRET = "intel-secret";
    const f = fakeFalcon(ROWS);
    const { app } = await makeApp(f.fetchFn);
    const get = await request(app).get("/cases/c1/crowdstrike/siem");
    expect(get.body).toEqual({ configured: false });
    const post = await request(app)
      .post("/cases/c1/crowdstrike/siem/search")
      .send({ query: QUERY, ...recent() });
    expect(post.status).toBe(409);
    expect(f.paths).toEqual([]);
  });

  it("GET reports the caps and a default range, never a credential", async () => {
    configure();
    const { app } = await makeApp(fakeFalcon([]).fetchFn);
    const res = await request(app).get("/cases/c1/crowdstrike/siem");
    expect(res.body).toMatchObject({
      configured: true,
      maxWindowDays: 7,
      maxRows: 10_000,
      timeoutMs: 300_000,
      repository: "search-all",
    });
    expect(
      Date.parse(res.body.defaultRange.end) - Date.parse(res.body.defaultRange.start),
    ).toBeLessThanOrEqual(7 * 24 * HOUR);
    expect(JSON.stringify(res.body)).not.toContain(SECRET);
  });

  it("GET reads only High and Critical rows for the default range, through the indexed filter (#2672)", async () => {
    configure();
    const { app, stateStore } = await makeApp(fakeFalcon([]).fetchFn);
    const now = Date.now();
    await stateStore.appendForensicEvents("c1", [
      event("low-wide", now - 6.5 * DAY, "Low"),
      event("med-wide", now - HOUR, "Medium"),
      event("high-1", now - 4 * DAY, "High"),
      event("high-2", now - 3.5 * DAY, "High"),
      event("crit-1", now - 3 * DAY, "Critical"),
    ]);
    const spy = vi.spyOn(stateStore, "forensicTimelineBatches");
    const res = await request(app).get("/cases/c1/crowdstrike/siem");
    expect(res.status).toBe(200);
    expect(spy).toHaveBeenCalled();
    for (const [, query] of spy.mock.calls) expect(["High", "Critical"]).toContain(query?.severity);
    // The severe window (4 to 3 days ago) plus a day either side; the Low/Medium spread is ignored.
    expect(res.body.defaultRange).toEqual({
      start: new Date(now - 5 * DAY).toISOString(),
      end: new Date(now - 2 * DAY).toISOString(),
    });
  });

  it("GET falls back to the last maxWindowDays when fewer than two severe events exist (#2672)", async () => {
    configure();
    const { app, stateStore } = await makeApp(fakeFalcon([]).fetchFn);
    const now = Date.now();
    await stateStore.appendForensicEvents("c1", [
      event("high-only", now - 3 * DAY, "High"),
      event("low-1", now - 2 * DAY, "Low"),
      event("med-1", now - DAY, "Medium"),
    ]);
    const before = Date.now();
    const res = await request(app).get("/cases/c1/crowdstrike/siem");
    const end = Date.parse(res.body.defaultRange.end);
    expect(end).toBeGreaterThanOrEqual(before);
    expect(end).toBeLessThanOrEqual(Date.now());
    expect(end - Date.parse(res.body.defaultRange.start)).toBe(7 * DAY);
  });

  it("GET refuses an unknown case with 404, like the POST, once the search is set up (#2673)", async () => {
    const { app: offApp } = await makeApp(fakeFalcon([]).fetchFn);
    const off = await request(offApp).get("/cases/nope/crowdstrike/siem");
    expect(off.status).toBe(200);
    expect(off.body).toEqual({ configured: false });

    configure();
    const { app } = await makeApp(fakeFalcon([]).fetchFn);
    const res = await request(app).get("/cases/nope/crowdstrike/siem");
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: "case not found" });
  });

  it("refuses a range wider than the limit before any call to Falcon", async () => {
    configure();
    const f = fakeFalcon(ROWS);
    const { app } = await makeApp(f.fetchFn);
    const end = Date.now() - HOUR;
    const res = await request(app)
      .post("/cases/c1/crowdstrike/siem/search")
      .send({
        query: QUERY,
        start: new Date(end - 10 * 24 * HOUR).toISOString(),
        end: new Date(end).toISOString(),
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("The limit is 7 days");
    expect(f.paths).toEqual([]);
  });

  it("runs the search as a job, keeps the rows as evidence and imports them through the CrowdStrike importer", async () => {
    configure();
    const f = fakeFalcon(ROWS);
    const { app, store, stateStore, superTimelineStore, activityLogStore, jobManager } = await makeApp(
      f.fetchFn,
    );
    const res = await request(app)
      .post("/cases/c1/crowdstrike/siem/search")
      .send({ query: QUERY, title: "Encoded PowerShell on WS-07", ...recent() });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    const job = await pollFor("the siem-search job to finish", async () => {
      const j = jobManager.get(res.body.jobId);
      return j && (j.status === "succeeded" || j.status === "failed") ? j : undefined;
    });
    expect(job.status, JSON.stringify(job)).toBe("succeeded");
    expect(job.kind).toBe("siem-search");
    expect(job.cancellable).toBe(false); // cancellable while searching, closed at the first write

    // Only start / poll / cancel queryjobs (plus the sign-in).
    for (const p of f.paths.filter((x) => !x.endsWith("/oauth2/token"))) {
      expect(p).toMatch(/^(POST|GET|DELETE) \/humio\/api\/v1\/repositories\/search-all\/queryjobs(\/job1)?$/);
    }

    // Evidence first: the returned rows as Falcon sent them (no event name was added to the file).
    const files = await readdir(store.importsDir("c1"));
    const evidence = files.find((n) => n.includes("crowdstrike-ngsiem"));
    expect(evidence).toBeTruthy();
    const stored = (await readFile(join(store.importsDir("c1"), evidence!), "utf8"))
      .split("\n")
      .map((l) => JSON.parse(l));
    expect(stored).toEqual(ROWS);

    // The encoded PowerShell row is graded above Info and reaches the forensic timeline; the notepad
    // row (Info) is in the super-timeline only. Both carry the NG-SIEM provenance.
    const state = await stateStore.load("c1");
    const forensic = state.forensicTimeline.filter((e) => e.sources?.includes("CrowdStrike NG-SIEM"));
    expect(forensic.some((e) => e.description.includes("-enc"))).toBe(true);
    expect(forensic.some((e) => e.description.includes("notepad"))).toBe(false);
    for (const e of forensic) expect(familyOfEvent(e)).toBe("crowdstrike");
    const sup = await superTimelineStore.query("c1", { limit: 100 });
    const superRows = (sup as unknown as { events: ForensicEvent[] }).events;
    const note = superRows.find((e) => e.description.includes("notepad"));
    expect(note?.sources).toEqual(["CrowdStrike Falcon", "CrowdStrike NG-SIEM"]);

    // The audit entry: query, repository, range, rows, who ran it — and never the secret.
    const entries = await activityLogStore.load("c1");
    const entry = entries.find((e) => e.action === "crowdstrike-siem.search");
    expect(entry?.category).toBe("hunt");
    expect(entry?.detail).toContain("found 2 rows");
    expect(entry?.detail).toContain("Repository: search-all");
    expect(entry?.detail).toContain(QUERY);
    expect(entry?.detail).toContain("Run by: analyst");
    expect(JSON.stringify(entries)).not.toContain(SECRET);
    expect(JSON.stringify(job)).not.toContain(SECRET);
  });

  it("a 403 fails the job with the scope sentence and stores nothing", async () => {
    configure();
    const fetchFn = (async (input: string | URL) => {
      const url = new URL(String(input));
      if (url.pathname === "/oauth2/token")
        return Response.json({ access_token: "tok", expires_in: 1799 }, { status: 201 });
      return new Response("{}", { status: 403 });
    }) as typeof fetch;
    const { app, store, jobManager } = await makeApp(fetchFn);
    const res = await request(app)
      .post("/cases/c1/crowdstrike/siem/search")
      .send({ query: QUERY, ...recent() });
    const job = await pollFor("the job to fail", async () => {
      const j = jobManager.get(res.body.jobId);
      return j?.status === "failed" ? j : undefined;
    });
    expect(JSON.stringify(job)).toContain("NGSIEM: Write");
    const files = await readdir(store.importsDir("c1")).catch(() => []);
    expect(files.some((n) => n.includes("crowdstrike-ngsiem"))).toBe(false);
  });
});
