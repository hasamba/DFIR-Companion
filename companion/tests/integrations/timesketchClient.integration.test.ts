import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { TimesketchClient } from "../../src/integrations/timesketch/timesketchClient.js";
import { pushCaseToTimesketch } from "../../src/integrations/timesketch/timesketchPush.js";
import { emptyState, type InvestigationState, type ForensicEvent } from "../../src/analysis/stateTypes.js";

// Integration smoke test: drives the REAL TimesketchClient (real global fetch, real cookie jar,
// real CSRF login, real redirect:manual handling, real urlencoded upload) over real HTTP against a
// stub that parses fields exactly like Timesketch/Flask — `request.form` only. The stub returns the
// real Timesketch error ("Unable to upload data without supplying a sketch…") when sketch_id is
// absent from the parsed form, so this test reproduces the multipart bug and locks in the urlencoded
// fix: a multipart body would not parse into `sketch_id` and the push would fail.

const USER = "analyst";
const PASS = "s3cret";
const CSRF = "CSRF-TOKEN-123";

interface StubSketch { id: number; name: string; timelines: { id: number; name: string }[] }
interface StubUpload { sketchId: string | null; name: string | null; events: string | null }

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(Buffer.from(c)));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

// Stub Timesketch state (reset per test).
let sketches: StubSketch[] = [];
let uploads: StubUpload[] = [];
let deletedTimelines: number[] = [];
let seq = 100;

let server: http.Server;
let base = "";

function isAuthed(req: http.IncomingMessage): boolean {
  return (req.headers.cookie ?? "").includes("session=authed");
}
function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

beforeAll(async () => {
  server = http.createServer(async (req, res) => {
    const url = req.url ?? "";
    const method = req.method ?? "GET";
    const path = url.split("?")[0];

    // ---- auth: login page (CSRF token + anon session cookie) ----
    if (method === "GET" && path === "/login/") {
      res.writeHead(200, { "content-type": "text/html", "set-cookie": "session=anon; Path=/" });
      res.end(`<form><input id="csrf_token" name="csrf_token" type="hidden" value="${CSRF}"></form>`);
      return;
    }
    // ---- auth: submit credentials → upgrade cookie on a 302 (Flask-Login style) ----
    if (method === "POST" && path === "/login/") {
      const form = new URLSearchParams(await readBody(req));
      const ok = form.get("username") === USER && form.get("password") === PASS
        && form.get("csrf_token") === CSRF && req.headers["x-csrftoken"] === CSRF
        && (req.headers.cookie ?? "").includes("session=anon");
      if (ok) {
        res.writeHead(302, { "set-cookie": "session=authed; Path=/", location: "/" });
        res.end("redirecting");
      } else {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<form>bad login</form>");
      }
      return;
    }

    // ---- everything under /api/v1 requires the authenticated session cookie ----
    if (path.startsWith("/api/v1/")) {
      if (!isAuthed(req)) return sendJson(res, 401, { message: "unauthorized" });

      // list sketches (login-check uses per_page=1; find uses page=N)
      if (method === "GET" && path === "/api/v1/sketches/") {
        const page = Number(new URL(base + url).searchParams.get("page") ?? "1");
        const rows = page > 1 ? [] : sketches.map((s) => ({ id: s.id, name: s.name }));
        return sendJson(res, 200, { objects: [rows], meta: {} });
      }
      // create sketch
      if (method === "POST" && path === "/api/v1/sketches/") {
        const body = JSON.parse((await readBody(req)) || "{}");
        const sketch: StubSketch = { id: seq++, name: String(body.name), timelines: [] };
        sketches.push(sketch);
        return sendJson(res, 201, { objects: [{ id: sketch.id, name: sketch.name }] });
      }
      // sketch detail (timelines) + delete timeline
      const detail = /^\/api\/v1\/sketches\/(\d+)\/$/.exec(path);
      if (method === "GET" && detail) {
        const s = sketches.find((x) => x.id === Number(detail[1]));
        return sendJson(res, 200, { objects: [{ id: s?.id, name: s?.name, timelines: s?.timelines ?? [] }] });
      }
      const delTl = /^\/api\/v1\/sketches\/(\d+)\/timelines\/(\d+)\/$/.exec(path);
      if (method === "DELETE" && delTl) {
        const s = sketches.find((x) => x.id === Number(delTl[1]));
        if (s) s.timelines = s.timelines.filter((t) => t.id !== Number(delTl[2]));
        deletedTimelines.push(Number(delTl[2]));
        return sendJson(res, 200, {});
      }
      // upload — parse ONLY as request.form (urlencoded), like Timesketch's resource
      if (method === "POST" && path === "/api/v1/upload/") {
        const form = new URLSearchParams(await readBody(req));
        const sketchId = form.get("sketch_id");
        if (!sketchId) {
          return sendJson(res, 400, { message: "Unable to upload data without supplying a sketch to associate it with." });
        }
        uploads.push({ sketchId, name: form.get("name"), events: form.get("events") });
        const s = sketches.find((x) => x.id === Number(sketchId));
        const tid = seq++;
        if (s) s.timelines.push({ id: tid, name: String(form.get("name")) });
        return sendJson(res, 201, { objects: [{ id: tid, name: form.get("name") }] });
      }
      return sendJson(res, 404, { message: "not found" });
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => { server.close(); });

beforeEach(() => { sketches = []; uploads = []; deletedTimelines = []; seq = 100; });

function event(over: Partial<ForensicEvent> & { timestamp: string; description: string }): ForensicEvent {
  return { id: over.timestamp, severity: "Info", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [], ...over };
}
function sampleState(): InvestigationState {
  return {
    ...emptyState("Case Alpha"),
    forensicTimeline: [
      event({ timestamp: "2026-06-04T10:00:00Z", description: "logon to DC01", severity: "High" }),
      event({ timestamp: "2026-06-04T11:00:00Z", description: "mimikatz run", severity: "Critical" }),
    ],
  };
}

describe("TimesketchClient (real HTTP against a stub Timesketch)", () => {
  it("logs in (CSRF + session cookie), creates the sketch, and uploads the timeline with sketch_id parsed from request.form", async () => {
    const client = new TimesketchClient({ baseUrl: base, username: USER, password: PASS });
    const res = await pushCaseToTimesketch(client, { sketchName: "Case Alpha", state: sampleState() }, { baseUrl: base });

    expect(res.created).toBe(true);
    expect(res.events).toBe(2);
    expect(uploads).toHaveLength(1);                                 // upload reached the server…
    expect(uploads[0].sketchId).toBe(String(res.sketchId));         // …WITH sketch_id (the bug: multipart loses it)
    expect(uploads[0].name).toBe("DFIR Companion timeline");
    const lines = (uploads[0].events ?? "").trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(lines.map((l) => JSON.parse(l).message)).toEqual(["logon to DC01", "mimikatz run"]);
    expect(res.sketchUrl).toBe(`${base}/sketch/${res.sketchId}/explore`);
  });

  it("reuses an existing sketch and clean-replaces the managed timeline before uploading", async () => {
    sketches.push({ id: 42, name: "Case Alpha", timelines: [{ id: 7, name: "DFIR Companion timeline" }] });
    const client = new TimesketchClient({ baseUrl: base, username: USER, password: PASS });
    const res = await pushCaseToTimesketch(client, { sketchName: "Case Alpha", state: sampleState() }, { baseUrl: base });

    expect(res.created).toBe(false);
    expect(res.sketchId).toBe(42);
    expect(res.replacedTimeline).toBe(true);
    expect(deletedTimelines).toContain(7);
    expect(uploads).toHaveLength(1);
    expect(uploads[0].sketchId).toBe("42");
  });

  it("fails with an auth error on a bad password (no session established)", async () => {
    const client = new TimesketchClient({ baseUrl: base, username: USER, password: "wrong" });
    await expect(pushCaseToTimesketch(client, { sketchName: "Case Alpha", state: sampleState() }))
      .rejects.toThrow(/auth failed/i);
    expect(uploads).toHaveLength(0);
  });
});
