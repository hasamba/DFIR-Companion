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

interface StubSketch {
  id: number;
  name: string;
  timelines: { id: number; name: string; color?: string; description?: string }[];
}
interface StubUpload {
  sketchId: string | null;
  name: string | null;
  events: string | null;
  dataLabel: string | null;
}
interface StubRename {
  timelineId: number;
  body: Record<string, unknown>;
  csrf: string | undefined;
}

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
let renames: StubRename[] = [];
let uploadReturnsColor = true;
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
      const ok =
        form.get("username") === USER &&
        form.get("password") === PASS &&
        form.get("csrf_token") === CSRF &&
        req.headers["x-csrftoken"] === CSRF &&
        (req.headers.cookie ?? "").includes("session=anon");
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
      // rename — like upstream TimelineResource.post: TimelineForm from the JSON body + X-CSRFToken,
      // name required (<=255), colour required and exactly 6 hex digits; replies a bare 200.
      if (method === "POST" && delTl) {
        const body = JSON.parse((await readBody(req)) || "{}") as Record<string, unknown>;
        const csrf = req.headers["x-csrftoken"] as string | undefined;
        renames.push({ timelineId: Number(delTl[2]), body, csrf });
        const nameOk = typeof body.name === "string" && body.name.length > 0 && body.name.length <= 255;
        const colorOk = typeof body.color === "string" && /^[0-9a-fA-F]{6}$/.test(body.color);
        const jsonOk = (req.headers["content-type"] ?? "").includes("application/json");
        if (!nameOk || !colorOk || !jsonOk || csrf !== CSRF) {
          return sendJson(res, 400, { message: "Unable to validate form data." });
        }
        const s = sketches.find((x) => x.id === Number(delTl[1]));
        const t = s?.timelines.find((x) => x.id === Number(delTl[2]));
        if (!t) return sendJson(res, 404, { message: "No timeline found with this ID." });
        t.name = String(body.name);
        t.description = String(body.description ?? "");
        t.color = String(body.color);
        return sendJson(res, 200, 200);
      }
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
          return sendJson(res, 400, {
            message: "Unable to upload data without supplying a sketch to associate it with.",
          });
        }
        uploads.push({
          sketchId,
          name: form.get("name"),
          events: form.get("events"),
          dataLabel: form.get("data_label"),
        });
        const s = sketches.find((x) => x.id === Number(sketchId));
        const tid = seq++;
        const name = String(form.get("name"));
        if (s) s.timelines.push({ id: tid, name, color: "3C8DBC", description: name });
        const timeline = uploadReturnsColor ? { id: tid, name, color: "3C8DBC" } : { id: tid, name };
        return sendJson(res, 201, { objects: [timeline] });
      }
      return sendJson(res, 404, { message: "not found" });
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => {
  server.close();
});

beforeEach(() => {
  sketches = [];
  uploads = [];
  deletedTimelines = [];
  renames = [];
  uploadReturnsColor = true;
  seq = 100;
});

function event(over: Partial<ForensicEvent> & { timestamp: string; description: string }): ForensicEvent {
  return {
    id: over.timestamp,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...over,
  };
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
    const res = await pushCaseToTimesketch(
      client,
      { sketchName: "Case Alpha", state: sampleState() },
      { baseUrl: base },
    );

    expect(res.created).toBe(true);
    expect(res.events).toBe(2);
    expect(uploads).toHaveLength(1); // upload reached the server…
    expect(uploads[0].sketchId).toBe(String(res.sketchId)); // …WITH sketch_id (the bug: multipart loses it)
    // #2414: uploaded under a staging name with a unique label, then renamed to the managed name.
    expect(uploads[0].name).toMatch(/^DFIR-Companion Forensic Timeline \(staging [0-9a-f]{6}\)$/);
    expect(uploads[0].dataLabel).toMatch(/^dfir-companion-[0-9a-f]{6}$/);
    expect(res.timelineName).toBe("DFIR-Companion Forensic Timeline");
    expect(sketches[0].timelines.map((t) => t.name)).toEqual(["DFIR-Companion Forensic Timeline"]);
    const lines = (uploads[0].events ?? "").trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(lines.map((l) => JSON.parse(l).message)).toEqual(["logon to DC01", "mimikatz run"]);
    expect(res.sketchUrl).toBe(`${base}/sketch/${res.sketchId}/explore`);
  });

  it("reuses an existing sketch and replaces the managed timeline only after the upload (#2414)", async () => {
    sketches.push({
      id: 42,
      name: "Case Alpha",
      timelines: [{ id: 7, name: "DFIR-Companion Forensic Timeline" }],
    });
    const client = new TimesketchClient({ baseUrl: base, username: USER, password: PASS });
    const res = await pushCaseToTimesketch(
      client,
      { sketchName: "Case Alpha", state: sampleState() },
      { baseUrl: base },
    );

    expect(res.created).toBe(false);
    expect(res.sketchId).toBe(42);
    expect(res.replacedTimeline).toBe(true);
    expect(deletedTimelines).toContain(7);
    expect(uploads).toHaveLength(1);
    expect(uploads[0].sketchId).toBe("42");
    expect(sketches[0].timelines).toEqual([
      {
        id: 100,
        name: "DFIR-Companion Forensic Timeline",
        color: "3C8DBC",
        description: "DFIR-Companion Forensic Timeline",
      },
    ]);
  });

  it("renames with name, description and the upload's colour as JSON with the CSRF header (#2414)", async () => {
    sketches.push({ id: 42, name: "Case Alpha", timelines: [] });
    const client = new TimesketchClient({ baseUrl: base, username: USER, password: PASS });
    await pushCaseToTimesketch(client, { sketchName: "Case Alpha", state: sampleState() });
    expect(renames).toEqual([
      {
        timelineId: 100,
        body: {
          name: "DFIR-Companion Forensic Timeline",
          description: "DFIR-Companion Forensic Timeline",
          color: "3C8DBC",
        },
        csrf: CSRF,
      },
    ]);
  });

  it("reads the colour from the sketch detail when the upload reply has none, keeping it", async () => {
    sketches.push({ id: 42, name: "Case Alpha", timelines: [] });
    uploadReturnsColor = false;
    const client = new TimesketchClient({ baseUrl: base, username: USER, password: PASS });
    const res = await pushCaseToTimesketch(client, { sketchName: "Case Alpha", state: sampleState() });
    expect(res.warnings).toEqual([]);
    expect(renames[0].body.color).toBe("3C8DBC");
  });

  it("a direct upload without a label keeps the default data label", async () => {
    sketches.push({ id: 42, name: "Case Alpha", timelines: [] });
    const client = new TimesketchClient({ baseUrl: base, username: USER, password: PASS });
    await client.login();
    const out = await client.uploadEvents(42, "manual", '{"message":"x"}\n');
    expect(uploads[0].dataLabel).toBe("dfir-companion");
    expect(out).toEqual({ timelineId: 100, color: "3C8DBC" });
  });

  it("fails with an auth error on a bad password (no session established)", async () => {
    const client = new TimesketchClient({ baseUrl: base, username: USER, password: "wrong" });
    await expect(
      pushCaseToTimesketch(client, { sketchName: "Case Alpha", state: sampleState() }),
    ).rejects.toThrow(/auth failed/i);
    expect(uploads).toHaveLength(0);
  });
});
