import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";

// Route-level coverage for attacker session segmentation (#229). segmentSessions has its own unit
// tests; what is exercised here is what those cannot see — that the URL reaches this handler at
// all, that a case which does not exist 404s instead of answering "no attacker sessions", that the
// DFIR_SESSION_GAP_S override is actually read, and that a missing state store 501s.

function ev(id: string, timestamp: string, extra: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp,
    description: "",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...extra,
  };
}

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-sessions-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "Intrusion", investigator: "Alice", aiProvider: null });

  stateStore = new StateStore(cases);
  await stateStore.save({
    ...emptyState("c1"),
    forensicTimeline: [
      ev("e1", "2026-05-20T14:01:00Z", { asset: "DC01", mitreTechniques: ["T1566"] }),
      ev("e2", "2026-05-20T14:02:00Z", { asset: "DC01", mitreTechniques: ["T1566.001"] }),
      // > 5 min later on the same host → a second session under the default threshold
      ev("e3", "2026-05-20T15:10:00Z", { asset: "DC01" }),
      // a different host entirely → its own session, never folded into DC01's
      ev("e4", "2026-05-20T14:01:30Z", { asset: "WS02" }),
    ],
  });

  app = createApp(cases, { stateStore });
});

afterEach(() => {
  delete process.env.DFIR_SESSION_GAP_S;
});

describe("GET /cases/:id/sessions", () => {
  it("segments the case timeline into per-host sessions in chronological order", async () => {
    const res = await request(app).get("/cases/c1/sessions");

    expect(res.status).toBe(200);
    expect(res.body.sessions).toHaveLength(3);
    expect(res.body.sessions.map((s: { id: string }) => s.id)).toEqual([
      "session-1",
      "session-2",
      "session-3",
    ]);
    expect(res.body.sessions[0]).toMatchObject({
      host: "DC01",
      eventCount: 2,
      dominantTactic: "Initial Access",
      startTime: "2026-05-20T14:01:00Z",
    });
    expect(res.body.sessions[0].label).toContain("Initial Access DC01");
    // The back-to-back WS02 event must not have joined DC01's session.
    expect(res.body.sessions[1]).toMatchObject({ host: "WS02", eventCount: 1 });
    expect(res.body.sessions[2]).toMatchObject({ host: "DC01", eventCount: 1 });
  });

  it("honors the DFIR_SESSION_GAP_S override", async () => {
    // A 10s threshold: the default 5 min held DC01's 14:01/14:02 pair together, and nothing in
    // this timeline is within 10s of its neighbour, so the split must now be total.
    process.env.DFIR_SESSION_GAP_S = "10";
    const res = await request(app).get("/cases/c1/sessions");

    expect(res.status).toBe(200);
    // Every event is now more than 10s from its neighbour on the same host → one session each.
    expect(res.body.sessions).toHaveLength(4);
  });

  it("404s for a case that does not exist instead of reporting no attacker sessions", async () => {
    const res = await request(app).get("/cases/typo/sessions");

    expect(res.status).toBe(404);
    // The failure mode this pins: StateStore.load answers a missing case with an empty state, so
    // the handler would otherwise return 200 with sessions: [].
    expect(res.body.sessions).toBeUndefined();
  });

  it("400s on a case id that could escape the cases root", async () => {
    const res = await request(app).get("/cases/a..b/sessions");

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid caseId");
  });

  it("501s when the state store is not configured", async () => {
    const bare = createApp(cases, {});
    const res = await request(bare).get("/cases/c1/sessions");

    expect(res.status).toBe(501);
    expect(res.body.error).toBe("state store not configured");
  });
});
