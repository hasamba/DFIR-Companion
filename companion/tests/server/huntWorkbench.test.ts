import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { SuperTimelineStore } from "../../src/analysis/superTimelineStore.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { createApp } from "../../src/server.js";
import { CaseStore } from "../../src/storage/caseStore.js";

function event(id: string, overrides: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-07-31T10:00:00.000Z",
    description: `event ${id}`,
    severity: "Low",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...overrides,
  };
}

let app: ReturnType<typeof createApp>;
let stateStore: StateStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-hunt-workbench-"));
  const cases = new CaseStore(root);
  await cases.createCase({
    caseId: "c1",
    name: "n",
    investigator: "i",
    aiProvider: null,
  });
  stateStore = new StateStore(cases);
  const state = emptyState("c1");
  state.forensicTimeline = [
    event("f-event", {
      asset: "DC01",
      severity: "High",
      description: "failed logon for jdoe",
      srcIp: "192.0.2.10",
    }),
  ];
  state.findings = [
    {
      id: "finding-1",
      title: "Repeated failures",
      description: "Needs evidence",
      severity: "High",
      status: "open",
      firstSeen: "2026-07-31T10:00:00.000Z",
      lastUpdated: "2026-07-31T10:00:00.000Z",
      mitreTechniques: [],
      relatedIocs: [],
      sourceScreenshots: [],
      relatedEventIds: [],
    },
  ];
  await stateStore.save(state);
  const superTimelineStore = new SuperTimelineStore(cases);
  await superTimelineStore.append("c1", [
    event("super-only", {
      asset: "RAW01",
      severity: "Info",
      description: "raw MFT row",
    }),
  ]);
  app = createApp(cases, { stateStore, superTimelineStore });
});

describe("hunt workbench routes", () => {
  it("documents the grammar and typed field catalogue", async () => {
    const response = await request(app).get("/cases/c1/hunt-query/catalog");
    expect(response.status).toBe(200);
    expect(response.body.grammar).toContain("AND");
    expect(response.body.fields).toContainEqual(
      expect.objectContaining({
        name: "event.category",
        type: "keyword",
      }),
    );
    expect(response.body.errors).toContainEqual(expect.objectContaining({ code: "unknown_field" }));
  });

  it("validates and explains without executing", async () => {
    const good = await request(app)
      .post("/cases/c1/hunt-query/validate")
      .send({ query: "host.name=DC01 AND severity=High" });
    expect(good.status).toBe(200);
    expect(good.body.valid).toBe(true);
    expect(good.body.explanation).toContain("host index");

    const bad = await request(app).post("/cases/c1/hunt-query/validate").send({ query: "sorce.ip=x" });
    expect(bad.status).toBe(400);
    expect(bad.body.error).toMatchObject({
      code: "unknown_field",
      line: 1,
      column: 1,
    });
  });

  it("executes each explicitly selected dataset with an opaque cursor", async () => {
    const forensic = await request(app).post("/cases/c1/hunt-query/execute").send({
      query: "host.name=DC01",
      dataset: "forensic",
      limit: 1,
    });
    expect(forensic.status).toBe(200);
    expect(forensic.body.events.map((item: ForensicEvent) => item.id)).toEqual(["f-event"]);

    const raw = await request(app).post("/cases/c1/hunt-query/execute").send({
      query: "host.name=RAW01",
      dataset: "super",
    });
    expect(raw.status).toBe(200);
    expect(raw.body.events.map((item: ForensicEvent) => item.id)).toEqual(["super-only"]);
    expect(raw.body.dataset).toBe("super");
  });

  it("rejects unvalidated request bodies and invalid datasets", async () => {
    expect(
      (await request(app).post("/cases/c1/hunt-query/execute").send({ query: 42, dataset: "forensic" }))
        .status,
    ).toBe(400);
    expect(
      (
        await request(app)
          .post("/cases/c1/hunt-query/execute")
          .send({ query: "severity=High", dataset: "both" })
      ).status,
    ).toBe(400);
  });

  it("saves templates and records execution history", async () => {
    const created = await request(app)
      .post("/cases/c1/hunt-query/saved")
      .send({
        name: "High events",
        query: "severity=$severity",
        dataset: "forensic",
        author: "analyst",
        parameters: { severity: "High" },
      });
    expect(created.status).toBe(201);

    const executed = await request(app).post("/cases/c1/hunt-query/execute").send({
      savedHuntId: created.body.id,
      query: created.body.query,
      dataset: created.body.dataset,
      author: "analyst",
      parameters: created.body.parameters,
    });
    expect(executed.status).toBe(200);

    const listed = await request(app).get("/cases/c1/hunt-query/saved");
    expect(listed.body[0].history).toHaveLength(1);
    expect(listed.body[0].history[0]).toMatchObject({
      executedBy: "analyst",
      status: "completed",
      matched: 1,
    });
  });

  it("never attaches super-timeline rows to finding evidence", async () => {
    const rejected = await request(app)
      .post("/cases/c1/hunt-query/finding-evidence")
      .send({
        dataset: "super",
        findingId: "finding-1",
        eventIds: ["super-only"],
      });
    expect(rejected.status).toBe(400);

    const accepted = await request(app)
      .post("/cases/c1/hunt-query/finding-evidence")
      .send({
        dataset: "forensic",
        findingId: "finding-1",
        eventIds: ["f-event", "super-only"],
      });
    expect(accepted.status).toBe(200);
    expect(accepted.body.addedEventIds).toEqual(["f-event"]);
    expect((await stateStore.load("c1")).findings[0].relatedEventIds).toEqual(["f-event"]);
  });
});
