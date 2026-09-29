import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { resetLimiters } from "../../src/http/rateLimiter.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createZip, readZip } from "../../src/analysis/zipArchive.js";

// #1784: POST /cases/import/zip brings an "Archive to ZIP" file back in as a case.

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-ziproute-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const custodyStore = new CustodyStore(store);
  const app = createApp(store, { stateStore, custodyStore });
  return { app, store, stateStore };
}

async function seedAndArchive(app: ReturnType<typeof createApp>, stateStore: StateStore): Promise<Buffer> {
  await request(app)
    .post("/cases")
    .send({ caseId: "INC-1", name: "Case One", investigator: "alice", aiProvider: "anthropic" });
  await stateStore.save({
    ...emptyState("INC-1"),
    iocs: [{ id: "i1", type: "domain", value: "bad.example.com", firstSeen: "2026-01-01T00:00:00Z" }],
    forensicTimeline: [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00Z",
        description: "evt",
        severity: "High",
        mitreTechniques: [],
        relatedFindingIds: [],
        sourceScreenshots: [],
      },
    ],
  });
  const archived = await request(app).post("/cases/INC-1/archive").send({});
  expect(archived.status).toBe(200);
  return readFile(archived.body.archivePath as string);
}

describe("POST /cases/import/zip", () => {
  beforeEach(() => resetLimiters());

  it("imports an archived case under a new id, with counts from the case database", async () => {
    const { app, store, stateStore } = await harness();
    const zip = await seedAndArchive(app, stateStore);

    const res = await request(app)
      .post("/cases/import/zip")
      .send({ data: zip.toString("base64"), targetCaseId: "INC-2" });

    expect(res.status).toBe(201);
    expect(res.body.caseId).toBe("INC-2");
    expect(res.body.verified).toBe(true);
    expect(res.body.sourceCaseId).toBe("INC-1");
    expect(res.body.counts).toMatchObject({ forensicEvents: 1, iocs: 1, findings: 0 });
    const state = await request(app).get("/cases/INC-2/state");
    expect(state.body.caseId).toBe("INC-2");

    const records = (await readFile(store.custodyLogPath("INC-2"), "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, string>);
    const arrivals = records.filter((r) => r.event === "transferred");
    expect(arrivals).toHaveLength(1);
    expect(arrivals[0].source).toBe("ZIP archive of case INC-1");
    expect(arrivals[0].trigger).toBe("zip-case-import");
  });

  it("answers 409 with the conflicting case id", async () => {
    const { app, stateStore } = await harness();
    const zip = await seedAndArchive(app, stateStore);
    const res = await request(app)
      .post("/cases/import/zip")
      .send({ data: zip.toString("base64") });
    expect(res.status).toBe(409);
    expect(res.body.caseId).toBe("INC-1");
  });

  it("answers 400 for bytes that are not a case archive", async () => {
    const { app } = await harness();
    const res = await request(app)
      .post("/cases/import/zip")
      .send({ data: Buffer.from("not a zip at all").toString("base64") });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not a valid case archive/);
  });

  it("answers 400 for a tampered archive", async () => {
    const { app, stateStore } = await harness();
    const zip = await seedAndArchive(app, stateStore);
    const tampered = createZip(
      readZip(zip).map((e) =>
        e.path === "INC-1/case.json"
          ? { path: e.path, data: Buffer.from(JSON.stringify({ caseId: "INC-1" })) }
          : e,
      ),
    );
    const res = await request(app)
      .post("/cases/import/zip")
      .send({ data: tampered.toString("base64"), targetCaseId: "INC-3" });
    expect(res.status).toBe(400);
  });

  it("answers 400 when data is missing", async () => {
    const { app } = await harness();
    const res = await request(app).post("/cases/import/zip").send({});
    expect(res.status).toBe(400);
  });
});
