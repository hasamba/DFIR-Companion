import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
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
  return { app, store, stateStore, custodyStore };
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

  // #2124: the ZIP the analyst handed over is receipted with its own hashes, ahead of `transferred`.
  it("receipts the ZIP archive's SHA-256, SHA-1 and size before the transferred entry", async () => {
    const { app, store, stateStore } = await harness();
    const zip = await seedAndArchive(app, stateStore);

    const res = await request(app)
      .post("/cases/import/zip")
      .send({ data: zip.toString("base64"), targetCaseId: "INC-2" });
    expect(res.status).toBe(201);

    const records = (await readFile(store.custodyLogPath("INC-2"), "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const sha256 = createHash("sha256").update(zip).digest("hex");
    const receivedAt = records.findIndex((r) => r.event === "received" && r.sha256 === sha256);
    expect(receivedAt).toBeGreaterThanOrEqual(0);
    const received = records[receivedAt];
    expect(received.sha1).toBe(createHash("sha1").update(zip).digest("hex"));
    expect(received.bytes).toBe(zip.length);
    expect(received.trigger).toBe("zip-case-import");
    expect(String(received.artifactPath).startsWith("received:")).toBe(true);
    expect(receivedAt).toBeLessThan(records.findIndex((r) => r.event === "transferred"));
  });

  // #2176: the receipt names the archive the analyst picked, not a generic label.
  describe("receipt file name", () => {
    async function receivedFor(filename?: unknown): Promise<Record<string, unknown>> {
      const { app, store, stateStore } = await harness();
      const zip = await seedAndArchive(app, stateStore);
      const res = await request(app)
        .post("/cases/import/zip")
        .send({
          data: zip.toString("base64"),
          targetCaseId: "INC-2",
          ...(filename === undefined ? {} : { filename }),
        });
      expect(res.status).toBe(201);
      const records = (await readFile(store.custodyLogPath("INC-2"), "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(records.find((r) => r.event === "transferred")?.source).toBe("ZIP archive of case INC-1");
      const received = records.find((r) => r.event === "received");
      expect(received).toBeDefined();
      return received as Record<string, unknown>;
    }

    it("records the archive's own file name, basename only", async () => {
      const received = await receivedFor("C:\\evidence\\INC-1 (archive).zip");
      expect(received.source).toBe("INC-1 (archive).zip");
      expect(String(received.artifactPath)).toContain("/INC-1 (archive).zip@");
    });

    it("falls back to the generic label when no file name is sent", async () => {
      const received = await receivedFor();
      expect(received.source).toBe("ZIP archive");
    });

    it("strips path traversal and control characters from the file name", async () => {
      const received = await receivedFor("../../etc/ev\u0000il\u001f.zip");
      expect(received.source).toBe("evil.zip");
    });
  });

  // #2124: the case is already published when the receipt is written, so a failed write is logged,
  // never turned into a 500 for an import that succeeded.
  it("still answers 201 when the archive receipt cannot be written", async () => {
    const { app, store, stateStore, custodyStore } = await harness();
    const zip = await seedAndArchive(app, stateStore);
    const record = custodyStore.record.bind(custodyStore);
    custodyStore.record = async (caseId, entry) => {
      if (entry.event === "received" && entry.trigger === "zip-case-import") throw new Error("disk full");
      return record(caseId, entry);
    };

    const res = await request(app)
      .post("/cases/import/zip")
      .send({ data: zip.toString("base64"), targetCaseId: "INC-2" });
    expect(res.status).toBe(201);
    const log = await readFile(store.custodyLogPath("INC-2"), "utf8");
    expect(log).toContain('"transferred"');
    expect(log).not.toContain("zip-case-import/");
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
