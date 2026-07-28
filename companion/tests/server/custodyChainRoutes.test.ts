import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
let artifactPath: string;
let logPath: string;

const recordIt = (body: Record<string, unknown> = {}) =>
  request(app).post("/cases/c1/custody").send({ artifactPath, collectedBy: "alice", ...body });

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-custodychainroute-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, { custodyStore: new CustodyStore(cases) });
  artifactPath = join(cases.importsDir("c1"), "evidence.csv");
  await writeFile(artifactPath, "hello world\n", "utf8");
  logPath = cases.custodyLogPath("c1");
});

describe("POST /cases/:id/custody event", () => {
  it("defaults to the collected event", async () => {
    const res = await recordIt();

    expect(res.status).toBe(201);
    expect(res.body.record).toMatchObject({ event: "collected", seq: 1, prevHash: "" });
  });

  it("records a transfer the analyst reports", async () => {
    const res = await recordIt({ event: "transferred", source: "handed to lab-3" });

    expect(res.body.record.event).toBe("transferred");
  });

  it("400s on an event outside the known set rather than logging it", async () => {
    const res = await recordIt({ event: "shredded" });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/event/);
    await expect(readFile(logPath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("GET /cases/:id/custody/verify chain", () => {
  it("reports an intact chain alongside the artifact hashes", async () => {
    await recordIt();
    await recordIt();

    const res = await request(app).get("/cases/c1/custody/verify");

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true, mismatches: [], chainBreaks: [] });
  });

  it("reports not-ok when the log was edited even though every artifact still hashes clean", async () => {
    await recordIt();
    await recordIt();
    const [first, second] = (await readFile(logPath, "utf8")).split("\n").filter((l) => l.trim());
    const tampered = JSON.parse(first) as Record<string, unknown>;
    tampered.collectedBy = "mallory";
    await writeFile(logPath, JSON.stringify(tampered) + "\n" + second + "\n", "utf8");

    const res = await request(app).get("/cases/c1/custody/verify");

    // The artifact itself was never touched — only the record of who collected it.
    expect(res.body.mismatches).toEqual([]);
    expect(res.body.chainBreaks).toEqual([{ line: 2, seq: 2, reason: "prev-hash-mismatch" }]);
    expect(res.body.ok).toBe(false);
  });
});
