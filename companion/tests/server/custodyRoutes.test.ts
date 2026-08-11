import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { createApp } from "../../src/server.js";

let app: ReturnType<typeof createApp>;
let cases: CaseStore;
let artifactPath: string;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-custodyroute-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  app = createApp(cases, { custodyStore: new CustodyStore(cases) });
  artifactPath = join(cases.importsDir("c1"), "evidence.csv");
  await writeFile(artifactPath, "hello world\n", "utf8");
});

describe("GET /cases/:id/custody", () => {
  it("returns an empty list before anything is recorded", async () => {
    const res = await request(app).get("/cases/c1/custody");
    expect(res.status).toBe(200);
    expect(res.body.records).toEqual([]);
  });

  it("404s for a case that does not exist", async () => {
    const res = await request(app).get("/cases/nope/custody");
    expect(res.status).toBe(404);
  });

  it("501s when no custody store is configured", async () => {
    const bare = createApp(cases, {});
    expect((await request(bare).get("/cases/c1/custody")).status).toBe(501);
    expect((await request(bare).post("/cases/c1/custody").send({ artifactPath })).status).toBe(501);
    expect((await request(bare).get("/cases/c1/custody/verify")).status).toBe(501);
  });
});

describe("POST /cases/:id/custody", () => {
  it("hashes the artifact server-side and returns the stored record", async () => {
    const res = await request(app)
      .post("/cases/c1/custody")
      .send({ artifactPath, collectedBy: "alice", source: "import", trigger: "manual" });
    expect(res.status).toBe(201);
    expect(res.body.ok).toBe(true);
    expect(res.body.record.sha256).toBe(createHash("sha256").update("hello world\n").digest("hex"));
    expect(res.body.record.collectedBy).toBe("alice");
    expect(res.body.record.caseId).toBe("c1");
    expect(Date.parse(res.body.record.collectedAt)).not.toBeNaN();

    const list = await request(app).get("/cases/c1/custody");
    expect(list.body.records).toHaveLength(1);
    expect(list.body.records[0].artifactPath).toBe(artifactPath);
  });

  it("defaults collectedBy to 'analyst' when it is absent", async () => {
    const res = await request(app).post("/cases/c1/custody").send({ artifactPath });
    expect(res.status).toBe(201);
    expect(res.body.record.collectedBy).toBe("analyst");
  });

  it("400s when artifactPath is missing or blank", async () => {
    expect((await request(app).post("/cases/c1/custody").send({})).status).toBe(400);
    expect((await request(app).post("/cases/c1/custody").send({ artifactPath: "   " })).status).toBe(400);
  });

  it("400s when the artifact cannot be read", async () => {
    const res = await request(app)
      .post("/cases/c1/custody")
      .send({ artifactPath: join(tmpdir(), "definitely-not-here.bin") });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/could not read artifact/);
  });

  it("404s for a case that does not exist", async () => {
    expect((await request(app).post("/cases/nope/custody").send({ artifactPath })).status).toBe(404);
  });

  it("423s on a closed case and records nothing", async () => {
    await cases.updateCaseMeta("c1", { status: "closed" });
    const res = await request(app).post("/cases/c1/custody").send({ artifactPath });
    expect(res.status).toBe(423);
    expect((await request(app).get("/cases/c1/custody")).body.records).toEqual([]);
  });

  // Guards the streaming hash: an artifact larger than the 1 MB read chunk must hash across
  // several chunks and still match a one-shot digest of the same bytes.
  it("hashes an artifact spanning multiple read chunks", async () => {
    const big = join(cases.importsDir("c1"), "big.bin");
    const bytes = randomBytes(3 * 1024 * 1024 + 17);
    await writeFile(big, bytes);
    const res = await request(app).post("/cases/c1/custody").send({ artifactPath: big });
    expect(res.status).toBe(201);
    expect(res.body.record.sha256).toBe(createHash("sha256").update(bytes).digest("hex"));
  });
});

describe("GET /cases/:id/custody/verify", () => {
  const recordIt = () => request(app).post("/cases/c1/custody").send({ artifactPath, collectedBy: "alice" });

  it("reports ok with no mismatches while the artifact is untouched", async () => {
    await recordIt();
    const res = await request(app).get("/cases/c1/custody/verify");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.mismatches).toEqual([]);
  });

  it("reports a hash-mismatch after the artifact is modified", async () => {
    await recordIt();
    await writeFile(artifactPath, "tampered\n", "utf8");
    const res = await request(app).get("/cases/c1/custody/verify");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
    expect(res.body.mismatches).toHaveLength(1);
    expect(res.body.mismatches[0].reason).toBe("hash-mismatch");
    expect(res.body.mismatches[0].artifactPath).toBe(artifactPath);
  });

  it("reports a missing artifact after the file is deleted", async () => {
    await recordIt();
    await rm(artifactPath);
    const res = await request(app).get("/cases/c1/custody/verify");
    expect(res.body.ok).toBe(false);
    expect(res.body.mismatches[0].reason).toBe("missing");
    expect(res.body.mismatches[0].actualSha256).toBeNull();
  });

  it("404s for a case that does not exist", async () => {
    expect((await request(app).get("/cases/nope/custody/verify")).status).toBe(404);
  });
});
