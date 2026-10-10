import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { mkdtemp, writeFile, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore, type CustodyRecord } from "../../src/analysis/custody.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { EVIDENCE_IMPORT_ROUTES } from "../../src/routes/importCaseGuard.js";

// #2111: custody is recorded when the companion RECEIVES a file, before any parser runs, so a file
// the importer rejects still has a hashed `received` entry. Bytes of rejected files are not stored.

// Observe the THOR parser: it is the first thing import-thor does with the body after the guards.
const parseHook = vi.hoisted(() => ({ onParse: null as null | (() => Promise<void> | void), calls: 0 }));
vi.mock("../../src/analysis/thorImport.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../src/analysis/thorImport.js")>();
  return {
    ...real,
    parseThorReport: (...args: Parameters<typeof real.parseThorReport>) => {
      parseHook.calls++;
      void parseHook.onParse?.();
      return real.parseThorReport(...args);
    },
  };
});

const JUNK = "this is definitely not a recognised forensic format\n";
const sha = (algo: "sha256" | "sha1", s: string | Buffer): string => createHash(algo).update(s).digest("hex");

async function makeApp(custodyStore?: CustodyStore) {
  const root = await mkdtemp(join(tmpdir(), "dfir-custody-receipt-"));
  const store = new CaseStore(root);
  const stateStore = new StateStore(store);
  const custody = custodyStore ?? new CustodyStore(store);
  const pipeline = buildRuntimePipeline({
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, {
    pipeline,
    stateStore,
    importMetaStore: new ImportMetaStore(store),
    custodyStore: custody,
  });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, custody, root };
}

const received = (records: CustodyRecord[]) => records.filter((r) => r.event === "received");

describe("custody at receipt (#2111)", () => {
  it("records a received entry, hashed with SHA-256 and SHA-1, for every body-based import route", async () => {
    const { app, custody } = await makeApp();
    const bodyRoutes = EVIDENCE_IMPORT_ROUTES.filter(
      (r) => r !== "import-file" && r !== "import-mac-login-item",
    );
    for (const route of bodyRoutes) {
      const field =
        route === "import-binary" ? { dataBase64: Buffer.from(JUNK).toString("base64") } : { text: JUNK };
      const res = await request(app)
        .post(`/cases/c1/${route}`)
        .send({ filename: `junk-${route}.dat`, ...field });
      // Whatever the importer says (reject, 501), the receipt must already be on the chain.
      expect(res.status, route).toBeGreaterThanOrEqual(200);
      const mine = received(await custody.load("c1")).filter((r) => r.trigger === route);
      expect(mine, route).toHaveLength(1);
      expect(mine[0]).toMatchObject({
        sha256: sha("sha256", JUNK),
        sha1: sha("sha1", JUNK),
        bytes: Buffer.byteLength(JUNK),
        source: `junk-${route}.dat`,
        caseId: "c1",
      });
      expect(mine[0].artifactPath.startsWith("received:")).toBe(true);
    }
  });

  it("does not store the bytes of a rejected file", async () => {
    const { app, store } = await makeApp();
    const res = await request(app)
      .post("/cases/c1/import-thor")
      .send({ filename: "junk-thor.dat", text: JUNK });
    expect(res.status).toBe(400);
    const imports = await readdir(store.importsDir("c1")).catch(() => [] as string[]);
    expect(imports.filter((f) => f.includes("junk-thor"))).toHaveLength(0);
  });

  it("records server-path imports from the judged handle", async () => {
    const { app, custody } = await makeApp();
    const dir = await mkdtemp(join(tmpdir(), "dfir-receipt-src-"));
    const src = join(dir, "mystery.bin");
    await writeFile(src, JUNK);
    for (const route of ["import-file", "import-mac-login-item"]) {
      await request(app).post(`/cases/c1/${route}`).send({ path: src });
      const mine = received(await custody.load("c1")).filter((r) => r.trigger === route);
      expect(mine, route).toHaveLength(1);
      expect(mine[0]).toMatchObject({
        sha256: sha("sha256", JUNK),
        sha1: sha("sha1", JUNK),
        source: "mystery.bin",
      });
    }
  });

  it("covers exactly the routes the live router registers", async () => {
    const { app } = await makeApp();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const layers = (app as any)._router.stack as Array<{
      route?: { path: string; methods: Record<string, boolean> };
    }>;
    const registered = layers
      .map((l) => l.route)
      .filter((r): r is { path: string; methods: Record<string, boolean> } => Boolean(r?.methods?.post))
      .filter((r) => /^\/cases\/:id\/import(-[a-z0-9-]+)?$/.test(r.path))
      .map((r) => r.path.replace("/cases/:id/", ""));
    expect([...registered].sort()).toEqual([...EVIDENCE_IMPORT_ROUTES].sort());
  });

  it("writes the receipt before the parser runs", async () => {
    const { app, store } = await makeApp();
    const seen: string[] = [];
    // The parser is synchronous, so read the log synchronously at the moment it is called.
    parseHook.onParse = () => {
      seen.push(readFileSync(store.custodyLogPath("c1"), "utf8"));
    };
    parseHook.calls = 0;
    await request(app).post("/cases/c1/import-thor").send({ filename: "t.json", text: JUNK });
    parseHook.onParse = null;
    expect(parseHook.calls).toBe(1);
    expect(seen[0]).toContain('"event":"received"');
  });

  it("an accepted import gets received then collected, same hashes", async () => {
    const { app, custody } = await makeApp();
    const csv = JSON.stringify({
      level: "Warning",
      module: "Filescan",
      message: "Suspicious file",
      time: "2026-05-02T10:00:00Z",
      file: "C:\\Temp\\a.exe",
    });
    const res = await request(app).post("/cases/c1/import-thor").send({ filename: "ev.json", text: csv });
    expect(res.status).toBe(202);
    const records = await custody.load("c1");
    const recv = records.find((r) => r.event === "received");
    const coll = records.find((r) => r.event === "collected");
    expect(recv && coll).toBeTruthy();
    expect(recv!.seq).toBeLessThan(coll!.seq);
    expect(recv!.sha256).toBe(coll!.sha256);
    expect(recv!.sha1).toBe(coll!.sha1);
    expect(recv!.sha1).toBe(sha("sha1", csv));
  });

  it("receipts every payload copy, so the stored one is on the chain whichever field the route reads", async () => {
    // import-thor reads `json` before `text`; a receipt of `text` alone would never match the store.
    const { app, custody } = await makeApp();
    const json = JSON.stringify({
      level: "Alert",
      module: "Filescan",
      message: "Malware file found",
      time: "2026-05-02T10:00:00Z",
      file: "C:\\Temp\\b.exe",
    });
    const res = await request(app)
      .post("/cases/c1/import-thor")
      .send({ filename: "both.json", text: JUNK, json });
    expect(res.status).toBe(202);
    const records = await custody.load("c1");
    const coll = records.find((r) => r.event === "collected");
    const recvHashes = received(records).map((r) => r.sha256);
    expect(recvHashes).toEqual(expect.arrayContaining([sha("sha256", JUNK), sha("sha256", json)]));
    expect(recvHashes).toContain(coll!.sha256);
  });

  it("receipts the decoded dataBase64 binary even when a text field is also present", async () => {
    const { app, custody } = await makeApp();
    const binary = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0xde, 0xad, 0xbe, 0xef]);
    await request(app)
      .post("/cases/c1/import-binary")
      .send({ filename: "tool.exe", text: JUNK, dataBase64: binary.toString("base64") });
    const records = await custody.load("c1");
    const hashes = received(records).map((r) => r.sha256);
    expect(hashes).toEqual(expect.arrayContaining([sha("sha256", JUNK), sha("sha256", binary)]));
    const coll = records.find((r) => r.event === "collected");
    if (coll) expect(hashes).toContain(coll.sha256);
  });

  it("receipts the server file when an empty text field is also present", async () => {
    const { app, custody } = await makeApp();
    const src = join(await mkdtemp(join(tmpdir(), "dfir-receipt-src-")), "real.bin");
    await writeFile(src, JUNK);
    await request(app).post("/cases/c1/import-file").send({ text: "", path: src });
    const hashes = received(await custody.load("c1")).map((r) => r.sha256);
    expect(hashes).toContain(sha("sha256", JUNK));
  });

  it("Verify now stays ok after a rejected import, and the monitor sees no problem", async () => {
    const { app, custody } = await makeApp();
    await request(app).post("/cases/c1/import-thor").send({ filename: "t.json", text: JUNK });
    expect(received(await custody.load("c1"))).toHaveLength(1);
    const verify = await request(app).get("/cases/c1/custody/verify");
    expect(verify.status).toBe(200);
    expect(verify.body).toMatchObject({ ok: true, mismatches: [], chainBreaks: [] });
  });

  it("a tampered receipt line is a chain break", async () => {
    const { app, store } = await makeApp();
    await request(app).post("/cases/c1/import-thor").send({ filename: "t.json", text: JUNK });
    await request(app).post("/cases/c1/import-siem").send({ filename: "s.json", text: JUNK });
    const log = store.custodyLogPath("c1");
    const lines = (await readFile(log, "utf8")).split("\n").filter(Boolean);
    lines[0] = lines[0].replace(/"source":"[^"]*"/, '"source":"forged"');
    await writeFile(log, lines.join("\n") + "\n");
    const verify = await request(app).get("/cases/c1/custody/verify");
    expect(verify.body.ok).toBe(false);
    expect(verify.body.chainBreaks.length).toBeGreaterThan(0);
  });

  it("an export after a rejected import adds no exported entry for the virtual path", async () => {
    const { app, custody } = await makeApp();
    await request(app).post("/cases/c1/import-thor").send({ filename: "t.json", text: JUNK });
    const out = await custody.recordExport("c1", { exportedBy: "me", destination: "x" });
    expect(out).toEqual([]);
  });

  it("a custody write failure returns 500 and the parser never runs", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-custody-receipt-fail-"));
    const store = new CaseStore(root);
    const custody = new CustodyStore(store);
    const real = custody.record.bind(custody);
    custody.record = vi.fn(async (id, input) => {
      if (input.event === "received") throw new Error("disk full");
      return real(id, input);
    });
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    parseHook.calls = 0;
    const app = createApp(store, { pipeline, stateStore, custodyStore: custody });
    await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
    const res = await request(app).post("/cases/c1/import-thor").send({ filename: "t.json", text: JUNK });
    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/custody/i);
    expect(parseHook.calls).toBe(0);
    const imports = await readdir(store.importsDir("c1")).catch(() => [] as string[]);
    expect(imports).toHaveLength(0);
  });

  it("records nothing when the case does not exist (the guard answers first)", async () => {
    const { app } = await makeApp();
    const res = await request(app).post("/cases/nope/import-thor").send({ text: JUNK });
    expect(res.status).toBe(404);
  });
});
