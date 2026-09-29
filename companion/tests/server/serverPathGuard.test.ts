import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { link, mkdir, mkdtemp, readdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import {
  openImportPath,
  openServerPath,
  type ServerPathPolicy,
  type ServerPathRefusal,
} from "../../src/routes/serverPathGuard.js";

// The guard now opens and judges the handle (#1834). These unit cases only need the verdict:
// the refusal, or null when the route may read it (the handle is closed here).
async function verdict(
  p: Promise<Awaited<ReturnType<typeof openServerPath>>>,
): Promise<ServerPathRefusal | null> {
  const opened = await p;
  if (opened.refusal) return opened.refusal;
  await opened.file.handle.close();
  return null;
}
const refuseImportPath = (p: string, s: CaseStore, caseId: string) => verdict(openImportPath(p, s, caseId));
const refuseServerPath = (p: string, policy: ServerPathPolicy) => verdict(openServerPath(p, policy));

// #1792: /import-file copied any server path into a case — the Companion's own .env included, whose
// API keys GET /settings/env masks even for admins — and every case reader could then download it.
// The routes that read a caller-named server path now refuse the config, the case storage (except
// the target case's drop folder / own files) and relative paths. The env file here is a FAKE.

const FAKE_ENV = "DFIR_FAKE_PROVIDER_KEY=not-a-real-value\n";
const THOR = JSON.stringify({
  time: "2026-05-16T08:00:00Z",
  hostname: "WS1",
  level: "Warning",
  module: "Filescan",
  message: "x",
});

let root: string;
let envFile: string;
let store: CaseStore;
const savedEnvFile = process.env.DFIR_ENV_FILE;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-path-guard-"));
  await mkdir(join(root, "config"));
  envFile = join(root, "config", ".env");
  await writeFile(envFile, FAKE_ENV);
  process.env.DFIR_ENV_FILE = envFile;
  store = new CaseStore(join(root, "cases"));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await store.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
});

afterEach(() => {
  if (savedEnvFile === undefined) delete process.env.DFIR_ENV_FILE;
  else process.env.DFIR_ENV_FILE = savedEnvFile;
});

describe("refuseImportPath", () => {
  it("refuses a relative path with a 400", async () => {
    expect(await refuseImportPath("package.json", store, "c1")).toMatchObject({ status: 400 });
  });

  it("refuses the live env file, by path, symlink, hardlink and a .env.bak beside it", async () => {
    const sym = join(root, "innocent.txt");
    // Windows CI may lack the symlink privilege; the other three paths still run there.
    const hasSym = await symlink(envFile, sym).then(
      () => true,
      () => false,
    );
    const hard = join(root, "hard.txt");
    await link(envFile, hard);
    const bak = join(root, "config", ".env.bak");
    await writeFile(bak, FAKE_ENV);
    for (const p of [envFile, hard, bak, ...(hasSym ? [sym] : [])]) {
      const r = await refuseImportPath(p, store, "c1");
      expect(r, p).toMatchObject({ status: 403 });
      expect(r!.error).toMatch(/own configuration/);
    }
  });

  it("refuses case storage: case.json, another case's drop folder, the cases root itself", async () => {
    const otherDrop = join(store.caseDir("c2"), "drop");
    await mkdir(otherDrop, { recursive: true });
    await writeFile(join(otherDrop, "e.jsonl"), THOR);
    for (const p of [join(store.caseDir("c1"), "case.json"), join(otherDrop, "e.jsonl")]) {
      const r = await refuseImportPath(p, store, "c1");
      expect(r, p).toMatchObject({ status: 403 });
      expect(r!.error).toMatch(/case storage/);
    }
    // A folder is never opened as a file (#1834): refused before anything is read.
    expect(await refuseImportPath(store.casesRoot, store, "c1")).toMatchObject({ status: 400 });
  });

  it("allows the target case's own drop folder, but not a hardlink placed in it", async () => {
    const drop = join(store.caseDir("c1"), "drop");
    await mkdir(drop, { recursive: true });
    await writeFile(join(drop, "big.jsonl"), THOR);
    expect(await refuseImportPath(join(drop, "big.jsonl"), store, "c1")).toBeNull();
    await link(join(store.caseDir("c2"), "case.json"), join(drop, "sneaky.json"));
    expect(await refuseImportPath(join(drop, "sneaky.json"), store, "c1")).toMatchObject({ status: 403 });
  });

  it("allows an ordinary evidence file outside the Companion; a missing file throws for the route to report", async () => {
    const evidence = join(root, "evidence.jsonl");
    await writeFile(evidence, THOR);
    expect(await refuseImportPath(evidence, store, "c1")).toBeNull();
    await expect(refuseImportPath(join(root, "missing.jsonl"), store, "c1")).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("custody policy: this case's own files are allowed, other cases' are not", async () => {
    const policy = { casesRoot: store.casesRoot, allowUnder: [store.caseDir("c1")], allowedLabel: "x" };
    expect(await refuseServerPath(join(store.caseDir("c1"), "case.json"), policy)).toBeNull();
    expect(await refuseServerPath(join(store.caseDir("c2"), "case.json"), policy)).toMatchObject({
      status: 403,
    });
  });
});

describe("routes refuse protected server paths (#1792)", () => {
  function importApp() {
    const stateStore = new StateStore(store);
    const pipeline = buildRuntimePipeline({
      provider: undefined,
      synthesisProvider: undefined,
      stateStore,
      store,
      imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
    });
    return createApp(store, { pipeline, stateStore, custodyStore: new CustodyStore(store) });
  }

  it("/import-file refuses the env file and copies nothing", async () => {
    const res = await request(importApp()).post("/cases/c1/import-file").send({ path: envFile });
    expect(res.status, JSON.stringify(res.body)).toBe(403);
    expect(res.body.error).toMatch(/own configuration/);
    expect(await readdir(store.importsDir("c1")).catch(() => [])).toEqual([]);
  });

  it("/import-file refuses a relative path and a case's case.json", async () => {
    const app = importApp();
    expect((await request(app).post("/cases/c1/import-file").send({ path: "package.json" })).status).toBe(
      400,
    );
    const caseJson = join(store.caseDir("c1"), "case.json");
    expect((await request(app).post("/cases/c1/import-file").send({ path: caseJson })).status).toBe(403);
  });

  it("/import-file still imports a file from this case's drop folder", async () => {
    const drop = join(store.caseDir("c1"), "drop");
    await mkdir(drop, { recursive: true });
    await writeFile(join(drop, "thor.jsonl"), THOR + "\n");
    const res = await request(importApp())
      .post("/cases/c1/import-file")
      .send({ path: join(drop, "thor.jsonl") });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
  });

  it("/import-mac-login-item refuses the env file", async () => {
    const res = await request(importApp()).post("/cases/c1/import-mac-login-item").send({ path: envFile });
    expect(res.status, JSON.stringify(res.body)).toBe(403);
  });

  it("POST /custody refuses the env file and another case's file, and records this case's own", async () => {
    const app = importApp();
    expect((await request(app).post("/cases/c1/custody").send({ artifactPath: envFile })).status).toBe(403);
    const other = join(store.caseDir("c2"), "case.json");
    expect((await request(app).post("/cases/c1/custody").send({ artifactPath: other })).status).toBe(403);
    const own = join(store.caseDir("c1"), "case.json");
    expect((await request(app).post("/cases/c1/custody").send({ artifactPath: own })).status).toBe(201);
  });
});
