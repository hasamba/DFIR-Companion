import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  link,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  readlink,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { openImportPath } from "../../src/routes/serverPathGuard.js";
import { confirmedPath, openedPath } from "../../src/storage/handlePath.js";

// #1834: the guard opens the file and judges the OPEN handle; the route reads only that handle.
// These cases use the real filesystem, no mocks: a swap after the open, a hardlink alias of a case
// file outside the cases root, a hardlink opened and then unlinked, a FIFO, and descriptor leaks.

const BENIGN = "benign evidence line\n";
let root: string;
let store: CaseStore;
const savedEnvFile = process.env.DFIR_ENV_FILE;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-path-handle-"));
  await mkdir(join(root, "config"));
  process.env.DFIR_ENV_FILE = join(root, "config", ".env");
  await writeFile(process.env.DFIR_ENV_FILE, "DFIR_FAKE_PROVIDER_KEY=not-a-real-value\n");
  store = new CaseStore(join(root, "cases"));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await store.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
});

afterEach(async () => {
  if (savedEnvFile === undefined) delete process.env.DFIR_ENV_FILE;
  else process.env.DFIR_ENV_FILE = savedEnvFile;
  await rm(root, { recursive: true, force: true });
});

const canSymlink = async (): Promise<boolean> =>
  symlink(join(root, "config"), join(root, "probe")).then(
    () => true,
    () => false, // Windows CI may lack the symlink privilege
  );

/** How many of this process's descriptors are open on `path` (Linux; 0 elsewhere). */
async function fdsOn(path: string): Promise<number> {
  if (process.platform !== "linux") return 0;
  const links = await Promise.all(
    (await readdir("/proc/self/fd")).map((fd) => readlink(`/proc/self/fd/${fd}`).catch(() => "")),
  );
  return links.filter((l) => l === path).length;
}

describe("openServerPath judges and returns the open handle (#1834)", () => {
  it("a path swapped for a symlink AFTER the open still reads the judged file", async () => {
    if (!(await canSymlink())) return;
    const evidence = join(root, "evidence.txt");
    await writeFile(evidence, BENIGN);
    const opened = await openImportPath(evidence, store, "c1");
    expect(opened.refusal).toBeUndefined();
    await rm(evidence);
    await symlink(join(store.caseDir("c2"), "case.json"), evidence);
    try {
      const buf = Buffer.alloc(64);
      const { bytesRead } = await opened.file!.handle.read(buf, 0, 64, 0);
      expect(buf.subarray(0, bytesRead).toString()).toBe(BENIGN);
    } finally {
      await opened.file!.handle.close();
    }
  });

  it("refuses a hardlink of another case's file placed OUTSIDE the cases root", async () => {
    const alias = join(root, "looks-like-evidence.json");
    await link(join(store.caseDir("c2"), "case.json"), alias);
    const opened = await openImportPath(alias, store, "c1");
    expect(opened.refusal).toMatchObject({ status: 403 });
    expect(opened.refusal!.error).toMatch(/hard link/);
  });

  it("reads ordinary hard-linked evidence whose other name is not protected", async () => {
    const evidence = join(root, "collection", "a.txt");
    await mkdir(join(root, "collection"));
    await writeFile(evidence, BENIGN);
    await link(evidence, join(root, "collection", "dedup-copy.txt"));
    const opened = await openImportPath(evidence, store, "c1");
    expect(opened.refusal).toBeUndefined();
    await opened.file!.handle.close();
  });

  it("refuses a hardlink of an .env variant beside the live env file", async () => {
    const bak = join(root, "config", ".env.bak");
    await writeFile(bak, "DFIR_FAKE_PROVIDER_KEY=not-a-real-value\n");
    const alias = join(root, "notes.txt");
    await link(bak, alias);
    expect((await openImportPath(alias, store, "c1")).refusal).toMatchObject({ status: 403 });
  });

  it("refuses a FIFO without blocking", async () => {
    if (process.platform === "win32") return;
    const fifo = join(root, "pipe");
    execFileSync("mkfifo", [fifo]);
    const opened = await openImportPath(fifo, store, "c1");
    expect(opened.refusal).toMatchObject({ status: 400 });
    expect(opened.refusal!.error).toMatch(/not a regular file/);
  });

  it("closes the handle on a refusal", async () => {
    const protectedFile = await realpath(join(store.caseDir("c2"), "case.json"));
    for (let i = 0; i < 5; i++) await openImportPath(protectedFile, store, "c1");
    expect(await fdsOn(protectedFile)).toBe(0);
  });
});

describe("storage/handlePath (#1834)", () => {
  it("a hardlink opened and then unlinked cannot be pinned to its old, harmless name", async () => {
    const protectedFile = join(store.caseDir("c2"), "case.json");
    const alias = join(root, "alias.json");
    await link(protectedFile, alias);
    const handle = await open(alias, "r");
    try {
      await unlink(alias); // only the protected name remains: nlink is back to 1
      const st = await handle.stat({ bigint: true });
      expect(st.nlink).toBe(1n);
      expect(await openedPath(handle, alias, st)).not.toBe(alias);
      expect(await confirmedPath(alias, st)).toBeNull();
    } finally {
      await handle.close();
    }
  });

  it("the fallback refuses a final component swapped after the open, and pins an unchanged one", async () => {
    const target = join(root, "file.txt");
    await writeFile(target, BENIGN);
    const handle = await open(target, "r");
    try {
      const st = await handle.stat({ bigint: true });
      expect(await confirmedPath(target, st)).toBe(target);
      await rm(target);
      await writeFile(target, "another inode\n");
      expect(await confirmedPath(target, st)).toBeNull();
    } finally {
      await handle.close();
    }
  });
});

describe("routes read the judged handle and close it (#1834)", () => {
  function app() {
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

  it("/import-file copies the file byte for byte and releases the descriptor", async () => {
    const evidence = join(root, "thor.jsonl");
    const line = JSON.stringify({
      time: "2026-05-16T08:00:00Z",
      hostname: "WS1",
      level: "Warning",
      module: "Filescan",
      message: "x",
    });
    await writeFile(evidence, line + "\n");
    const res = await request(app()).post("/cases/c1/import-file").send({ path: evidence });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    const [stored] = await readdir(store.importsDir("c1"));
    expect(await readFile(join(store.importsDir("c1"), stored), "utf8")).toBe(line + "\n");
    await new Promise((r) => setTimeout(r, 50));
    expect(await fdsOn(await realpath(evidence))).toBe(0);
  });

  it("/import-file and POST /custody name a hardlink alias as a refusal", async () => {
    const alias = join(root, "alias.json");
    await link(join(store.caseDir("c2"), "case.json"), alias);
    const server = app();
    expect((await request(server).post("/cases/c1/import-file").send({ path: alias })).status).toBe(403);
    expect((await request(server).post("/cases/c1/custody").send({ artifactPath: alias })).status).toBe(403);
  });
});
