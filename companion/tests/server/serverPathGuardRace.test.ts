import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";

// #1834: the guard judged a path once, then the routes re-opened it BY PATH after several awaits.
// A swap in between — the checked file replaced by a symlink to a protected file — read the
// protected file. This suite performs that swap at the worst moment: right after ANY function the
// guard module exports resolves (the mock wraps them all, so it fits the old check-only API and the
// new open-and-judge API alike). The route must still end up with the bytes of the file it judged.

let afterGuard: (() => Promise<void>) | null = null;

vi.mock("../../src/routes/serverPathGuard.js", async (importOriginal) => {
  const real = await importOriginal<Record<string, unknown>>();
  const wrapped: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(real)) {
    wrapped[name] =
      typeof value === "function"
        ? async (...args: unknown[]) => {
            const result = await (value as (...a: unknown[]) => Promise<unknown>)(...args);
            if (afterGuard) await afterGuard();
            return result;
          }
        : value;
  }
  return wrapped;
});

const BENIGN = JSON.stringify({
  time: "2026-05-16T08:00:00Z",
  hostname: "WS1",
  level: "Warning",
  module: "Filescan",
  message: "benign",
});
const SECRET_CASE = JSON.stringify({
  time: "2026-05-16T08:00:00Z",
  hostname: "OTHER",
  level: "Alert",
  module: "Filescan",
  message: "protected content from another case",
});

let root: string;
let store: CaseStore;
let protectedFile: string;
const savedEnvFile = process.env.DFIR_ENV_FILE;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-path-race-"));
  await mkdir(join(root, "config"));
  process.env.DFIR_ENV_FILE = join(root, "config", ".env");
  await writeFile(process.env.DFIR_ENV_FILE, "DFIR_FAKE_PROVIDER_KEY=not-a-real-value\n");
  store = new CaseStore(join(root, "cases"));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await store.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
  // A protected file: inside another case's storage. The guard refuses it when named directly.
  protectedFile = join(store.caseDir("c2"), "imports", "secret.jsonl");
  await mkdir(join(store.caseDir("c2"), "imports"), { recursive: true });
  await writeFile(protectedFile, SECRET_CASE + "\n");
});

afterEach(async () => {
  afterGuard = null;
  if (savedEnvFile === undefined) delete process.env.DFIR_ENV_FILE;
  else process.env.DFIR_ENV_FILE = savedEnvFile;
  await rm(root, { recursive: true, force: true });
});

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

/** Arm the swap: after the guard returns, `path` becomes a symlink to the protected file. */
async function armSwap(path: string): Promise<boolean> {
  const probe = join(root, "probe-link");
  // Windows CI may lack the symlink privilege; the swap cannot be staged there.
  const canLink = await symlink(protectedFile, probe).then(
    () => true,
    () => false,
  );
  if (!canLink) return false;
  afterGuard = async () => {
    afterGuard = null;
    await rm(path, { force: true });
    await symlink(protectedFile, path);
  };
  return true;
}

describe("a path swapped after the guard never reads the protected file (#1834)", () => {
  it("/import-file stores the judged file's bytes, never the swapped-in target's", async () => {
    const evidence = join(root, "evidence.jsonl");
    await writeFile(evidence, BENIGN + "\n");
    if (!(await armSwap(evidence))) return;
    const res = await request(app()).post("/cases/c1/import-file").send({ path: evidence });
    const stored = await readdir(store.importsDir("c1")).catch(() => [] as string[]);
    for (const name of stored) {
      const bytes = await readFile(join(store.importsDir("c1"), name), "utf8");
      expect(bytes, `stored ${name}`).not.toContain("protected content");
    }
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    expect(stored).toHaveLength(1);
    expect(await readFile(join(store.importsDir("c1"), stored[0]), "utf8")).toBe(BENIGN + "\n");
  });

  it("POST /custody records the judged file's hash, never the swapped-in target's", async () => {
    const evidence = join(root, "image.bin");
    await writeFile(evidence, "benign evidence bytes");
    if (!(await armSwap(evidence))) return;
    const res = await request(app()).post("/cases/c1/custody").send({ artifactPath: evidence });
    const sha = (s: string) => createHash("sha256").update(s).digest("hex");
    expect(res.body.record?.sha256).not.toBe(sha(SECRET_CASE + "\n"));
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.record.sha256).toBe(sha("benign evidence bytes"));
  });
});
