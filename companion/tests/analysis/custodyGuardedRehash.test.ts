import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { CustodyStore } from "../../src/analysis/custody.js";
import { createApp } from "../../src/server.js";

// #1841: verify, export and transfer re-hashed a recorded path BY NAME. A path swapped after the
// record was made — for a symlink to another case's file or to the config, or for a FIFO — leaked
// that file's SHA-256 through GET /custody/verify, or hung a worker on open(). The re-hash now goes
// through the same open-and-judge guard as recording, with the policy the record was made under.

const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
const SECRET = "protected content from another case\n";
const ENV_TEXT = "DFIR_FAKE_PROVIDER_KEY=not-a-real-value\n";

let root: string;
let cases: CaseStore;
let custody: CustodyStore;
let evidence: string;
let protectedFile: string;
const savedEnvFile = process.env.DFIR_ENV_FILE;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "dfir-custody-guarded-"));
  await mkdir(join(root, "config"));
  await mkdir(join(root, "evidence"));
  process.env.DFIR_ENV_FILE = join(root, "config", ".env");
  await writeFile(process.env.DFIR_ENV_FILE, ENV_TEXT);
  cases = new CaseStore(join(root, "cases"));
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  await cases.createCase({ caseId: "c2", name: "n", investigator: "i", aiProvider: null });
  protectedFile = join(cases.caseDir("c2"), "imports", "secret.jsonl");
  await mkdir(join(cases.caseDir("c2"), "imports"), { recursive: true });
  await writeFile(protectedFile, SECRET);
  custody = new CustodyStore(cases);
  evidence = join(root, "evidence", "memory.raw");
});

afterEach(async () => {
  if (savedEnvFile === undefined) delete process.env.DFIR_ENV_FILE;
  else process.env.DFIR_ENV_FILE = savedEnvFile;
  await rm(root, { recursive: true, force: true });
});

async function collect(path: string, text: string): Promise<void> {
  await writeFile(path, text);
  await custody.record("c1", {
    artifactPath: path,
    sha256: sha(text),
    collectedBy: "alice",
    collectedAt: "2026-09-29T10:00:00.000Z",
    source: "host-a",
    trigger: "manual",
    caseId: "c1",
  });
}

/** Replace `path` with a symlink to `to`. False where the platform will not create one. */
async function swapForSymlink(path: string, to: string): Promise<boolean> {
  await rm(path);
  try {
    await symlink(to, path);
    return true;
  } catch {
    return false;
  }
}

function swapForFifo(path: string): Promise<boolean> {
  if (process.platform === "win32") return Promise.resolve(false);
  return rm(path).then(() => {
    execFileSync("mkfifo", [path], { stdio: ["ignore", "pipe", "pipe"] });
    return true;
  });
}

describe("verifyIntegrity re-hashes through the server-path guard (#1841)", () => {
  it("verifies an untouched artifact outside case storage and one inside the case", async () => {
    await collect(evidence, "benign\n");
    await collect(join(cases.importsDir("c1"), "own.csv"), "own\n");
    expect(await custody.verifyIntegrity("c1")).toEqual([]);
  });

  it("still reports a real change as a hash-mismatch with the new hash", async () => {
    await collect(evidence, "benign\n");
    await writeFile(evidence, "tampered\n");
    expect(await custody.verifyIntegrity("c1")).toEqual([
      expect.objectContaining({ reason: "hash-mismatch", actualSha256: sha("tampered\n") }),
    ]);
  });

  it("refuses a recorded path swapped for a symlink to another case's file — no hash", async () => {
    await collect(evidence, "benign\n");
    if (!(await swapForSymlink(evidence, protectedFile))) return;

    const mismatches = await custody.verifyIntegrity("c1");
    expect(mismatches).toEqual([
      expect.objectContaining({ artifactPath: evidence, reason: "refused", actualSha256: null }),
    ]);
    expect(mismatches[0].detail).toMatch(/case storage/);
    expect(JSON.stringify(mismatches)).not.toContain(sha(SECRET));
  });

  it("refuses a recorded path swapped for a symlink to the Companion's config", async () => {
    await collect(evidence, "benign\n");
    if (!(await swapForSymlink(evidence, process.env.DFIR_ENV_FILE!))) return;

    const mismatches = await custody.verifyIntegrity("c1");
    expect(mismatches).toEqual([expect.objectContaining({ reason: "refused", actualSha256: null })]);
    expect(JSON.stringify(mismatches)).not.toContain(sha(ENV_TEXT));
  });

  it("refuses a FIFO without hanging", async () => {
    await collect(evidence, "benign\n");
    if (!(await swapForFifo(evidence))) return;

    const mismatches = await custody.verifyIntegrity("c1");
    expect(mismatches).toEqual([expect.objectContaining({ reason: "refused", actualSha256: null })]);
    expect(mismatches[0].detail).toMatch(/not a regular file/);
  }, 5000);

  it("still reports a deleted artifact as missing", async () => {
    await collect(evidence, "benign\n");
    await rm(evidence);
    expect(await custody.verifyIntegrity("c1")).toEqual([
      expect.objectContaining({ reason: "missing", actualSha256: null }),
    ]);
  });

  it("GET /cases/:id/custody/verify answers verified:false with the reason and no leaked hash", async () => {
    await collect(evidence, "benign\n");
    if (!(await swapForSymlink(evidence, protectedFile))) return;

    const res = await request(createApp(cases, { custodyStore: custody })).get("/cases/c1/custody/verify");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(false);
    expect(res.body.mismatches[0]).toMatchObject({ reason: "refused", actualSha256: null });
    expect(res.text).not.toContain(sha(SECRET));
  });
});

describe("recordExport and recordTransfer re-hash through the guard (#1841)", () => {
  it("records no exported event carrying a swapped-in protected file's hash", async () => {
    await collect(evidence, "benign\n");
    const own = join(cases.importsDir("c1"), "own.csv");
    await collect(own, "own\n");
    if (!(await swapForSymlink(evidence, protectedFile))) return;

    const written = await custody.recordExport("c1", { exportedBy: "alice", destination: "zip" });
    expect(written.map((r) => r.artifactPath)).toEqual([own]);
    expect(JSON.stringify(await custody.load("c1"))).not.toContain(sha(SECRET));
  });

  it("does not hang an export on a FIFO", async () => {
    await collect(evidence, "benign\n");
    if (!(await swapForFifo(evidence))) return;
    expect(await custody.recordExport("c1", { exportedBy: "alice", destination: "zip" })).toEqual([]);
  }, 5000);

  it("refuses a transfer of a swapped path and appends nothing", async () => {
    await collect(evidence, "benign\n");
    if (!(await swapForSymlink(evidence, protectedFile))) return;
    const before = await readFile(cases.custodyLogPath("c1"), "utf8");

    await expect(
      custody.recordTransfer("c1", {
        artifactPaths: [evidence],
        transferredBy: "alice",
        destination: "sift",
      }),
    ).rejects.toThrow(/cannot record transfer.*refused/);
    expect(await readFile(cases.custodyLogPath("c1"), "utf8")).toBe(before);
  });

  it("transfers an untouched artifact with its hash", async () => {
    await collect(evidence, "benign\n");
    const [rec] = await custody.recordTransfer("c1", {
      artifactPaths: [evidence],
      transferredBy: "alice",
      destination: "sift",
    });
    expect(rec).toMatchObject({ event: "transferred", sha256: sha("benign\n") });
  });
});
