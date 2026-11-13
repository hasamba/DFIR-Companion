import { describe, it, expect, vi, beforeEach } from "vitest";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";

/**
 * GET /settings/browse-fs must answer 403 / 400 for a folder it cannot read or that is not a
 * folder, not 500 (#2617). The mocked readdir keeps this deterministic when run as root.
 */
const readdirFault = vi.hoisted(() => ({ code: null as string | null }));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    readdir: ((...args: Parameters<typeof actual.readdir>) => {
      if (readdirFault.code) {
        return Promise.reject(
          Object.assign(new Error(`${readdirFault.code}: scandir '/secret/path'`), {
            code: readdirFault.code,
          }),
        );
      }
      return actual.readdir(...args);
    }) as typeof actual.readdir,
  };
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-browse-fs-err-"));
  const store = new CaseStore(root);
  return createApp(store, { stateStore: new StateStore(store), demoMode: false });
}

describe("GET /settings/browse-fs error mapping", () => {
  beforeEach(() => {
    readdirFault.code = null;
  });

  it.each(["EACCES", "EPERM"])("maps %s to 403 with a clear message and no raw detail", async (code) => {
    readdirFault.code = code;
    const res = await request(await harness()).get("/settings/browse-fs");
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/cannot read this folder/i);
    expect(JSON.stringify(res.body)).not.toMatch(/scandir|secret/);
  });

  it.each(["ENOTDIR", "ELOOP", "ENAMETOOLONG"])("maps %s to 400", async (code) => {
    readdirFault.code = code;
    const res = await request(await harness()).get("/settings/browse-fs");
    expect(res.status).toBe(400);
    expect(res.body.error).toBeTruthy();
    expect(JSON.stringify(res.body)).not.toMatch(/scandir|secret/);
  });

  it("keeps unknown errors at 500 without leaking the raw message", async () => {
    readdirFault.code = "EIO";
    const res = await request(await harness()).get("/settings/browse-fs");
    expect(res.status).toBe(500);
    expect(JSON.stringify(res.body)).not.toMatch(/scandir|secret/);
  });

  const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
  it.skipIf(isRoot || process.platform === "win32")("answers 403 for a real chmod 000 folder", async () => {
    const app = await harness();
    const dir = await mkdtemp(join(tmpdir(), "dfir-browse-fs-000-"));
    await chmod(dir, 0o000);
    try {
      const res = await request(app).get("/settings/browse-fs").query({ dir });
      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/cannot read/i);
    } finally {
      await chmod(dir, 0o700);
      await rm(dir, { recursive: true, force: true });
    }
  });
});
