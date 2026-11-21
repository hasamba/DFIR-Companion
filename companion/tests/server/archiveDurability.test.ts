// #2800: the archive a ZIP or encrypted delete saves in the cases root must be on disk — file bytes
// AND directory entry — before the case folder goes. Without the fsyncs a power loss or OS crash
// could persist the deletion while losing the archive's cached bytes, destroying both copies. When
// durability cannot be established the write fails, the route answers an error and the case stays.
import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { writeBufferNewFile } from "../../src/analysis/archiveNoClobber.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";

const faults = vi.hoisted(() => ({
  /** Return an error to fail the fsync of `path`, or null to let it run. */
  syncFails: null as null | ((path: string) => NodeJS.ErrnoException | null),
  linkFails: null as null | NodeJS.ErrnoException,
  synced: [] as string[],
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    open: (async (...args: Parameters<typeof actual.open>) => {
      const path = String(args[0]);
      // A folder is never really opened here: Windows refuses that before any sync could run, so a
      // stub handle stands in and the injected outcome is the same on every platform.
      if ((await actual.stat(path).catch(() => null))?.isDirectory()) {
        return {
          sync: async () => {
            const err = faults.syncFails?.(path);
            if (err) throw err;
            faults.synced.push(path);
          },
          close: async () => undefined,
        };
      }
      const fh = await actual.open(...args);
      const realSync = fh.sync.bind(fh);
      fh.sync = async () => {
        const err = faults.syncFails?.(path);
        if (err) throw err;
        faults.synced.push(path);
        return realSync();
      };
      return fh;
    }) as typeof actual.open,
    link: (async (...args: Parameters<typeof actual.link>) => {
      if (faults.linkFails) throw faults.linkFails;
      return actual.link(...args);
    }) as typeof actual.link,
  };
});

afterEach(() => {
  faults.syncFails = null;
  faults.linkFails = null;
  faults.synced = [];
});

function errno(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`${code}: injected`), { code });
}

const nameFor = (n: number) => (n === 1 ? "c1.zip" : `c1 (${n}).zip`);

async function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "dfir-durable-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe("writeBufferNewFile durability (#2800)", () => {
  it("fsyncs the temp file before publishing it and the directory after", async () => {
    await withDir(async (dir) => {
      const p = await writeBufferNewFile(dir, nameFor, Buffer.from("zip"));
      expect(p).toBe(join(dir, "c1.zip"));
      const tmpIdx = faults.synced.findIndex((s) => s.endsWith(".tmp"));
      const dirIdx = faults.synced.indexOf(dir);
      expect(tmpIdx).toBeGreaterThanOrEqual(0);
      expect(dirIdx).toBeGreaterThan(tmpIdx);
    });
  });

  it("fails and leaves nothing when the temp file cannot be synced", async () => {
    await withDir(async (dir) => {
      faults.syncFails = (p) => (p.endsWith(".tmp") ? errno("EIO") : null);
      await expect(writeBufferNewFile(dir, nameFor, Buffer.from("zip"))).rejects.toThrow(/EIO/);
      expect(await readdir(dir)).toEqual([]);
    });
  });

  it("fsyncs the published file after the copy fallback, and fails when that sync fails", async () => {
    await withDir(async (dir) => {
      faults.linkFails = errno("EPERM"); // no hard links here: the exclusive copy publishes
      await writeBufferNewFile(dir, nameFor, Buffer.from("zip"));
      expect(faults.synced).toContain(join(dir, "c1.zip"));
    });
    await withDir(async (dir) => {
      faults.linkFails = errno("EPERM");
      faults.syncFails = (p) => (p === join(dir, "c1.zip") ? errno("EIO") : null);
      await expect(writeBufferNewFile(dir, nameFor, Buffer.from("zip"))).rejects.toThrow(/EIO/);
      expect(await readdir(dir)).toEqual([]);
    });
  });

  it("fails and removes the published file when the directory cannot be synced", async () => {
    await withDir(async (dir) => {
      faults.syncFails = (p) => (p === dir ? errno("EIO") : null);
      await expect(writeBufferNewFile(dir, nameFor, Buffer.from("zip"))).rejects.toThrow(/EIO/);
      expect(await readdir(dir)).toEqual([]);
    });
  });

  it.each(["EPERM", "EISDIR", "EINVAL"])(
    "treats a directory fsync the platform does not support (%s) as best effort",
    async (code) => {
      await withDir(async (dir) => {
        faults.syncFails = (p) => (p === dir ? errno(code) : null);
        const p = await writeBufferNewFile(dir, nameFor, Buffer.from("zip"));
        expect(await readdir(dir)).toEqual(["c1.zip"]);
        expect(p).toBe(join(dir, "c1.zip"));
      });
    },
  );
});

async function harness() {
  const root = await mkdtemp(join(tmpdir(), "dfir-durable-route-"));
  const store = new CaseStore(root);
  const app = createApp(store, { stateStore: new StateStore(store) });
  await request(app).post("/cases").send({ caseId: "INC-D", name: "n", investigator: "i", aiProvider: null });
  expect((await request(app).patch("/cases/INC-D/status").send({ status: "closed" })).status).toBe(200);
  return { app, store };
}

describe("delete routes keep the case when the archive is not durable (#2800)", () => {
  it("encrypted delete: a failed fsync answers an error and deletes nothing", async () => {
    const { app, store } = await harness();
    faults.syncFails = (p) => (p.includes(".dfircase.") && p.endsWith(".tmp") ? errno("EIO") : null);
    const res = await request(app)
      .post("/cases/INC-D/delete")
      .send({ archiveFirst: "encrypted", password: "correct horse battery staple" });
    expect(res.status).toBe(500);
    expect(await store.caseExists("INC-D")).toBe(true);
    expect((await readdir(store.casesRoot)).filter((f) => f.endsWith(".dfircase"))).toEqual([]);
  });

  it("ZIP delete: a failed fsync answers an error and deletes nothing", async () => {
    const { app, store } = await harness();
    faults.syncFails = (p) => (p.includes(".zip.") && p.endsWith(".tmp") ? errno("EIO") : null);
    const res = await request(app).post("/cases/INC-D/delete").send({ archiveFirst: "zip" });
    expect(res.status).toBe(500);
    expect(await store.caseExists("INC-D")).toBe(true);
    expect((await readdir(store.casesRoot)).filter((f) => f.endsWith(".zip"))).toEqual([]);
  });
});
