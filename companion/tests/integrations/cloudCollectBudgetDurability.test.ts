import { describe, it, expect } from "vitest";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createCollection, runCollection } from "../../src/integrations/cloudCollect/collectEngine.js";
import { QueryUsageStore } from "../../src/integrations/cloudCollect/collectBudget.js";
import { nodeCollectFs, type CollectFs } from "../../src/integrations/cloudCollect/collectFs.js";
import { faultFs, pipelineImporter, tempCase } from "../helpers/cloudCollectFakes.js";
import { denseSession, denseSource, fakeClock } from "../helpers/cloudCollectDense.js";

// #2312 review: a reservation is reported only once it is durable (temp file fsynced, renamed, the
// folder fsynced), and an unreadable quota record FAILS CLOSED — never a silent fresh count.

const SCOPE = "microsoft:00000000-0000-4000-a000-000000000003";
const errno = (code: string) => () => Object.assign(new Error(code), { code });

async function usageFile(): Promise<string> {
  return join(await mkdtemp(join(tmpdir(), "dfir-quota-dur-")), "cloud-quota", "query-usage.json");
}

/** The real fs, recording every call in order. */
function recordingFs(log: string[]): CollectFs {
  const wrap =
    <A extends unknown[], R>(op: string, fn: (...a: A) => Promise<R>) =>
    async (...a: A): Promise<R> => {
      const out = await fn(...a);
      log.push(`${op} ${String(a[0]).split(/[\\/]/).pop()}`);
      return out;
    };
  return {
    ...nodeCollectFs,
    writeFileSync: wrap("write", nodeCollectFs.writeFileSync),
    rename: wrap("rename", nodeCollectFs.rename),
    fsyncDir: wrap("fsyncDir", nodeCollectFs.fsyncDir),
  };
}

describe("quota record durability (#2312 review)", () => {
  it("reserve resolves only after write+fsync of the temp file, rename, and the folder fsync", async () => {
    const file = await usageFile();
    const log: string[] = [];
    const store = new QueryUsageStore(file, { fs: recordingFs(log) });
    expect(await store.tryReserve(SCOPE, 1, 5)).toEqual({ ok: true, used: 1 });
    expect(log).toEqual([
      "write query-usage.json.tmp",
      "rename query-usage.json.tmp",
      "fsyncDir cloud-quota",
    ]);
  });

  it("a folder fsync the platform cannot do is not a failure; any other fsync error is", async () => {
    for (const code of ["EPERM", "EISDIR", "EINVAL", "ENOTSUP", "EBADF"]) {
      const fs = faultFs();
      fs.inject("fsyncDir", (p) => p.endsWith("cloud-quota"), errno(code));
      expect((await new QueryUsageStore(await usageFile(), { fs }).tryReserve(SCOPE, 1, 5)).ok).toBe(true);
    }
    const fs = faultFs();
    const file = await usageFile();
    fs.inject("fsyncDir", (p) => p.endsWith("cloud-quota"), errno("EIO"));
    await expect(new QueryUsageStore(file, { fs }).tryReserve(SCOPE, 1, 5)).rejects.toThrow(
      /quota record could not be saved at .*query-usage\.json/,
    );
  });

  it("a failed temp write reports no reservation, and the collection stops before sending", async () => {
    const fs = faultFs();
    fs.inject("writeFileSync", (p) => p.endsWith("query-usage.json.tmp"), errno("ENOSPC"));
    const file = await usageFile();
    const store = new QueryUsageStore(file, { fs });
    const t = await tempCase();
    const session = denseSession({ records: [], cap: 10 });
    await createCollection(
      faultFs(),
      session,
      {
        dir: t.dir,
        collectionId: "cc-test-abc123",
        caseId: "c1",
        accountId: "a",
        accountName: "lab",
        provider: "microsoft",
        sources: ["ct"],
        window: { start: "2026-10-01T10:00:00Z", end: "2026-10-01T11:00:00Z" },
        filters: {},
        companionVersion: "0",
      },
      () => "2026-10-05T00:00:00.000Z",
    );
    const cp = await runCollection(
      {
        fs: faultFs(),
        session,
        importer: pipelineImporter(t),
        sources: [denseSource({ queryCost: 1 })],
        now: () => "2026-10-05T00:00:00.000Z",
        clock: fakeClock(),
        budget: store.budget(SCOPE, 5),
      },
      t.dir,
      { resume: false },
    );
    expect(session.calls).toHaveLength(0);
    expect(cp.stopReason).toMatch(/quota record could not be saved at .*query-usage\.json/);
  });

  it("an unreadable record fails closed: refused with its path, the file left as it was", async () => {
    const file = await usageFile();
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, "{not json");
    const store = new QueryUsageStore(file);
    await expect(store.tryReserve(SCOPE, 1, 5)).rejects.toThrow(
      /quota record unreadable at .*query-usage\.json — check or remove it/,
    );
    await expect(store.used(SCOPE)).rejects.toThrow(/check or remove it/);
    expect(await readFile(file, "utf8")).toBe("{not json");
    await writeFile(file, JSON.stringify({ version: 9 }));
    await expect(store.tryReserve(SCOPE, 1, 5)).rejects.toThrow(/unreadable/);
  });
});
