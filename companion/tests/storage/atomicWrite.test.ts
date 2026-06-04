import { describe, it, expect, vi } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { atomicWrite } from "../../src/storage/atomicWrite.js";

function eperm(): NodeJS.ErrnoException {
  const e = new Error("EPERM: operation not permitted, rename") as NodeJS.ErrnoException;
  e.code = "EPERM";
  return e;
}

describe("atomicWrite", () => {
  it("writes content atomically (real fs round-trip)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dfir-atomic-"));
    const target = join(dir, "x.json");
    await atomicWrite(target, '{"a":1}');
    expect(await readFile(target, "utf8")).toBe('{"a":1}');
  });

  it("retries the rename through a transient EPERM lock and succeeds", async () => {
    const writeFile = vi.fn(async () => {});
    let calls = 0;
    const rename = vi.fn(async () => { if (++calls < 3) throw eperm(); });   // fails twice, then OK
    const sleep = vi.fn(async () => {});

    await atomicWrite("/case/investigation.json", "{}", { writeFile, rename, sleep });

    expect(rename).toHaveBeenCalledTimes(3);   // retried until it worked
    expect(sleep).toHaveBeenCalledTimes(2);    // backed off between the failures
  });

  it("rethrows a non-transient error immediately (no retries)", async () => {
    const rename = vi.fn(async () => { const e = new Error("ENOSPC") as NodeJS.ErrnoException; e.code = "ENOSPC"; throw e; });
    await expect(atomicWrite("/x", "{}", { writeFile: async () => {}, rename, sleep: async () => {} }))
      .rejects.toThrow("ENOSPC");
    expect(rename).toHaveBeenCalledTimes(1);
  });

  it("gives up and rethrows when the lock never clears", async () => {
    const rename = vi.fn(async () => { throw eperm(); });
    await expect(atomicWrite("/x", "{}", { writeFile: async () => {}, rename, sleep: async () => {}, retries: 3 }))
      .rejects.toThrow("EPERM");
    expect(rename).toHaveBeenCalledTimes(4);   // initial + 3 retries
  });
});
