import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { atomicWrite, atomicWriteRetries } from "../../src/storage/atomicWrite.js";

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

  it("reports the retry count via onRetry only when a retry was needed", async () => {
    let calls = 0;
    const rename = vi.fn(async () => { if (++calls < 3) throw eperm(); });   // fails twice, then OK
    const onRetry = vi.fn();

    await atomicWrite("/case/investigation.json", "{}", { writeFile: async () => {}, rename, sleep: async () => {}, onRetry });

    expect(onRetry).toHaveBeenCalledTimes(1);
    expect(onRetry).toHaveBeenCalledWith(2);   // succeeded on the 3rd attempt → 2 retries
  });

  it("does not call onRetry on a clean first-try success", async () => {
    const onRetry = vi.fn();
    await atomicWrite("/x", "{}", { writeFile: async () => {}, rename: async () => {}, sleep: async () => {}, onRetry });
    expect(onRetry).not.toHaveBeenCalled();
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

describe("atomicWriteRetries", () => {
  const ORIGINAL = process.env.DFIR_ATOMIC_WRITE_RETRIES;
  afterEach(() => {
    if (ORIGINAL === undefined) delete process.env.DFIR_ATOMIC_WRITE_RETRIES;
    else process.env.DFIR_ATOMIC_WRITE_RETRIES = ORIGINAL;
  });

  it("defaults to 20 when unset", () => {
    delete process.env.DFIR_ATOMIC_WRITE_RETRIES;
    expect(atomicWriteRetries()).toBe(20);
  });

  it("honors a positive override", () => {
    process.env.DFIR_ATOMIC_WRITE_RETRIES = "50";
    expect(atomicWriteRetries()).toBe(50);
  });

  it("floors a fractional override", () => {
    process.env.DFIR_ATOMIC_WRITE_RETRIES = "12.9";
    expect(atomicWriteRetries()).toBe(12);
  });

  it("falls back to 20 for 0, negative, or unparseable values", () => {
    for (const v of ["0", "-5", "lots"]) {
      process.env.DFIR_ATOMIC_WRITE_RETRIES = v;
      expect(atomicWriteRetries()).toBe(20);
    }
  });
});
