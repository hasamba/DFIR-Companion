import { afterEach, describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ImportLock } from "../../src/analysis/importLock.js";
import {
  ARCHIVE_INGEST_WAIT_MS,
  archiveWaitMs,
  nextArchivePollMs,
  withArchiveBarrier,
} from "../../src/routes/archiveImportBarrier.js";
import type { RouteContext } from "../../src/routes/context.js";

// #1927: the archive wait option was used unchecked (NaN made the wait endless, polled every ~1 ms),
// and the wait re-checked every 25 ms for up to 30 s. The option now falls back to the default when
// it is not a finite, non-negative number, and the re-check interval grows from 25 ms to 250 ms.

describe("archiveWaitMs (#1927)", () => {
  it.each([NaN, Infinity, -Infinity, -1, "100", undefined, null])(
    "falls back to the default for %s",
    (option) => {
      expect(archiveWaitMs(option)).toBe(ARCHIVE_INGEST_WAIT_MS);
    },
  );

  it("keeps a finite, non-negative wait, including 0 (never wait)", () => {
    expect(archiveWaitMs(0)).toBe(0);
    expect(archiveWaitMs(100)).toBe(100);
  });
});

describe("nextArchivePollMs (#1927)", () => {
  it("starts at 25 ms, doubles, and caps at 250 ms", () => {
    expect(nextArchivePollMs(0, 30_000)).toBe(25);
    expect(nextArchivePollMs(25, 30_000)).toBe(50);
    expect(nextArchivePollMs(50, 30_000)).toBe(100);
    expect(nextArchivePollMs(100, 30_000)).toBe(200);
    expect(nextArchivePollMs(200, 30_000)).toBe(250);
    expect(nextArchivePollMs(250, 30_000)).toBe(250);
  });

  it("never sleeps past the deadline, and always yields at least 1 ms", () => {
    expect(nextArchivePollMs(250, 40)).toBe(40);
    expect(nextArchivePollMs(0, 10)).toBe(10);
    expect(nextArchivePollMs(250, 0)).toBe(1);
    expect(nextArchivePollMs(250, -5)).toBe(1);
  });
});

describe("withArchiveBarrier with a bad wait option (#1927)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function fakeRes() {
    const res = { statusCode: 200, body: undefined as unknown };
    const api = {
      status(code: number) {
        res.statusCode = code;
        return api;
      },
      json(body: unknown) {
        res.body = body;
        return api;
      },
    };
    return { res, api: api as unknown as Response };
  }

  it("a NaN wait still answers 409 at the default deadline while the section stays held", async () => {
    const root = await mkdtemp(join(tmpdir(), "dfir-archive-wait-"));
    const lock = new ImportLock();
    const release = await lock.acquire("c1");
    vi.useFakeTimers();
    const ctx = {
      store: { casesRoot: root },
      importLock: lock,
      options: { archiveIngestWaitMs: NaN },
    } as unknown as RouteContext;
    const handler = vi.fn(async () => undefined);
    const { res, api } = fakeRes();
    let settled = false;
    const done = withArchiveBarrier(ctx, handler)({ params: { id: "c1" } } as unknown as Request, api).then(
      () => (settled = true),
    );
    await vi.advanceTimersByTimeAsync(ARCHIVE_INGEST_WAIT_MS - 1_000);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(2_000);
    await done;
    expect(res.statusCode).toBe(409);
    expect(handler).not.toHaveBeenCalled();
    release();
  });
});
