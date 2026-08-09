import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  ingestCapture,
  _resetDedupCache,
  isDedupEnabled,
  InvalidImageError,
} from "../../src/ingest/captureIngest.js";

let root: string;
let store: CaseStore;

async function pngBase64(r: number, g: number, b: number): Promise<string> {
  const buf = await sharp({
    create: { width: 32, height: 32, channels: 3, background: { r, g, b } },
  })
    .png()
    .toBuffer();
  return buf.toString("base64");
}

function payload(over: Partial<Record<string, unknown>> = {}) {
  return {
    caseId: "c1",
    timestamp: "2026-05-28T10:00:00.000Z",
    url: "https://velociraptor.local/hunts",
    tabTitle: "Hunts",
    triggerType: "timer",
    imageBase64: "",
    ...over,
  };
}

beforeEach(async () => {
  _resetDedupCache();
  root = await mkdtemp(join(tmpdir(), "dfir-ingest-"));
  store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
});

describe("ingestCapture", () => {
  it("persists image + metadata and returns metadata with sequence 1", async () => {
    const img = await pngBase64(50, 60, 70);
    const meta = await ingestCapture(store, payload({ imageBase64: img }));

    expect(meta.sequenceNumber).toBe(1);
    expect(meta.isDuplicate).toBe(false);
    expect(meta.contentHash).toMatch(/^[0-9a-f]{64}$/); // SHA-256 hex

    const onDisk = await readFile(join(store.screenshotsDir("c1"), meta.screenshotFile));
    expect(onDisk.length).toBeGreaterThan(0);

    const log = (await readFile(store.capturesLogPath("c1"), "utf8")).trim().split("\n");
    expect(log).toHaveLength(1);
  });

  it("marks a BYTE-IDENTICAL second capture as duplicate", async () => {
    const img = await pngBase64(128, 128, 128);
    await ingestCapture(store, payload({ imageBase64: img }));
    const second = await ingestCapture(store, payload({ imageBase64: img }));
    expect(second.isDuplicate).toBe(true);
    expect(second.sequenceNumber).toBe(2);
  });

  it("does NOT mark a different second capture as duplicate (exact match only)", async () => {
    await ingestCapture(store, payload({ imageBase64: await pngBase64(128, 128, 128) }));
    // A different image — even slightly — is not a duplicate; it must be analyzed.
    const second = await ingestCapture(store, payload({ imageBase64: await pngBase64(128, 128, 129) }));
    expect(second.isDuplicate).toBe(false);
  });

  // The extension retries the SAME bytes after a 5xx (captureQueue classifies it as `retry` and
  // keeps the entry at the head of the queue). If the cache remembered a frame whose write blew up,
  // that retry would come back isDuplicate — and a duplicate is skipped by willAnalyze, the OCR
  // indexer and captureAnalysis alike, so the frame would be stored but never analyzed (#513).
  // Both writes matter: whichever one blows up, the frame is not on record, so the cache must not
  // claim it. Parameterised so moving the cache update between the two calls cannot pass.
  it.each(["nextSequenceNumber", "saveScreenshot", "appendCapture"] as const)(
    "does not remember a frame whose %s failed, so the retry is still analyzed",
    async (method) => {
      const img = await pngBase64(10, 20, 30);
      const real = store[method].bind(store) as (...args: unknown[]) => Promise<unknown>;
      let failNext = true;
      (store as unknown as Record<string, unknown>)[method] = async (...args: unknown[]) => {
        if (failNext) {
          failNext = false;
          throw new Error("ENOSPC: no space left on device");
        }
        return real(...args);
      };

      await expect(ingestCapture(store, payload({ imageBase64: img }))).rejects.toThrow(/ENOSPC/);

      const retried = await ingestCapture(store, payload({ imageBase64: img }));
      expect(retried.isDuplicate).toBe(false);
      const onDisk = await readFile(join(store.screenshotsDir("c1"), retried.screenshotFile));
      expect(onDisk.length).toBeGreaterThan(0);
    },
  );

  // When one of two overlapping identical captures fails, the one that DID land is the only copy on
  // disk — so it must be analyzed, not written off as a duplicate of the frame that never made it.
  it("analyzes the surviving capture when an overlapping identical one fails", async () => {
    const img = await pngBase64(5, 6, 7);
    const realSave = store.saveScreenshot.bind(store);
    let failFirst = true;
    store.saveScreenshot = async (...args: Parameters<typeof realSave>) => {
      if (failFirst) {
        failFirst = false;
        await new Promise((r) => setTimeout(r, 20)); // lose the race deliberately
        throw new Error("ENOSPC: no space left on device");
      }
      return realSave(...args);
    };

    const [doomed, landed] = await Promise.allSettled([
      ingestCapture(store, payload({ imageBase64: img })),
      ingestCapture(store, payload({ imageBase64: img })),
    ]);
    expect(doomed.status).toBe("rejected");
    expect(landed.status).toBe("fulfilled");
    // The only copy on disk: it has to be analyzed, not skipped as a duplicate of a frame that
    // never landed.
    if (landed.status === "fulfilled") expect(landed.value.isDuplicate).toBe(false);

    // And it is what the next identical frame dedupes against.
    const third = await ingestCapture(store, payload({ imageBase64: img }));
    expect(third.isDuplicate).toBe(true);
  });

  // The claim is made in the same tick as the decision, so an await cannot open a window where two
  // overlapping identical captures both read the stale hash and both come back non-duplicate.
  it("still flags the second of two overlapping identical captures", async () => {
    const img = await pngBase64(77, 88, 99);
    const [first, second] = await Promise.all([
      ingestCapture(store, payload({ imageBase64: img })),
      ingestCapture(store, payload({ imageBase64: img })),
    ]);
    expect([first.isDuplicate, second.isDuplicate].filter(Boolean)).toHaveLength(1);
  });

  it("never flags a duplicate when dedup is disabled", async () => {
    const img = await pngBase64(128, 128, 128);
    await ingestCapture(store, payload({ imageBase64: img }), false);
    const second = await ingestCapture(store, payload({ imageBase64: img }), false);
    expect(second.isDuplicate).toBe(false);
  });

  it("includes the slugified tab title in the screenshot filename", async () => {
    const img = await pngBase64(10, 20, 30);
    const meta = await ingestCapture(store, payload({ imageBase64: img, tabTitle: "Velociraptor — Hunts" }));
    // .png, not .webp: the extension follows the DETECTED format (#425), and this fixture is a PNG.
    expect(meta.screenshotFile).toMatch(/^000001_.*_Velociraptor-Hunts\.png$/);
    const onDisk = await readFile(join(store.screenshotsDir("c1"), meta.screenshotFile));
    expect(onDisk.length).toBeGreaterThan(0);
  });

  it("falls back to seq+timestamp when the title has no safe characters", async () => {
    const img = await pngBase64(40, 50, 60);
    const meta = await ingestCapture(store, payload({ imageBase64: img, tabTitle: "💀💀" }));
    // No trailing underscore, no title segment at all.
    expect(meta.screenshotFile).toMatch(/^000001_[^_]+\.png$/);
  });

  it("rejects an invalid payload (missing url)", async () => {
    const bad = payload({ imageBase64: await pngBase64(1, 1, 1) });
    delete (bad as Record<string, unknown>).url;
    await expect(ingestCapture(store, bad)).rejects.toThrow();
  });
});

describe("ingestCapture — image magic-byte validation", () => {
  const b64 = (...bytes: number[]) => Buffer.from(bytes).toString("base64");
  const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

  it("rejects arbitrary binary posing as a screenshot", async () => {
    await expect(
      ingestCapture(store, payload({ imageBase64: b64(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12) })),
    ).rejects.toBeInstanceOf(InvalidImageError);
  });

  it("rejects bytes too short to carry a signature", async () => {
    await expect(ingestCapture(store, payload({ imageBase64: b64(...PNG) }))).rejects.toBeInstanceOf(
      InvalidImageError,
    );
  });

  it("writes nothing to disk when the bytes are rejected", async () => {
    await expect(
      ingestCapture(store, payload({ imageBase64: b64(...Array(16).fill(0x41)) })),
    ).rejects.toBeInstanceOf(InvalidImageError);
    await expect(readdir(store.screenshotsDir("c1"))).resolves.toEqual([]);
  });

  it.each([
    ["PNG", [...PNG, 0, 0, 0, 13]],
    ["JPEG", [0xff, 0xd8, 0xff, 0xe0, 0, 16, 0x4a, 0x46, 0x49, 0x46, 0, 1]],
    ["GIF", [0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 1, 0, 1, 0, 0x80, 0]],
    ["WebP", [0x52, 0x49, 0x46, 0x46, 26, 0, 0, 0, 0x57, 0x45, 0x42, 0x50]],
  ])("accepts %s", async (_name, bytes) => {
    const meta = await ingestCapture(store, payload({ imageBase64: b64(...bytes) }));
    expect(meta.screenshotFile).toBeTruthy();
  });
});

describe("isDedupEnabled", () => {
  it("is enabled by default (unset)", () => {
    expect(isDedupEnabled({})).toBe(true);
  });
  it("stays enabled for any other value", () => {
    expect(isDedupEnabled({ DFIR_DEDUP: "on" })).toBe(true);
    expect(isDedupEnabled({ DFIR_DEDUP: "true" })).toBe(true);
  });
  it("is disabled when DFIR_DEDUP is off/false/no/0 (case-insensitive)", () => {
    for (const v of ["off", "OFF", "false", "No", "0"]) {
      expect(isDedupEnabled({ DFIR_DEDUP: v })).toBe(false);
    }
  });
});
