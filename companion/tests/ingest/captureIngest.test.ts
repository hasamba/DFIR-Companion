import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  ingestCapture,
  _resetDedupCache,
  isDedupEnabled,
} from "../../src/ingest/captureIngest.js";

let root: string;
let store: CaseStore;

async function pngBase64(r: number, g: number, b: number): Promise<string> {
  const buf = await sharp({
    create: { width: 32, height: 32, channels: 3, background: { r, g, b } },
  }).png().toBuffer();
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

  it("never flags a duplicate when dedup is disabled", async () => {
    const img = await pngBase64(128, 128, 128);
    await ingestCapture(store, payload({ imageBase64: img }), false);
    const second = await ingestCapture(store, payload({ imageBase64: img }), false);
    expect(second.isDuplicate).toBe(false);
  });

  it("includes the slugified tab title in the screenshot filename", async () => {
    const img = await pngBase64(10, 20, 30);
    const meta = await ingestCapture(
      store,
      payload({ imageBase64: img, tabTitle: "Velociraptor — Hunts" }),
    );
    expect(meta.screenshotFile).toMatch(/^000001_.*_Velociraptor-Hunts\.webp$/);
    const onDisk = await readFile(join(store.screenshotsDir("c1"), meta.screenshotFile));
    expect(onDisk.length).toBeGreaterThan(0);
  });

  it("falls back to seq+timestamp when the title has no safe characters", async () => {
    const img = await pngBase64(40, 50, 60);
    const meta = await ingestCapture(store, payload({ imageBase64: img, tabTitle: "💀💀" }));
    // No trailing underscore, no title segment at all.
    expect(meta.screenshotFile).toMatch(/^000001_[^_]+\.webp$/);
  });

  it("rejects an invalid payload (missing url)", async () => {
    const bad = payload({ imageBase64: await pngBase64(1, 1, 1) });
    delete (bad as Record<string, unknown>).url;
    await expect(ingestCapture(store, bad)).rejects.toThrow();
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
