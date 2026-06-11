import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import {
  ingestCapture,
  _resetDedupCache,
  resolveDedupThreshold,
  DEFAULT_DUP_THRESHOLD,
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
    expect(meta.perceptualHash).toMatch(/^[0-9a-f]{128}$/);

    const onDisk = await readFile(join(store.screenshotsDir("c1"), meta.screenshotFile));
    expect(onDisk.length).toBeGreaterThan(0);

    const log = (await readFile(store.capturesLogPath("c1"), "utf8")).trim().split("\n");
    expect(log).toHaveLength(1);
  });

  it("marks a near-identical second capture as duplicate", async () => {
    const img = await pngBase64(128, 128, 128);
    await ingestCapture(store, payload({ imageBase64: img }));
    const second = await ingestCapture(store, payload({ imageBase64: img }));
    expect(second.isDuplicate).toBe(true);
    expect(second.sequenceNumber).toBe(2);
  });

  it("never flags a duplicate when dedup is disabled (threshold null)", async () => {
    const img = await pngBase64(128, 128, 128);
    await ingestCapture(store, payload({ imageBase64: img }), null);
    const second = await ingestCapture(store, payload({ imageBase64: img }), null);
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

describe("resolveDedupThreshold", () => {
  it("defaults to DEFAULT_DUP_THRESHOLD when unset", () => {
    expect(resolveDedupThreshold({})).toBe(DEFAULT_DUP_THRESHOLD);
  });
  it("honors a custom DFIR_DEDUP_THRESHOLD", () => {
    expect(resolveDedupThreshold({ DFIR_DEDUP_THRESHOLD: "25" })).toBe(25);
    expect(resolveDedupThreshold({ DFIR_DEDUP_THRESHOLD: "0" })).toBe(0);
  });
  it("falls back to the default on an invalid threshold", () => {
    expect(resolveDedupThreshold({ DFIR_DEDUP_THRESHOLD: "abc" })).toBe(DEFAULT_DUP_THRESHOLD);
    expect(resolveDedupThreshold({ DFIR_DEDUP_THRESHOLD: "-3" })).toBe(DEFAULT_DUP_THRESHOLD);
  });
  it("returns null (disabled) when DFIR_DEDUP is off/false/no/0", () => {
    for (const v of ["off", "OFF", "false", "no", "0"]) {
      expect(resolveDedupThreshold({ DFIR_DEDUP: v })).toBeNull();
    }
  });
  it("DFIR_DEDUP=off wins over a set threshold", () => {
    expect(resolveDedupThreshold({ DFIR_DEDUP: "off", DFIR_DEDUP_THRESHOLD: "25" })).toBeNull();
  });
});
