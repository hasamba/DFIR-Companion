import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import sharp from "sharp";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { CommentsStore } from "../../src/analysis/comments.js";
import { ingestCapture, _resetDedupCache } from "../../src/ingest/captureIngest.js";
import { makeImageLoader } from "../../src/analysis/imageLoader.js";

/**
 * Every accepted capture format, end to end (#425).
 *
 * Ingest advertises PNG, JPEG, GIF and WebP, and used to store all four under a `.webp` filename.
 * The image loader then reported `image/webp` whatever the bytes were, and the evidence route
 * derived its Content-Type from that wrong extension — so for three of the four formats, the
 * filename, the media type sent to the AI provider, and the response header all described the
 * evidence incorrectly.
 *
 * The four things that must agree, per format: the saved bytes, the filename extension, the AI
 * media type, and the evidence response header.
 */
const FORMATS = [
  { format: "png" as const, ext: ".png", mime: "image/png" },
  { format: "jpeg" as const, ext: ".jpg", mime: "image/jpeg" },
  { format: "gif" as const, ext: ".gif", mime: "image/gif" },
  { format: "webp" as const, ext: ".webp", mime: "image/webp" },
];

let store: CaseStore;
let app: ReturnType<typeof createApp>;

beforeEach(async () => {
  _resetDedupCache();
  const root = await mkdtemp(join(tmpdir(), "dfir-capfmt-"));
  store = new CaseStore(root);
  app = createApp(store, { stateStore: new StateStore(store), commentsStore: new CommentsStore(store) });
  await store.createCase({ caseId: "c1", name: "Case", investigator: "alice", aiProvider: null });
});

async function encode(format: (typeof FORMATS)[number]["format"]): Promise<Buffer> {
  return sharp({ create: { width: 24, height: 24, channels: 3, background: "#3366aa" } })
    .toFormat(format)
    .toBuffer();
}

describe.each(FORMATS)("capture ingest — $format", ({ format, ext, mime }) => {
  it("stores the bytes verbatim under a filename that names the real format", async () => {
    const bytes = await encode(format);
    const meta = await ingestCapture(store, {
      caseId: "c1",
      timestamp: "2026-05-28T10:00:00.000Z",
      url: "https://example.test/x",
      tabTitle: "Evidence",
      triggerType: "timer",
      imageBase64: bytes.toString("base64"),
    });

    expect(meta.screenshotFile.endsWith(ext)).toBe(true);
    const onDisk = await readFile(join(store.screenshotsDir("c1"), meta.screenshotFile));
    // Verbatim: the fix preserves the source format rather than transcoding, so the content hash
    // covers the bytes the analyst's browser actually sent.
    expect(onDisk.equals(bytes)).toBe(true);
  });

  it("hands the AI provider the matching media type", async () => {
    const bytes = await encode(format);
    const meta = await ingestCapture(store, {
      caseId: "c1",
      timestamp: "2026-05-28T10:00:00.000Z",
      url: "https://example.test/x",
      tabTitle: "Evidence",
      triggerType: "timer",
      imageBase64: bytes.toString("base64"),
    });

    const loaded = await makeImageLoader(store)("c1", meta.screenshotFile);
    expect(loaded.mimeType).toBe(mime);
    expect(Buffer.from(loaded.base64, "base64").equals(bytes)).toBe(true);
  });

  it("serves the evidence with the matching Content-Type", async () => {
    const bytes = await encode(format);
    const meta = await ingestCapture(store, {
      caseId: "c1",
      timestamp: "2026-05-28T10:00:00.000Z",
      url: "https://example.test/x",
      tabTitle: "Evidence",
      triggerType: "timer",
      imageBase64: bytes.toString("base64"),
    });

    const res = await request(app).get(`/cases/c1/evidence/${meta.screenshotFile}`);
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain(mime);
  });
});

describe("screenshots already on disk under the old fixed .webp suffix", () => {
  it("are described by their bytes, not by the misleading name", async () => {
    // No migration ships with the fix, so the loader and the evidence route have to cope with the
    // files the old code wrote: PNG bytes in a .webp filename.
    const bytes = await encode("png");
    await store.saveScreenshot("c1", "000001_legacy.webp", bytes);

    expect((await makeImageLoader(store)("c1", "000001_legacy.webp")).mimeType).toBe("image/png");
    const res = await request(app).get("/cases/c1/evidence/000001_legacy.webp");
    expect(res.headers["content-type"]).toContain("image/png");
  });

  it("does not re-type a non-image evidence file by its content", async () => {
    // The sniff covers four image magic numbers only — an imported CSV stays text/plain.
    await store.saveImport("c1", "hits.csv", "a,b\n1,2\n");
    const res = await request(app).get("/cases/c1/evidence/hits.csv");
    expect(res.headers["content-type"]).toContain("text/plain");
  });
});
