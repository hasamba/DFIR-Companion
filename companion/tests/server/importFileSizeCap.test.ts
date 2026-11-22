import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, open, readdir, writeFile } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createApp, buildRuntimePipeline } from "../../src/server.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ImportMetaStore } from "../../src/analysis/importMeta.js";
import {
  importFileTooLarge,
  maxImportFileBytes,
  readImportFileBounded,
} from "../../src/routes/importFileHead.js";
import { CHANGED_WHILE_IMPORTING } from "../../src/routes/receiptedFile.js";

// #2830. While `growth.on`, the real bounded read is handed a handle whose stat is one byte short of
// what its read yields — a file appended to between the two. Off, the module is untouched.
const growth = vi.hoisted(() => ({ on: false }));
vi.mock("../../src/storage/boundedRead.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../src/storage/boundedRead.js")>();
  return {
    ...real,
    readHandleBounded: (handle: FileHandle, maxBytes: number) =>
      real.readHandleBounded(growth.on ? statOneByteShort(handle) : handle, maxBytes),
  };
});

function statOneByteShort(handle: FileHandle): FileHandle {
  return {
    stat: async () => ({ size: (await handle.stat()).size - 1 }),
    read: (buf: Buffer, offset: number, length: number, position: number) =>
      handle.read(buf, offset, length, position),
  } as unknown as FileHandle;
}

// #921, gap 2. POST /cases/:id/import-file reads a server-local path with readFile(utf8) for every
// non-Plaso kind, and the only bound was the catch for V8's "Invalid string length" at ~512 MB. A
// 400 MB file needs a 400 MB Buffer plus a string of up to twice that on the heap, so on a host with
// a modest --max-old-space-size the heap OOM lands BEFORE the string-length error ever throws — and
// a heap OOM is a process crash, not a 413. The route is the documented escape hatch the drop
// folder's oversize message points at, so it needs a cap it can STATE, not a fixed one.

// THOR JSONL: one finding per line, mapped deterministically with no AI call — and, unlike a JSON
// ARRAY, a format whose detector still classifies it from a head sample that ends mid-file. (A
// Chainsaw array over 256 KB has never been classifiable through import-file; that predates #921.)
function thorLine(i: number): string {
  return JSON.stringify({
    time: "2026-05-16T08:00:00Z",
    hostname: "WIN11",
    level: "Warning",
    module: "Filescan",
    message: `Bulk finding ${i}`,
    file: `C:\\bulk\\file-${i}.tmp`,
  });
}

/** A THOR JSONL file of at least `bytes` bytes. */
function thorOfAtLeast(bytes: number): string {
  const lines: string[] = [];
  for (let size = 0, i = 0; size < bytes; i++) {
    const line = thorLine(i);
    lines.push(line);
    size += line.length + 1;
  }
  return lines.join("\n") + "\n";
}

async function makeApp() {
  const root = await mkdtemp(join(tmpdir(), "dfir-import-file-cap-"));
  const store = new CaseStore(join(root, "cases"));
  const stateStore = new StateStore(store);
  const pipeline = buildRuntimePipeline({
    provider: undefined,
    synthesisProvider: undefined,
    stateStore,
    store,
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
  const app = createApp(store, { pipeline, stateStore, importMetaStore: new ImportMetaStore(store) });
  await request(app).post("/cases").send({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return { app, store, root };
}

const saved = process.env.DFIR_MAX_IMPORT_FILE_MB;
beforeEach(() => {
  process.env.DFIR_MAX_IMPORT_FILE_MB = "1";
});
afterEach(() => {
  growth.on = false;
  if (saved === undefined) delete process.env.DFIR_MAX_IMPORT_FILE_MB;
  else process.env.DFIR_MAX_IMPORT_FILE_MB = saved;
});

describe("POST /cases/:id/import-file — whole-file size cap (#921)", () => {
  it("refuses a non-Plaso file over the cap with a 413 that names the knob, before reading it", async () => {
    const { app, store, root } = await makeApp();
    const path = join(root, "big-thor.jsonl");
    // 1.5 MiB plus one line: over a 1 MB cap, and rounds UP to the "2 MB" the message must state.
    await writeFile(path, thorOfAtLeast(1.5 * 1024 * 1024), "utf8");

    const res = await request(app).post("/cases/c1/import-file").send({ path });

    expect(res.status, JSON.stringify(res.body)).toBe(413);
    expect(res.body.error).toMatch(/DFIR_MAX_IMPORT_FILE_MB/);
    expect(res.body.error).toMatch(/\b1 MB\b/); // the cap it was measured against
    expect(res.body.error).toMatch(/\b2 MB\b/); // and the size that exceeded it
    // Refused, not imported: no evidence copy was made.
    expect(await readdir(store.importsDir("c1")).catch(() => [])).toEqual([]);
  });

  it("still imports the same kind under the cap", async () => {
    const { app, root } = await makeApp();
    const path = join(root, "small-thor.jsonl");
    await writeFile(path, thorOfAtLeast(2048), "utf8");

    const res = await request(app).post("/cases/c1/import-file").send({ path });
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ kind: "thor" });
  });
});

describe("importFileTooLarge", () => {
  const MB = 1024 * 1024;

  it("is null under or at the cap, and for Plaso at any size", () => {
    expect(importFileTooLarge(256 * MB, "thor", 256 * MB)).toBeNull();
    expect(importFileTooLarge(10 * 1024 * MB, "plaso", 256 * MB)).toBeNull();
  });

  it("names the kind, both sizes in MB, the knob and the Plaso exemption when over", () => {
    const msg = importFileTooLarge(300 * MB, "thor", 256 * MB);
    expect(msg).toMatch(/thor/);
    expect(msg).toMatch(/300 MB/);
    expect(msg).toMatch(/256 MB/);
    expect(msg).toMatch(/DFIR_MAX_IMPORT_FILE_MB/);
    expect(msg).toMatch(/Plaso/);
  });

  it("rounds a fractional size up, so a file just over the cap never reads as equal to it", () => {
    expect(importFileTooLarge(256 * MB + 1, "csv", 256 * MB)).toMatch(/257 MB/);
  });
});

// #2815. The setting is not the only bound on a whole read: the engine cannot hold one string past
// ~512 MB, so a raised DFIR_MAX_IMPORT_FILE_MB let a 600 MB file be read whole and only then refused,
// and told the analyst to raise the setting for a file no setting can admit.
describe("importFileTooLarge — the safe whole-read limit bounds a raised setting (#2815)", () => {
  const MB = 1024 * 1024;

  it("refuses a file over the safe limit although the setting is higher, without suggesting the setting", () => {
    const msg = importFileTooLarge(600 * MB, "csv", 1024 * MB);
    expect(msg).not.toBeNull();
    expect(msg).toMatch(/600 MB/);
    expect(msg).toMatch(/448 MB/); // the limit it was really measured against, not the 1024 MB setting
    expect(msg).not.toMatch(/1024 MB/);
    expect(msg).not.toMatch(/raise DFIR_MAX_IMPORT_FILE_MB/);
    expect(msg).toMatch(/Plaso super-timelines/);
    expect(msg).toMatch(/Velociraptor JSON Lines/);
  });

  it("does not tell the analyst to raise the setting for a file between the safe limit and ~512 MB", () => {
    const msg = importFileTooLarge(480 * MB, "csv", 256 * MB);
    expect(msg).toMatch(/480 MB/);
    expect(msg).not.toMatch(/raise DFIR_MAX_IMPORT_FILE_MB/);
  });

  it("still admits a file under both the setting and the safe limit, and Plaso at any size", () => {
    expect(importFileTooLarge(400 * MB, "csv", 1024 * MB)).toBeNull();
    expect(importFileTooLarge(10 * 1024 * MB, "plaso", 1024 * MB)).toBeNull();
  });

  it("measures against an injected safe limit", () => {
    expect(importFileTooLarge(2048, "csv", MB, 1024)).toMatch(/cannot be held in memory at any setting/);
    expect(importFileTooLarge(1024, "csv", MB, 1024)).toBeNull();
  });
});

describe("readImportFileBounded — reads to the safe limit, not the raw setting (#2815)", () => {
  const MB = 1024 * 1024;

  async function handleOn(bytes: number) {
    const dir = await mkdtemp(join(tmpdir(), "dfir-import-file-ceiling-"));
    const path = join(dir, "rows.csv");
    await writeFile(path, "a".repeat(bytes), "utf8");
    return open(path, "r");
  }

  it("returns the refusal, not the text, for a file over the injected safe limit", async () => {
    const fh = await handleOn(2048);
    try {
      const read = await readImportFileBounded(fh, "csv", MB, 1024);
      expect(read.text).toBeUndefined();
      expect(read.tooLarge).toMatch(/too large to import as csv/);
      expect(read.tooLarge).not.toMatch(/raise DFIR_MAX_IMPORT_FILE_MB/);
    } finally {
      await fh.close();
    }
  });

  it("still returns the text of a file under the injected safe limit", async () => {
    const fh = await handleOn(512);
    try {
      const read = await readImportFileBounded(fh, "csv", MB, 1024);
      expect(read.tooLarge).toBeUndefined();
      expect(read.text).toHaveLength(512);
    } finally {
      await fh.close();
    }
  });
});

// #2830. The bounded read reports growth as "too large" with the promised size plus one. Under the
// ceiling that is not a size refusal, and the sentence builder returned null — which went out behind
// a non-null assertion as 413 {"error":null}.
describe("a file that grows during the whole read, under the ceiling (#2830)", () => {
  const MB = 1024 * 1024;

  it("readImportFileBounded reports the change, not a null size refusal", async () => {
    // stat says 1000 bytes; the read yields 1001.
    const growing = {
      stat: async () => ({ size: 1000 }),
      read: async (buf: Buffer, offset: number, length: number) => {
        buf.fill(0x61, offset, offset + length);
        return { bytesRead: length, buffer: buf };
      },
    } as unknown as FileHandle;

    const read = await readImportFileBounded(growing, "csv", MB);

    expect(read).toEqual({ changed: true });
  });

  it("still reports a size refusal when the growth takes the file over the ceiling", async () => {
    const growing = {
      stat: async () => ({ size: 1024 }),
      read: async (buf: Buffer, offset: number, length: number) => {
        buf.fill(0x61, offset, offset + length);
        return { bytesRead: length, buffer: buf };
      },
    } as unknown as FileHandle;

    const read = await readImportFileBounded(growing, "csv", MB, 1024);

    expect(read.tooLarge).toMatch(/too large to import as csv/);
  });

  it("the route answers 409 with the changed-while-importing sentence and keeps no copy", async () => {
    const { app, store, root } = await makeApp();
    const path = join(root, "growing-thor.jsonl");
    await writeFile(path, thorOfAtLeast(2048), "utf8");
    growth.on = true;

    const res = await request(app).post("/cases/c1/import-file").send({ path });

    expect(res.status, JSON.stringify(res.body)).toBe(409);
    expect(res.body.error).toBe(CHANGED_WHILE_IMPORTING);
    expect(await readdir(store.importsDir("c1")).catch(() => [])).toEqual([]);
  });
});

describe("maxImportFileBytes", () => {
  it("defaults to 256 MB — the same ceiling as DFIR_MAX_BODY_MB, so an operator sees one number", () => {
    expect(maxImportFileBytes({})).toBe(256 * 1024 * 1024);
  });

  it("reads DFIR_MAX_IMPORT_FILE_MB in whole megabytes and falls back on garbage or zero", () => {
    expect(maxImportFileBytes({ DFIR_MAX_IMPORT_FILE_MB: "1" })).toBe(1024 * 1024);
    expect(maxImportFileBytes({ DFIR_MAX_IMPORT_FILE_MB: "4096" })).toBe(4096 * 1024 * 1024);
    expect(maxImportFileBytes({ DFIR_MAX_IMPORT_FILE_MB: "big" })).toBe(256 * 1024 * 1024);
    expect(maxImportFileBytes({ DFIR_MAX_IMPORT_FILE_MB: "0" })).toBe(256 * 1024 * 1024);
  });

  it("falls back on a negative or infinite value — either would reject every import or disable the cap", () => {
    // Both strings pass the generic settings validation and are truthy under Number().
    expect(maxImportFileBytes({ DFIR_MAX_IMPORT_FILE_MB: "-1" })).toBe(256 * 1024 * 1024);
    expect(maxImportFileBytes({ DFIR_MAX_IMPORT_FILE_MB: "Infinity" })).toBe(256 * 1024 * 1024);
  });
});
