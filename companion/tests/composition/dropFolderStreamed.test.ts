import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { CaseStore } from "../../src/storage/caseStore.js";
import { DropStatusStore } from "../../src/analysis/dropStatus.js";
import { createDropFolder, dropDirOf, type DropFolderDeps } from "../../src/composition/dropFolder.js";

// #2336 — the drop folder reads a cloud audit export or a Plaso super-timeline the way Import-from-
// path does: a gzip head is detected and decompressed on read, and a file over DFIR_DROP_MAX_BYTES
// streams from disk instead of being refused. A gzip of any other kind is refused with the same
// sentence the routes give. The cap is lowered here so "over the cap" needs only a few KB.

const CAP_BYTES = 2048;
const savedCap = process.env.DFIR_DROP_MAX_BYTES;
beforeAll(() => {
  process.env.DFIR_DROP_MAX_BYTES = String(CAP_BYTES);
});
afterAll(() => {
  if (savedCap === undefined) delete process.env.DFIR_DROP_MAX_BYTES;
  else process.env.DFIR_DROP_MAX_BYTES = savedCap;
});

const record = (i: number) => ({
  eventVersion: "1.09",
  userIdentity: { type: "IAMUser", arn: `arn:aws:iam::123456789012:user/ops${i}`, userName: `ops${i}` },
  eventTime: "2026-10-01T10:00:00Z",
  eventSource: "iam.amazonaws.com",
  eventName: "ListUsers",
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  eventID: `00000000-0000-4000-b000-${String(i).padStart(12, "0")}`,
});
const cloudTrail = (n: number): string =>
  JSON.stringify({ Records: Array.from({ length: n }, (_, i) => record(i)) });
const PLASO_HEADER = "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n";
const plaso = (n: number): string =>
  PLASO_HEADER +
  Array.from(
    { length: n },
    (_, i) =>
      `2026-05-02T10:00:${String(i % 60).padStart(2, "0")}+00:00,Mtime,FILE,NTFS,C:\\f${i}.txt,mft,OS:x,\n`,
  ).join("");

/** A detector stand-in that only knows the three shapes these tests drop. */
function resolveImportKind(_name: string, text: string): string {
  if (text.startsWith('{"Records"')) return "aws";
  if (text.startsWith("datetime,timestamp_desc")) return "plaso";
  if (/sshd\[/.test(text)) return "syslog";
  return "unknown";
}

interface DiskCall {
  kind: string;
  name: string;
  bytes: Buffer;
}

function harness(store: CaseStore, dropStatusStore: DropStatusStore) {
  const refuse = (): never => {
    throw new Error("not expected to be reached");
  };
  const calls: DiskCall[] = [];
  const ingestDiskFile: DropFolderDeps["ingestDiskFile"] = vi.fn(
    async (_caseId: string, kind: string, handle: FileHandle, name: string) => {
      // Read through the very handle the sweep opened (no-follow), as the stored copy would.
      const { size } = await handle.stat();
      const buf = Buffer.alloc(size);
      await handle.read(buf, 0, size, 0);
      calls.push({ kind, name, bytes: buf });
      return { storedName: `0001_${name}`, addedEvents: 1, addedIocs: 0, disclosure: ["Read by streaming."] };
    },
  );
  const drops = createDropFolder({
    store,
    options: { dropStatusStore },
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: () => {},
    dispatchNotify: () => {},
    resolveImportKind,
    ingestStreamed: vi.fn(async () => ({ storedName: "x", addedEvents: 0, addedIocs: 0, analyzed: true })),
    ingestDiskFile,
    ingestMacLoginItemBinary: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
  return { drops, calls, ingestDiskFile };
}

async function seed(name: string, body: Buffer | string) {
  const root = await mkdtemp(join(tmpdir(), "dfir-drop-streamed-"));
  const store = new CaseStore(root);
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(dropDir, { recursive: true });
  await writeFile(join(dropDir, name), body);
  const dropStatusStore = new DropStatusStore(store);
  return { store, dropDir, dropStatusStore, ...harness(store, dropStatusStore) };
}

async function sweepTwice(s: Awaited<ReturnType<typeof seed>>) {
  await s.drops.scanCaseDrops("c1");
  await s.drops.scanCaseDrops("c1");
  return s.dropStatusStore.load("c1");
}

describe("drop folder streams cloud and Plaso files, and reads gzip (#2336)", () => {
  it("streams a cloud export over the drop cap instead of refusing it", async () => {
    const body = cloudTrail(40);
    expect(body.length).toBeGreaterThan(CAP_BYTES);
    const s = await seed("ct.json", body);
    const status = await sweepTwice(s);
    expect(status.failed).toEqual([]);
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]).toMatchObject({ kind: "aws", name: "ct.json" });
    expect(s.calls[0].bytes.toString()).toBe(body);
    expect((await stat(join(s.dropDir, "_processed", "ct.json"))).isFile()).toBe(true);
    // The streamed import's disclosure reaches drop-log.txt.
    expect(await readFile(join(s.dropDir, "drop-log.txt"), "utf8")).toContain("Read by streaming.");
  });

  it("streams a gzip cloud export of any size, detected from its decompressed head", async () => {
    const gz = gzipSync(cloudTrail(2));
    const s = await seed("ct.json.gz", gz);
    const status = await sweepTwice(s);
    expect(status.failed).toEqual([]);
    expect(status.pendingRawInputs ?? []).toEqual([]); // not mistaken for a raw tool input
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0].kind).toBe("aws");
    expect(s.calls[0].bytes.equals(gz)).toBe(true); // the stored copy is the gzip as dropped
  });

  it("refuses a gzip of a kind that does not stream, with the routes' sentence", async () => {
    const gz = gzipSync("Oct  1 10:00:00 host sshd[1]: Accepted password for root\n".repeat(20));
    const s = await seed("auth.log.gz", gz);
    const status = await sweepTwice(s);
    expect(s.calls).toHaveLength(0);
    expect(status.failed).toHaveLength(1);
    expect(status.failed[0]?.reason).toMatch(/gzip uploads are read only for cloud audit exports/);
    expect((await stat(join(s.dropDir, "_failed", "auth.log.gz"))).isFile()).toBe(true);
  });

  it("streams a Plaso super-timeline over the drop cap instead of refusing it", async () => {
    const body = plaso(60);
    expect(body.length).toBeGreaterThan(CAP_BYTES);
    const s = await seed("supertimeline.csv", body);
    const status = await sweepTwice(s);
    expect(status.failed).toEqual([]);
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0].kind).toBe("plaso");
  });

  it("still refuses an oversize file of a kind that does not stream", async () => {
    const body = "Oct  1 10:00:00 host sshd[1]: Accepted password for root\n".repeat(80);
    const s = await seed("auth.log", body);
    const status = await sweepTwice(s);
    expect(s.calls).toHaveLength(0);
    expect(status.failed[0]?.reason).toMatch(/too large/);
  });

  it("keeps a small cloud file on the whole-file path", async () => {
    const s = await seed("ct.json", cloudTrail(1));
    await sweepTwice(s);
    expect(s.calls).toHaveLength(0);
  });
});
