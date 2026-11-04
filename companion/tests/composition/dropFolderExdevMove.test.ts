import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, access, appendFile, symlink, open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { createDropFolder, dropDirOf } from "../../src/composition/dropFolder.js";

// #2270. When drop/<relpath> and drop/_processed|_failed/<relpath> sit on different filesystems,
// rename() fails with EXDEV and the move falls back to a copy. That copy used to buffer the whole
// file with FileHandle.readFile(), with no cap. It now streams from the verified descriptor and is
// bounded by the size fstat reported when the move started: a file that grew is refused and left
// in place. It is deliberately NOT capped by DFIR_DROP_MAX_BYTES — oversize files are failed into
// _failed/ and tool-handled raw inputs are size-independent, and both still have to move.

const hooks = vi.hoisted(() => ({
  exdev: false,
  beforeExdev: null as null | ((src: string) => Promise<void>),
}));
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    rename: (async (...args: Parameters<typeof actual.rename>) => {
      if (!hooks.exdev) return actual.rename(...args);
      if (hooks.beforeExdev) await hooks.beforeExdev(String(args[0]));
      throw Object.assign(new Error("cross-device link not permitted"), { code: "EXDEV" });
    }) as typeof actual.rename,
  };
});

afterEach(() => {
  hooks.exdev = false;
  hooks.beforeExdev = null;
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

function harness(store: CaseStore) {
  const refuse = (): never => {
    throw new Error("not expected to be called by moveDropFile");
  };
  return createDropFolder({
    store,
    options: {},
    hasAiProvider: () => false,
    getControl: refuse,
    recordImportFailure: refuse,
    dispatchNotify: refuse,
    resolveImportKind: refuse,
    ingestStreamed: refuse,
    ingestMacLoginItemBinary: refuse,
    liveToolConfigs: () => new Map(),
    resolveToolForExt: () => null,
    rawExtClaimed: () => false,
    runDropToolAndIngest: refuse,
    indexCaptureText: refuse,
    captureBuffers: new Map(),
    flush: refuse,
  });
}

async function seed(content: Buffer) {
  const store = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-drop-exdev-")));
  await store.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  const dropDir = dropDirOf(store, "c1");
  await mkdir(join(dropDir, "triage"), { recursive: true });
  const relpath = join("triage", "evidence.bin");
  await writeFile(join(dropDir, relpath), content);
  return { store, dropDir, relpath, src: join(dropDir, relpath) };
}

describe("moveDropFile across filesystems (EXDEV fallback, #2270)", () => {
  it("copies the file into _processed/ with identical bytes and removes the source", async () => {
    const data = Buffer.from("evidence ".repeat(4096));
    const { store, dropDir, relpath, src } = await seed(data);
    hooks.exdev = true;

    await harness(store).moveDropFile(dropDir, relpath, true);

    expect((await readFile(join(dropDir, "_processed", relpath))).equals(data)).toBe(true);
    await expect(access(src)).rejects.toThrow();
  });

  it("never buffers the whole file with FileHandle.readFile()", async () => {
    const { store, dropDir, relpath, src } = await seed(Buffer.from("bytes"));
    const probe = await open(src, "r");
    const proto = Object.getPrototypeOf(probe) as { readFile: (...a: unknown[]) => unknown };
    await probe.close();
    const spy = vi.spyOn(proto, "readFile");
    hooks.exdev = true;

    await harness(store).moveDropFile(dropDir, relpath, true);

    expect(spy).not.toHaveBeenCalled();
  });

  it("still moves a file larger than DFIR_DROP_MAX_BYTES into _failed/", async () => {
    vi.stubEnv("DFIR_DROP_MAX_BYTES", "16");
    const data = Buffer.from("x".repeat(4096));
    const { store, dropDir, relpath, src } = await seed(data);
    hooks.exdev = true;

    await harness(store).moveDropFile(dropDir, relpath, false);

    expect((await readFile(join(dropDir, "_failed", relpath))).equals(data)).toBe(true);
    await expect(access(src)).rejects.toThrow();
  });

  it("refuses a file that grew after the move started, and leaves it in place", async () => {
    const data = Buffer.from("original ".repeat(100));
    const { store, dropDir, relpath, src } = await seed(data);
    const growth = Buffer.from("APPENDED-BY-A-CO-WRITER".repeat(100));
    hooks.exdev = true;
    hooks.beforeExdev = (path) => appendFile(path, growth);

    await expect(harness(store).moveDropFile(dropDir, relpath, true)).rejects.toThrow(
      /changed size while being moved across filesystems/,
    );

    expect((await readFile(src)).equals(Buffer.concat([data, growth]))).toBe(true);
    await expect(access(join(dropDir, "_processed", relpath))).rejects.toThrow();
  });

  it("still refuses a symlink source, and copies nothing from its target", async () => {
    const { store, dropDir } = await seed(Buffer.from("unused"));
    const target = join(dropDir, "..", "host-secret.txt");
    await writeFile(target, "HOST-SECRET");
    const relpath = join("triage", "link.txt");
    await symlink(target, join(dropDir, relpath));
    hooks.exdev = true;

    await expect(harness(store).moveDropFile(dropDir, relpath, true)).rejects.toThrow(
      /symlink detected .* refused to move \(security\)/,
    );
    await expect(access(join(dropDir, "_processed", relpath))).rejects.toThrow();
  });
});
