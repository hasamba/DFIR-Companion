import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { writeHeldText } from "../../src/composition/dropHeld.js";

// #2764: a temp file left by a crashed save must not make the next held-text save fail.
// Synthetic data only.

const REL = "_held/WS-ALPHA-C.0000000000000001/results/Windows.System.Pslist.json";
const HELD_DIR = "_held/WS-ALPHA-C.0000000000000001/results";
const NAME = "Windows.System.Pslist.json";

let root: string;
let dropDir: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "drop-held-text-"));
  dropDir = join(root, "drop");
  await mkdir(join(dropDir, ...HELD_DIR.split("/")), { recursive: true });
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const tempsIn = async (dir: string): Promise<string[]> =>
  (await readdir(dir)).filter((n) => n.endsWith(".tmp"));

describe("writeHeldText (#2764)", () => {
  it("saves despite a stale temp file a crashed run left under the same process id", async () => {
    const dir = join(dropDir, ...HELD_DIR.split("/"));
    const stale = join(dir, `.${NAME}.${process.pid}.tmp`);
    await writeFile(stale, "half-written leftover");

    await expect(writeHeldText(dropDir, REL, '{"a":1}\n')).resolves.toBeUndefined();

    expect(await readFile(join(dir, NAME), "utf8")).toBe('{"a":1}\n');
    expect(await readFile(stale, "utf8")).toBe("half-written leftover");
  });

  it("leaves no temp file after a successful save, and replaces an earlier version", async () => {
    const dir = join(dropDir, ...HELD_DIR.split("/"));
    await writeHeldText(dropDir, REL, "first\n");
    await writeHeldText(dropDir, REL, "second\n");
    expect(await readFile(join(dir, NAME), "utf8")).toBe("second\n");
    expect(await tempsIn(dir)).toEqual([]);
  });

  it("removes its own temp file when the save fails", async () => {
    const dir = join(dropDir, ...HELD_DIR.split("/"));
    await mkdir(join(dir, NAME, "blocker"), { recursive: true }); // rename onto a non-empty folder fails
    await expect(writeHeldText(dropDir, REL, "x\n")).rejects.toThrow();
    expect(await tempsIn(dir)).toEqual([]);
  });

  it("still refuses a path outside drop/_held/", async () => {
    await expect(writeHeldText(dropDir, "../escape.json", "x")).rejects.toThrow("unsafe held path");
    await expect(writeHeldText(dropDir, "results/x.json", "x")).rejects.toThrow("unsafe held path");
  });
});
