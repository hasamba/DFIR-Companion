import { describe, it, expect, vi, beforeEach } from "vitest";
import { mkdir, mkdtemp, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";

// #2767: two decisions on one held file, or a failed move, must never leave a zero-byte reservation.
// Synthetic values only.

const fsState = vi.hoisted(() => ({ failNextRename: false }));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    rename: async (from: string, to: string) => {
      if (fsState.failNextRename) {
        fsState.failNextRename = false;
        throw Object.assign(new Error(`ENOENT: no such file or directory, rename '${from}'`), {
          code: "ENOENT",
        });
      }
      return actual.rename(from, to);
    },
  };
});

const { decideHeldFile, moveWithinDrop } = await import("../../src/analysis/dropHeldFiles.js");
const { HuntHeldStore } = await import("../../src/analysis/huntHeldStore.js");

const BODY = '{"rows":[1,2,3]}';

async function setup() {
  const root = await mkdtemp(join(tmpdir(), "dfir-heldfiles-"));
  const drop = join(root, "drop");
  const state = join(root, "state");
  await mkdir(join(drop, "_held"), { recursive: true });
  await mkdir(state, { recursive: true });
  await writeFile(join(drop, "_held", "a.json"), BODY);
  return { drop, store: new HuntHeldStore(() => state) };
}

async function walk(dir: string, base = dir): Promise<{ rel: string; size: number }[]> {
  const out: { rel: string; size: number }[] = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(full, base)));
    else out.push({ rel: relative(base, full).replace(/\\/g, "/"), size: (await stat(full)).size });
  }
  return out;
}

beforeEach(() => {
  fsState.failNextRename = false;
});

describe("held-file moves leave no reservation behind (#2767)", () => {
  it("a failed rename removes the name it reserved and rethrows", async () => {
    const { drop } = await setup();
    fsState.failNextRename = true;
    await expect(moveWithinDrop(drop, "_held/a.json", "_skipped/a.json")).rejects.toThrow();
    const files = await walk(drop);
    expect(files).toEqual([{ rel: "_held/a.json", size: BODY.length }]);
  });

  for (const decisions of [
    ["skip", "import"],
    ["import", "skip"],
    ["skip", "skip"],
    ["import", "import"],
    ["skip", "import", "import"],
  ] as const) {
    it(`concurrent ${decisions.join(" + ")}: one wins, the rest get a clean refusal, no empty files`, async () => {
      const { drop, store } = await setup();
      const results = await Promise.all(
        decisions.map((d) => decideHeldFile(store, "c1", drop, "_held/a.json", d)),
      );
      const winners = results.filter((r) => r.to);
      expect(winners).toHaveLength(1);
      for (const loser of results.filter((r) => !r.to)) {
        expect(loser.error).toMatch(/already/);
        expect(loser.error).not.toContain(drop);
      }
      const files = await walk(drop);
      expect(files.filter((f) => f.size === 0)).toEqual([]);
      expect(files).toHaveLength(1);
      expect(files[0].rel).toBe(winners[0].to);
      expect(await readFile(join(drop, ...winners[0].to!.split("/")), "utf8")).toBe(BODY);
    });
  }

  it("a decision on a held file that was already moved gets the same clean refusal", async () => {
    const { drop, store } = await setup();
    const first = await decideHeldFile(store, "c1", drop, "_held/a.json", "skip");
    expect(first.to).toBe("_skipped/a.json");
    const second = await decideHeldFile(store, "c1", drop, "_held/a.json", "import");
    expect(second.to).toBeUndefined();
    expect(second.error).toMatch(/already/);
    expect((await walk(drop)).map((f) => f.rel)).toEqual(["_skipped/a.json"]);
  });
});
