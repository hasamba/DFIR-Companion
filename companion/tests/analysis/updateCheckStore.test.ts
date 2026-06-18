// companion/tests/analysis/updateCheckStore.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { UpdateCheckStore } from "../../src/analysis/updateCheckStore.js";

let file: string;
beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-update-"));
  // Subdir that does not exist yet — persist() must create it (like KEV/NSRL).
  file = join(root, "updates", "update-check.json");
});

describe("UpdateCheckStore", () => {
  it("returns {} when the file does not exist", async () => {
    const store = new UpdateCheckStore(file);
    expect(await store.load()).toEqual({});
  });

  it("round-trips the enabled toggle", async () => {
    const store = new UpdateCheckStore(file);
    await store.setEnabled(true);
    expect((await new UpdateCheckStore(file).load()).enabled).toBe(true);
  });

  it("ignores a corrupt file that contains a JSON array", async () => {
    const { mkdir, writeFile } = await import("node:fs/promises");
    const { dirname } = await import("node:path");
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, "[1,2,3]");
    expect(await new UpdateCheckStore(file).load()).toEqual({});
  });

  it("round-trips the cached result and preserves the toggle", async () => {
    const store = new UpdateCheckStore(file);
    await store.setEnabled(true);
    await store.setResult({ latestVersion: "0.24.0", latestTag: "v0.24.0", htmlUrl: "https://x", checkedAt: 42 });
    const rec = await new UpdateCheckStore(file).load();
    expect(rec.enabled).toBe(true);
    expect(rec.result?.latestVersion).toBe("0.24.0");
    expect(rec.result?.checkedAt).toBe(42);
  });
});
