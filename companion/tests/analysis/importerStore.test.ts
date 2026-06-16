import { describe, it, expect } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ImporterStore } from "../../src/analysis/importerStore.js";
import { EXAMPLE_IMPORTER_SPEC } from "../../src/analysis/importerSpec.js";

async function dir() { return mkdtemp(join(tmpdir(), "dfir-imp-")); }

describe("ImporterStore", () => {
  it("loads a valid spec, skips a malformed file, and reports errors", async () => {
    const d = await dir();
    const s = new ImporterStore(d);
    await s.save(EXAMPLE_IMPORTER_SPEC as never);
    await writeFile(join(d, "broken.json"), "{ not valid json");
    const reg = await s.loadAll();
    expect(reg.importers.has("mde-advanced-hunting")).toBe(true);
    expect(reg.errors.some((e) => e.file === "broken.json")).toBe(true);
  });

  it("saves, lists, and deletes by id", async () => {
    const s = new ImporterStore(await dir());
    await s.save(EXAMPLE_IMPORTER_SPEC as never);
    expect((await s.loadAll()).meta.map((m) => m.id)).toContain("mde-advanced-hunting");
    expect(await s.delete("mde-advanced-hunting")).toBe(true);
    expect((await s.loadAll()).importers.size).toBe(0);
  });

  it("persists precedence, defaulting to builtin-first", async () => {
    const s = new ImporterStore(await dir());
    expect(await s.precedence()).toBe("builtin-first");
    await s.setPrecedence("external-first");
    expect(await s.precedence()).toBe("external-first");
  });
});
