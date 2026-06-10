import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArtifactBundleStore, BUILT_IN_BUNDLES } from "../../src/analysis/artifactBundleStore.js";

describe("ArtifactBundleStore", () => {
  let root: string;
  let store: ArtifactBundleStore;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-bundles-"));
    store = new ArtifactBundleStore(root);
  });

  describe("list()", () => {
    it("returns the built-in bundles when no custom bundles exist", async () => {
      const bundles = await store.list();
      const ids = bundles.map((b) => b.id);
      expect(ids).toContain("fast-triage");
      expect(ids).toContain("full-triage");
      expect(bundles.length).toBe(BUILT_IN_BUNDLES.length);
    });

    it("merges custom bundles after the built-ins", async () => {
      await store.save({ name: "My Triage", description: "d", artifacts: ["Windows.System.Pslist"] });
      const bundles = await store.list();
      const custom = bundles.filter((b) => !b.builtIn);
      expect(custom).toHaveLength(1);
      expect(custom[0].name).toBe("My Triage");
      expect(custom[0].artifacts).toEqual(["Windows.System.Pslist"]);
    });

    it("returns built-ins even when the bundles dir does not exist", async () => {
      const fresh = new ArtifactBundleStore(join(root, "nope"));
      expect((await fresh.list()).length).toBe(BUILT_IN_BUNDLES.length);
    });
  });

  describe("get()", () => {
    it("returns a built-in bundle by id", async () => {
      const b = await store.get("fast-triage");
      expect(b).not.toBeNull();
      expect(b!.builtIn).toBe(true);
      expect(b!.artifacts.length).toBeGreaterThan(0);
    });

    it("returns null for an unknown id", async () => {
      expect(await store.get("nope")).toBeNull();
    });
  });

  describe("save()", () => {
    it("assigns a uuid, marks builtIn false, and trims artifact names", async () => {
      const b = await store.save({ name: "A", description: "", artifacts: [" Windows.System.Pslist ", ""] });
      expect(b.id).toBeTruthy();
      expect(b.builtIn).toBe(false);
      expect(b.artifacts).toEqual(["Windows.System.Pslist"]);
    });

    it("persists so a new store instance can read it", async () => {
      await store.save({ id: "persistent", name: "P", description: "d", artifacts: ["Generic.System.Pstree"] });
      const store2 = new ArtifactBundleStore(root);
      expect((await store2.get("persistent"))?.name).toBe("P");
    });

    it("saving with a built-in id stores an editable override (builtIn stays, customized flagged)", async () => {
      const saved = await store.save({ id: "fast-triage", name: "Fast Triage (mine)", description: "edited", artifacts: ["Windows.System.Pslist"] });
      expect(saved.builtIn).toBe(true);
      expect(saved.customized).toBe(true);
      const got = await store.get("fast-triage");
      expect(got?.name).toBe("Fast Triage (mine)");
      expect(got?.builtIn).toBe(true);
      expect(got?.customized).toBe(true);
      const inList = (await store.list()).find((b) => b.id === "fast-triage");
      expect(inList?.name).toBe("Fast Triage (mine)");
      expect(inList?.customized).toBe(true);
    });
  });

  describe("delete()", () => {
    it("deletes a custom bundle", async () => {
      const b = await store.save({ name: "Del", description: "", artifacts: ["Windows.System.Pslist"] });
      expect(await store.delete(b.id)).toBe(true);
      expect(await store.get(b.id)).toBeNull();
    });

    it("returns false when the custom bundle does not exist", async () => {
      expect(await store.delete("no-such")).toBe(false);
    });

    it("editing a built-in then deleting resets it to the shipped default", async () => {
      const def = BUILT_IN_BUNDLES.find((b) => b.id === "full-triage")!;
      await store.save({ id: "full-triage", name: "My Full", description: "x", artifacts: ["Windows.System.Pslist"] });
      expect((await store.get("full-triage"))?.name).toBe("My Full");
      expect(await store.delete("full-triage")).toBe(true);   // removes the override
      const reset = await store.get("full-triage");
      expect(reset?.name).toBe(def.name);
      expect(reset?.customized).toBe(false);
    });

    it("returns false for a pristine built-in (nothing to reset)", async () => {
      expect(await store.delete("fast-triage")).toBe(false);
      expect(store.isBuiltIn("fast-triage")).toBe(true);
      expect(store.isBuiltIn("not-a-builtin")).toBe(false);
    });
  });

  it("every built-in bundle has a name, description, and at least one artifact", () => {
    for (const b of BUILT_IN_BUNDLES) {
      expect(b.name).toBeTruthy();
      expect(b.description).toBeTruthy();
      expect(b.artifacts.length).toBeGreaterThan(0);
    }
  });
});
