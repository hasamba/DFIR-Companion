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
      expect(ids).toContain("best-practice");
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
      const b = await store.get("best-practice");
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

    it("persists a positive relative expiry and drops a non-positive one", async () => {
      const withExpiry = await store.save({ name: "E", description: "", artifacts: ["A.B"], expirySeconds: 86_400 });
      expect(withExpiry.expirySeconds).toBe(86_400);
      const noExpiry = await store.save({ name: "E2", description: "", artifacts: ["A.B"], expirySeconds: 0 });
      expect(noExpiry.expirySeconds).toBeUndefined();
    });

    it("saving with a built-in id stores an editable override (builtIn stays, customized flagged)", async () => {
      const saved = await store.save({ id: "best-practice", name: "Best Practice (mine)", description: "edited", artifacts: ["Windows.System.Pslist"] });
      expect(saved.builtIn).toBe(true);
      expect(saved.customized).toBe(true);
      const got = await store.get("best-practice");
      expect(got?.name).toBe("Best Practice (mine)");
      expect(got?.builtIn).toBe(true);
      expect(got?.customized).toBe(true);
      const inList = (await store.list()).find((b) => b.id === "best-practice");
      expect(inList?.name).toBe("Best Practice (mine)");
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
      const def = BUILT_IN_BUNDLES.find((b) => b.id === "best-practice")!;
      await store.save({ id: "best-practice", name: "My Edit", description: "x", artifacts: ["Windows.System.Pslist"] });
      expect((await store.get("best-practice"))?.name).toBe("My Edit");
      expect(await store.delete("best-practice")).toBe(true);   // removes the override
      const reset = await store.get("best-practice");
      expect(reset?.name).toBe(def.name);
      expect(reset?.customized).toBe(false);
    });

    it("returns false for a pristine built-in (nothing to reset)", async () => {
      expect(await store.delete("best-practice")).toBe(false);
      expect(store.isBuiltIn("best-practice")).toBe(true);
      expect(store.isBuiltIn("not-a-builtin")).toBe(false);
    });
  });

  it("persists per-artifact params and ships them on the Best Practice built-in (Hayabusa RuleLevel/RuleStatus)", async () => {
    const saved = await store.save({ name: "P", description: "", artifacts: ["Windows.Hayabusa.Rules"], params: { "Windows.Hayabusa.Rules": { RuleLevel: "Critical, High, and Medium" } } });
    expect(saved.params).toEqual({ "Windows.Hayabusa.Rules": { RuleLevel: "Critical, High, and Medium" } });
    const bp = await store.get("best-practice");
    expect(bp?.params?.["Windows.Hayabusa.Rules"]?.RuleLevel).toBe("Critical, High, and Medium");
    expect(bp?.params?.["Windows.Hayabusa.Rules"]?.RuleStatus).toBe("Stable and Experimental");
  });

  it("persists per-artifact WHERE filters and ships them on the Best Practice built-in", async () => {
    const saved = await store.save({ name: "F", description: "", artifacts: ["A.B"], filters: { "A.B": "NOT X =~ 'y'" } });
    expect(saved.filters).toEqual({ "A.B": "NOT X =~ 'y'" });
    const bp = await store.get("best-practice");
    expect(bp?.filters?.["DetectRaptor.Generic.Detection.YaraFile"]).toContain("pagefile");
  });

  it("sanitizes params — drops nested objects and coerces values to strings", async () => {
    // untrusted shape (as it arrives from the route body) — numbers coerced, nested objects dropped
    const params = { "A.B": { Keep: 5, Drop: { nested: 1 } } } as unknown as Record<string, Record<string, string>>;
    const saved = await store.save({ name: "P", description: "", artifacts: ["A.B"], params });
    expect(saved.params).toEqual({ "A.B": { Keep: "5" } });
  });

  it("stores a '__proto__' artifact key as an own property instead of hitting the prototype setter", async () => {
    // Built with JSON.parse, not an object literal: in a literal, `__proto__:` is proto-setter
    // syntax rather than a key. JSON.parse gives a real own property — which is exactly how these
    // arrive, as a parsed request body.
    const filters = JSON.parse('{"__proto__":"NOT OSPath =~ \'x\'","A.B":"NOT Z"}');
    const params = JSON.parse('{"__proto__":{"Evil":"yes"},"A.B":{"Keep":"1"}}');
    const saved = await store.save({ name: "PP", description: "", artifacts: ["A.B"], filters, params });

    // The accumulators are null-prototype, so nothing was reassigned via the inherited setter...
    expect(Object.getPrototypeOf(saved.filters!)).toBeNull();
    expect(Object.getPrototypeOf(saved.params!)).toBeNull();
    // ...and no global prototype was polluted.
    expect(({} as Record<string, unknown>).Evil).toBeUndefined();
    expect(({} as Record<string, unknown>)["A.B"]).toBeUndefined();

    // The entry is kept predictably rather than silently dropped, alongside the normal ones.
    expect(Object.keys(saved.filters!)).toEqual(["__proto__", "A.B"]);
    expect(saved.params!["__proto__"]).toEqual({ Evil: "yes" });

    // And it survives the JSON round-trip as a plain, unpolluted object.
    const reloaded = await store.get(saved.id);
    expect(Object.getPrototypeOf(reloaded!.filters!)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(reloaded!.filters!, "__proto__")).toBe(true);
    expect(reloaded!.filters!["A.B"]).toBe("NOT Z");
  });

  it("ships a super-timeline triage built-in flagged superTimelineOnly (no detection artifacts)", async () => {
    const bundle = await store.get("super-timeline-triage");
    expect(bundle).not.toBeNull();
    expect(bundle?.superTimelineOnly).toBe(true);
    expect(bundle?.builtIn).toBe(true);
    expect(bundle?.artifacts).toContain("Windows.NTFS.MFT");
    expect(bundle?.artifacts.some((a) => /sigma|yara|hayabusa/i.test(a))).toBe(false);
  });

  it("preserves superTimelineOnly across an edit (override round-trip)", async () => {
    const original = await store.get("super-timeline-triage");
    await store.save({ ...original!, artifacts: [...original!.artifacts, "Windows.Some.Extra"] });
    const reloaded = await store.get("super-timeline-triage");
    expect(reloaded?.superTimelineOnly).toBe(true);
  });

  it("every built-in bundle has a name, description, and at least one artifact", () => {
    for (const b of BUILT_IN_BUNDLES) {
      expect(b.name).toBeTruthy();
      expect(b.description).toBeTruthy();
      expect(b.artifacts.length).toBeGreaterThan(0);
    }
  });
});
