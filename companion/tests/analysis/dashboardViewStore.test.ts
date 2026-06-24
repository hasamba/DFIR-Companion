import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DashboardViewStore } from "../../src/analysis/dashboardViewStore.js";
import { BUILT_IN_DASHBOARD_VIEWS } from "../../src/analysis/dashboardViews.js";

describe("DashboardViewStore", () => {
  let root: string;
  let store: DashboardViewStore;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-dashviews-"));
    store = new DashboardViewStore(root);
  });

  describe("list()", () => {
    it("returns the built-in views when none are saved", async () => {
      const views = await store.list();
      expect(views.length).toBe(BUILT_IN_DASHBOARD_VIEWS.length);
      expect(views.every((v) => v.builtIn && !v.customized)).toBe(true);
      expect(views.map((v) => v.id)).toContain("executive");
    });

    it("returns built-ins even when the dir does not exist", async () => {
      const fresh = new DashboardViewStore(join(root, "nope"));
      expect((await fresh.list()).length).toBe(BUILT_IN_DASHBOARD_VIEWS.length);
    });

    it("appends custom views after the built-ins", async () => {
      await store.save({ name: "My View", sections: ["sec-findings", "sec-timeline"] });
      const views = await store.list();
      const custom = views.filter((v) => !v.builtIn);
      expect(custom).toHaveLength(1);
      expect(custom[0].name).toBe("My View");
      expect(custom[0].sections).toEqual(["sec-findings", "sec-timeline"]);
    });
  });

  describe("save()", () => {
    it("assigns an id to a new custom view and drops invalid section ids", async () => {
      const saved = await store.save({ name: "Triage-ish", sections: ["sec-findings", "not-a-section", "sec-iocs"] });
      expect(saved.id).toBeTruthy();
      expect(saved.builtIn).toBe(false);
      expect(saved.sections).toEqual(["sec-findings", "sec-iocs"]); // bogus id filtered out
    });

    it("clamps filters and keeps a valid report template reference", async () => {
      const saved = await store.save({
        name: "Lead-ish",
        sections: ["sec-findings"],
        filters: { minSeverity: "High", topN: 3 },
        reportTemplateId: "executive-brief",
      });
      expect(saved.filters).toEqual({ minSeverity: "High", topN: 3 });
      expect(saved.reportTemplateId).toBe("executive-brief");
    });

    it("overrides a built-in in place (editable built-in), flagged customized", async () => {
      await store.save({ id: "executive", name: "Exec (custom)", sections: ["sec-exec", "sec-findings"] });
      const view = await store.get("executive");
      expect(view).not.toBeNull();
      expect(view!.builtIn).toBe(true);
      expect(view!.customized).toBe(true);
      expect(view!.name).toBe("Exec (custom)");
      // list() reflects the override too.
      const fromList = (await store.list()).find((v) => v.id === "executive")!;
      expect(fromList.customized).toBe(true);
    });
  });

  describe("get()", () => {
    it("returns a built-in by id (not customized) and null for unknown", async () => {
      const exec = await store.get("executive");
      expect(exec!.builtIn).toBe(true);
      expect(exec!.customized).toBe(false);
      expect(await store.get("nope")).toBeNull();
    });
  });

  describe("delete()", () => {
    it("removes a custom view", async () => {
      const saved = await store.save({ name: "Temp", sections: ["sec-findings"] });
      expect(await store.delete(saved.id)).toBe(true);
      expect(await store.get(saved.id)).toBeNull();
    });

    it("resets an overridden built-in to its shipped default", async () => {
      await store.save({ id: "lead", name: "Lead (custom)", sections: ["sec-findings"] });
      expect((await store.get("lead"))!.customized).toBe(true);
      expect(await store.delete("lead")).toBe(true);
      const reset = await store.get("lead");
      expect(reset!.customized).toBe(false);
      expect(reset!.name).toBe("Lead"); // back to the shipped built-in
    });

    it("returns false when nothing is on disk", async () => {
      expect(await store.delete("custom-that-never-existed")).toBe(false);
    });
  });

  it("skips a malformed file instead of throwing", async () => {
    await writeFile(join(root, "broken.json"), "{ not valid json", "utf8");
    await store.save({ name: "Good", sections: ["sec-findings"] });
    const views = await store.list();
    expect(views.some((v) => v.name === "Good")).toBe(true);
  });
});
