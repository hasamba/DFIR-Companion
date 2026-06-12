import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ReportTemplateStore } from "../../src/reports/reportTemplateStore.js";
import { BUILT_IN_REPORT_TEMPLATES, orderedEnabledSections } from "../../src/reports/reportTemplate.js";

describe("ReportTemplateStore", () => {
  let root: string;
  let store: ReportTemplateStore;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-report-templates-"));
    store = new ReportTemplateStore(root);
  });

  describe("list()", () => {
    it("returns the built-in templates when no custom templates exist", async () => {
      const templates = await store.list();
      const ids = templates.map((t) => t.id);
      expect(ids).toContain("standard");
      expect(ids).toContain("executive-brief");
      expect(templates.length).toBe(BUILT_IN_REPORT_TEMPLATES.length);
      expect(templates.every((t) => t.builtIn && !t.customized)).toBe(true);
    });

    it("returns built-ins even when the templates dir does not exist", async () => {
      const fresh = new ReportTemplateStore(join(root, "nope"));
      expect((await fresh.list()).length).toBe(BUILT_IN_REPORT_TEMPLATES.length);
    });

    it("merges custom templates after the built-ins", async () => {
      await store.save({ name: "Client Deliverable", accentColor: "#ff8800" });
      const templates = await store.list();
      const custom = templates.filter((t) => !t.builtIn);
      expect(custom).toHaveLength(1);
      expect(custom[0].name).toBe("Client Deliverable");
      expect(custom[0].accentColor).toBe("#ff8800");
      expect(custom[0].id).toBeTruthy(); // auto-assigned uuid
    });
  });

  describe("save()", () => {
    it("normalizes the payload (sections coverage, accent validation, builtIn derived from id)", async () => {
      const saved = await store.save({ name: "  Trimmed  ", accentColor: "garbage", sections: "bad" });
      expect(saved.name).toBe("Trimmed");
      expect(saved.accentColor).toBe("#2d6cdf"); // junk → default
      expect(saved.sections.length).toBeGreaterThan(0);
      expect(saved.builtIn).toBe(false);
    });

    it("writing under a built-in id creates an editable override (customized), reset deletes it", async () => {
      const saved = await store.save({ id: "standard", name: "Standard (branded)", accentColor: "#112233" });
      expect(saved.builtIn).toBe(true);
      expect(saved.customized).toBe(true);

      const got = await store.get("standard");
      expect(got?.customized).toBe(true);
      expect(got?.accentColor).toBe("#112233");

      // list shows the override in place of the shipped default
      const inList = (await store.list()).find((t) => t.id === "standard")!;
      expect(inList.customized).toBe(true);

      // delete resets it to the shipped default
      expect(await store.delete("standard")).toBe(true);
      const reset = await store.get("standard");
      expect(reset?.customized).toBe(false);
      expect(reset?.accentColor).toBe("#2d6cdf");
    });
  });

  describe("get()", () => {
    it("returns a built-in by id with builtIn flag", async () => {
      const brief = await store.get("executive-brief");
      expect(brief?.builtIn).toBe(true);
      expect(orderedEnabledSections(brief!)).toEqual(["titlePage", "executiveSummary", "businessImpact", "conclusions"]);
    });

    it("returns null for an unknown custom id", async () => {
      expect(await store.get("does-not-exist")).toBeNull();
    });
  });

  describe("delete()", () => {
    it("removes a custom template and returns true; false when nothing on disk", async () => {
      const saved = await store.save({ id: "mine", name: "Mine" });
      expect(await store.delete(saved.id)).toBe(true);
      expect(await store.get("mine")).toBeNull();
      expect(await store.delete("mine")).toBe(false);
    });
  });
});
