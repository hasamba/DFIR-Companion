import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TemplateStore, BUILT_IN_TEMPLATES, buildInitialQuestions, buildInitialNextSteps } from "../../src/analysis/templateStore.js";

describe("TemplateStore", () => {
  let root: string;
  let store: TemplateStore;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-templates-"));
    store = new TemplateStore(root);
  });

  describe("list()", () => {
    it("returns all built-in templates when no custom templates exist", async () => {
      const templates = await store.list();
      expect(templates.length).toBeGreaterThanOrEqual(BUILT_IN_TEMPLATES.length);
      const ids = templates.map((t) => t.id);
      expect(ids).toContain("ransomware");
      expect(ids).toContain("bec");
      expect(ids).toContain("insider-threat");
      expect(ids).toContain("web-intrusion");
      expect(ids).toContain("general-malware");
    });

    it("includes custom templates after saving", async () => {
      await store.save({ name: "My Template", description: "test", recommendedImports: [], initialKeyQuestions: ["Q1"], severityFloor: null, huntPlatforms: [] });
      const templates = await store.list();
      const custom = templates.filter((t) => !t.builtIn);
      expect(custom).toHaveLength(1);
      expect(custom[0].name).toBe("My Template");
    });

    it("returns built-in templates even if templates directory does not exist", async () => {
      const fresh = new TemplateStore(join(root, "nonexistent"));
      const templates = await fresh.list();
      expect(templates.length).toBe(BUILT_IN_TEMPLATES.length);
    });
  });

  describe("get()", () => {
    it("returns a built-in template by id", async () => {
      const t = await store.get("ransomware");
      expect(t).not.toBeNull();
      expect(t!.name).toBe("Ransomware");
      expect(t!.builtIn).toBe(true);
      expect(t!.initialKeyQuestions.length).toBeGreaterThan(0);
    });

    it("returns null for an unknown id", async () => {
      expect(await store.get("does-not-exist")).toBeNull();
    });

    it("returns a saved custom template by id", async () => {
      const saved = await store.save({ name: "Custom", description: "desc", recommendedImports: ["thor"], initialKeyQuestions: ["Q?"], severityFloor: "High", huntPlatforms: ["Velociraptor"] });
      const fetched = await store.get(saved.id);
      expect(fetched).not.toBeNull();
      expect(fetched!.name).toBe("Custom");
      expect(fetched!.builtIn).toBe(false);
      expect(fetched!.recommendedImports).toEqual(["thor"]);
    });
  });

  describe("save()", () => {
    it("assigns a uuid when id is omitted", async () => {
      const t = await store.save({ name: "A", description: "", recommendedImports: [], initialKeyQuestions: [], severityFloor: null, huntPlatforms: [] });
      expect(t.id).toBeTruthy();
      expect(t.builtIn).toBe(false);
    });

    it("uses the provided id", async () => {
      const t = await store.save({ id: "my-tmpl", name: "B", description: "", recommendedImports: [], initialKeyQuestions: [], severityFloor: null, huntPlatforms: [] });
      expect(t.id).toBe("my-tmpl");
    });

    it("persists the template so a new store instance can read it", async () => {
      await store.save({ id: "persistent", name: "P", description: "d", recommendedImports: [], initialKeyQuestions: ["Q"], severityFloor: null, huntPlatforms: [] });
      const store2 = new TemplateStore(root);
      const fetched = await store2.get("persistent");
      expect(fetched?.name).toBe("P");
    });
  });

  describe("delete()", () => {
    it("deletes a custom template (returns true)", async () => {
      const t = await store.save({ name: "Del", description: "", recommendedImports: [], initialKeyQuestions: [], severityFloor: null, huntPlatforms: [] });
      expect(await store.delete(t.id)).toBe(true);
      expect(await store.get(t.id)).toBeNull();
    });

    it("returns false when the custom template does not exist", async () => {
      expect(await store.delete("no-such-custom")).toBe(false);
    });

    it("throws when trying to delete a built-in template", async () => {
      await expect(store.delete("ransomware")).rejects.toThrow(/built-in/);
    });
  });
});

describe("buildInitialQuestions()", () => {
  it("creates one question per entry with status=unknown and pinned=true", () => {
    const template = BUILT_IN_TEMPLATES.find((t) => t.id === "ransomware")!;
    const questions = buildInitialQuestions(template);
    expect(questions).toHaveLength(template.initialKeyQuestions.length);
    for (const [i, q] of questions.entries()) {
      expect(q.id).toBeTruthy();
      expect(q.question).toBe(template.initialKeyQuestions[i]);
      expect(q.status).toBe("unknown");
      expect(q.answer).toBe("");
      expect(q.pinned).toBe(true);
    }
  });

  it("returns distinct ids across calls", () => {
    const template = BUILT_IN_TEMPLATES.find((t) => t.id === "bec")!;
    const q1 = buildInitialQuestions(template);
    const q2 = buildInitialQuestions(template);
    const ids1 = q1.map((q) => q.id);
    const ids2 = q2.map((q) => q.id);
    expect(ids1).not.toEqual(ids2);
  });
});

describe("buildInitialNextSteps()", () => {
  it("creates one NextStep per entry with correct fields", () => {
    const template = BUILT_IN_TEMPLATES.find((t) => t.id === "ransomware")!;
    const steps = buildInitialNextSteps(template);
    expect(steps).toHaveLength(template.initialNextSteps.length);
    for (const [i, s] of steps.entries()) {
      expect(s.id).toBeTruthy();
      expect(s.action).toBe(template.initialNextSteps[i].action);
      expect(s.priority).toBe(template.initialNextSteps[i].priority);
      expect(s.rationale).toBe(template.initialNextSteps[i].rationale);
      expect(s.pointer).toBe(template.initialNextSteps[i].pointer);
    }
  });

  it("all built-in templates have at least 5 next steps", () => {
    for (const t of BUILT_IN_TEMPLATES) {
      expect(t.initialNextSteps.length).toBeGreaterThanOrEqual(5);
    }
  });

  it("all next steps have valid priority values", () => {
    const valid = new Set(["critical", "high", "medium", "low"]);
    for (const t of BUILT_IN_TEMPLATES) {
      for (const s of t.initialNextSteps) {
        expect(valid.has(s.priority)).toBe(true);
      }
    }
  });

  it("returns distinct ids across calls", () => {
    const template = BUILT_IN_TEMPLATES.find((t) => t.id === "general-malware")!;
    const s1 = buildInitialNextSteps(template);
    const s2 = buildInitialNextSteps(template);
    expect(s1.map((s) => s.id)).not.toEqual(s2.map((s) => s.id));
  });

  it("returns empty array when template has no initialNextSteps", () => {
    const bare = { ...BUILT_IN_TEMPLATES[0], initialNextSteps: [] as never[] };
    expect(buildInitialNextSteps(bare)).toEqual([]);
  });
});
