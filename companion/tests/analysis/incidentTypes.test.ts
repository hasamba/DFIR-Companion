import { describe, it, expect } from "vitest";
import {
  applyIncidentTypeToState,
  renderIncidentTypeBlock,
  parseIncidentType,
  BUILT_IN_INCIDENT_TYPE_IDS,
  TYPE_SEED_PREFIX,
  type IncidentType,
} from "../../src/analysis/incidentTypes.js";
import { loadBuiltInIncidentTypes, getBuiltInIncidentType } from "../../src/analysis/incidentTypesData.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

const ransomware = getBuiltInIncidentType("ransomware")!;

function customType(over: Partial<IncidentType> = {}): IncidentType {
  return {
    id: "org-ransomware-variant",
    name: "Org Ransomware Variant",
    description: "Org-specific ransomware variant",
    builtIn: false,
    recommendedImports: ["edr"],
    initialKeyQuestions: ["What was the entry point?"],
    initialNextSteps: [
      { action: "Isolate host", priority: "critical", rationale: "contain", pointer: "EDR" },
    ],
    severityFloor: "High",
    huntPlatforms: ["Velociraptor"],
    recommendedImportOrder: ["edr"],
    findingsSeeds: ["Encryption observed"],
    synthesisHint: "Org-specific ransomware — prioritize encryption.",
    ...over,
  };
}

describe("built-in incident-type library (data/incident-types/*.json)", () => {
  it("loads the eight built-in types from disk, in canonical order", () => {
    expect(loadBuiltInIncidentTypes().map((t) => t.id)).toEqual([...BUILT_IN_INCIDENT_TYPE_IDS]);
  });

  it("every built-in carries the fields the pickers and the apply path read", () => {
    for (const t of loadBuiltInIncidentTypes()) {
      expect(t.builtIn).toBe(true);
      expect(t.name.length).toBeGreaterThan(0);
      expect(t.initialKeyQuestions.length).toBeGreaterThan(0);
      expect(t.initialNextSteps.length).toBeGreaterThan(0);
      expect(t.recommendedImportOrder.length).toBeGreaterThan(0);
      expect(t.findingsSeeds.length).toBeGreaterThan(0);
      expect(t.synthesisHint.length).toBeGreaterThan(0);
    }
  });

  it("getBuiltInIncidentType resolves by id and returns undefined for unknown", () => {
    expect(getBuiltInIncidentType("ransomware")?.id).toBe("ransomware");
    expect(getBuiltInIncidentType("nope")).toBeUndefined();
  });

  it("ransomware seeds VSS deletion and double-extortion; BEC seeds inbox rules and OAuth", () => {
    expect(ransomware.findingsSeeds).toContain("VSS shadow copies deleted");
    expect(ransomware.findingsSeeds).toContain("Double-extortion leak-site listing");
    expect(ransomware.synthesisHint).toContain("T1486");

    const bec = getBuiltInIncidentType("bec")!;
    expect(bec.findingsSeeds).toContain("Attacker-created inbox/forwarding rules");
    expect(bec.findingsSeeds).toContain("OAuth app grant persistence");
  });
});

describe("parseIncidentType", () => {
  it("rejects a definition with no id or no name rather than yielding an unusable type", () => {
    expect(parseIncidentType({ name: "No id" })).toBeNull();
    expect(parseIncidentType({ id: "no-name" })).toBeNull();
    expect(parseIncidentType({ id: "", name: "empty id" })).toBeNull();
  });

  it("keeps a definition whose optional fields are malformed, defaulting just those", () => {
    const parsed = parseIncidentType({
      id: "minimal",
      name: "Minimal",
      findingsSeeds: "not-an-array",
    });
    expect(parsed?.id).toBe("minimal");
    expect(parsed?.findingsSeeds).toEqual([]);
  });
});

describe("applyIncidentTypeToState", () => {
  it("populates key questions and next steps on an empty state", () => {
    const {
      state: next,
      questionsAdded,
      nextStepsAdded,
    } = applyIncidentTypeToState(emptyState("c1"), ransomware, { now: () => "2026-07-25T00:00:00Z" });
    const expectedQuestions = ransomware.initialKeyQuestions.length + ransomware.findingsSeeds.length;
    expect(questionsAdded).toBe(expectedQuestions);
    expect(nextStepsAdded).toBe(ransomware.initialNextSteps.length);
    expect(next.keyQuestions.length).toBe(expectedQuestions);
    expect(next.nextSteps.length).toBe(ransomware.initialNextSteps.length);
    expect(next.updatedAt).toBe("2026-07-25T00:00:00Z");
  });

  // The regression this whole module was reworked for: lastSummary is the analyst's case summary
  // AND the report's executive-summary fallback. A prompt hint written there prints as the executive
  // summary of a forensic report, and is then silently overwritten by the first AI synthesis.
  it("never touches lastSummary — the synthesis hint must not reach the report", () => {
    const { state: fromEmpty } = applyIncidentTypeToState(emptyState("c1"), ransomware);
    expect(fromEmpty.lastSummary).toBe("");
    expect(JSON.stringify(fromEmpty)).not.toContain("T1486");

    const written = { ...emptyState("c1"), lastSummary: "Analyst wrote this summary." };
    expect(applyIncidentTypeToState(written, ransomware).state.lastSummary).toBe(
      "Analyst wrote this summary.",
    );
  });

  it("seeds findings as pinned confirm/deny questions with a [type-seed] prefix", () => {
    const { state: next } = applyIncidentTypeToState(emptyState("c1"), ransomware);
    const seedQs = next.keyQuestions.filter((q) => q.question.startsWith(TYPE_SEED_PREFIX));
    expect(seedQs.length).toBe(ransomware.findingsSeeds.length);
    expect(seedQs.every((q) => q.status === "unknown" && q.pinned && q.answer === "")).toBe(true);
    expect(new Set(seedQs.map((q) => q.id)).size).toBe(seedQs.length); // ids are unique
  });

  it("merges by default — preserves analyst entries and skips seeds already present", () => {
    const state = {
      ...emptyState("c1"),
      keyQuestions: [
        {
          id: "q1",
          question: "Analyst's own question",
          status: "unknown" as const,
          answer: "",
          pointer: "",
          pinned: false,
        },
      ],
      nextSteps: [
        {
          id: "s1",
          priority: "high" as const,
          action: ransomware.initialNextSteps[0].action,
          rationale: "x",
          pointer: "y",
        },
      ],
    };
    const { state: next, questionsAdded, nextStepsAdded } = applyIncidentTypeToState(state, ransomware);
    expect(next.keyQuestions.some((q) => q.question === "Analyst's own question")).toBe(true);
    expect(next.nextSteps.filter((s) => s.action === ransomware.initialNextSteps[0].action)).toHaveLength(1);
    expect(questionsAdded).toBe(ransomware.initialKeyQuestions.length + ransomware.findingsSeeds.length);
    expect(nextStepsAdded).toBe(ransomware.initialNextSteps.length - 1);
  });

  it("merging twice is idempotent — a re-apply adds nothing", () => {
    const once = applyIncidentTypeToState(emptyState("c1"), ransomware).state;
    const { state: twice, questionsAdded, nextStepsAdded } = applyIncidentTypeToState(once, ransomware);
    expect(questionsAdded).toBe(0);
    expect(nextStepsAdded).toBe(0);
    expect(twice.keyQuestions.length).toBe(once.keyQuestions.length);
    expect(twice.nextSteps.length).toBe(once.nextSteps.length);
  });

  it("replace mode overwrites existing questions and next steps", () => {
    const state = {
      ...emptyState("c1"),
      keyQuestions: [
        { id: "old", question: "old", status: "unknown" as const, answer: "", pointer: "", pinned: false },
      ],
      nextSteps: [
        { id: "old", priority: "low" as const, action: "old action", rationale: "x", pointer: "y" },
      ],
    };
    const { state: next } = applyIncidentTypeToState(state, ransomware, { replace: true });
    expect(next.keyQuestions.some((q) => q.question === "old")).toBe(false);
    expect(next.nextSteps.some((s) => s.action === "old action")).toBe(false);
    expect(next.keyQuestions.length).toBe(
      ransomware.initialKeyQuestions.length + ransomware.findingsSeeds.length,
    );
  });

  it("is pure — does not mutate the input state", () => {
    const state = emptyState("c1");
    const original = JSON.stringify(state);
    applyIncidentTypeToState(state, ransomware);
    expect(JSON.stringify(state)).toBe(original);
  });

  it("applies a custom (non-built-in) type through the same path", () => {
    const { state: next } = applyIncidentTypeToState(emptyState("c1"), customType());
    expect(next.keyQuestions.some((q) => q.question === "What was the entry point?")).toBe(true);
    expect(next.keyQuestions.some((q) => q.question.includes("Encryption observed"))).toBe(true);
  });
});

describe("renderIncidentTypeBlock", () => {
  it("renders the type name and hint for the synthesis prompt", () => {
    const block = renderIncidentTypeBlock(ransomware);
    expect(block).toContain("INCIDENT TYPE: Ransomware.");
    expect(block).toContain("T1486");
    expect(block.endsWith("\n\n")).toBe(true);
  });

  it("is empty for no type or a blank hint, so callers can concatenate it unconditionally", () => {
    expect(renderIncidentTypeBlock(null)).toBe("");
    expect(renderIncidentTypeBlock(undefined)).toBe("");
    expect(renderIncidentTypeBlock(customType({ synthesisHint: "   " }))).toBe("");
  });
});
