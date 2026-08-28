import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { TagsStore } from "../../src/analysis/tags.js";
import { compileRuleset } from "../../src/analysis/taggerRules.js";
import { runAndApplyTagger } from "../../src/analysis/taggerRun.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// WHO gets recorded as a tag's author when two DIFFERENT rules both apply the SAME normalized
// tag label to the SAME event.
//
// TagsStore.add() dedups only on (targetType, targetId, label) — never on author (tags.ts) — so
// the second rule's write is a no-op: the tag that survives carries whichever rule's add() call
// ran FIRST. runAndApplyTagger writes tags by iterating result.perRule in ruleset order
// (taggerRun.ts), which is compileRuleset's rule order, which is the ruleset object's own key
// order (Object.entries preserves insertion order — taggerRules.ts). So "which rule gets credit
// for a shared tag" is a real, silent dependency on how tags.yaml happens to list its rules — not
// a race, but not documented or guarded anywhere either.
//
// This test pins the behaviour so a change to iteration order (parallelizing the write loop,
// sorting rules by id, reordering tags.yaml) shows up as a failing test instead of a quiet
// authorship swap discovered on a real case.

function ev(p: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-06-01T00:00:00Z",
    description: "d",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    ...p,
  };
}

async function freshTagsStore(): Promise<TagsStore> {
  const root = await mkdtemp(join(tmpdir(), "dfir-tagger-authorship-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  return new TagsStore(cases);
}

// Matches both rules below: "7045" (a service install) and "lsass" (credential access).
const suspicious = ev({ id: "e1", message: "suspicious lsass service 7045 install" });

describe("tagger authorship on a shared tag label", () => {
  it("credits whichever rule runs FIRST when two rules apply the same tag to the same event", async () => {
    // "svc" is declared before "cred" — both apply the "flagged" tag to this event.
    const rulesSvcFirst = compileRuleset({
      svc: { any: [{ field: "message", contains: "7045" }], tags: ["flagged"], severity: "Medium" },
      cred: { any: [{ field: "message", contains: "lsass" }], tags: ["flagged"], severity: "High" },
    });

    const tagsStore = await freshTagsStore();
    await runAndApplyTagger({
      caseId: "c1",
      events: [suspicious],
      ruleset: rulesSvcFirst,
      forensicTimeline: [suspicious],
      tagsStore,
      mutateForensic: false,
    });

    const flagged = (await tagsStore.load("c1")).filter((t) => t.label === "flagged");
    expect(flagged).toHaveLength(1); // one label, one tag — the second rule's add() was a no-op
    expect(flagged[0].author).toBe("tagger:svc"); // svc ran first in this ruleset's order
  });

  it("flips to the OTHER rule's authorship when the same two rules are declared in the opposite order", async () => {
    // Same two rules, same input event — only the object/YAML key order changes.
    const rulesCredFirst = compileRuleset({
      cred: { any: [{ field: "message", contains: "lsass" }], tags: ["flagged"], severity: "High" },
      svc: { any: [{ field: "message", contains: "7045" }], tags: ["flagged"], severity: "Medium" },
    });

    const tagsStore = await freshTagsStore();
    await runAndApplyTagger({
      caseId: "c1",
      events: [suspicious],
      ruleset: rulesCredFirst,
      forensicTimeline: [suspicious],
      tagsStore,
      mutateForensic: false,
    });

    const flagged = (await tagsStore.load("c1")).filter((t) => t.label === "flagged");
    expect(flagged).toHaveLength(1);
    expect(flagged[0].author).toBe("tagger:cred"); // cred now runs first — authorship follows rule order
  });

  it("still unions severity across both rules even though only one gets credit for the shared tag", async () => {
    // Authorship of the shared tag is order-dependent (above); severity is NOT — raiseSeverity is
    // commutative, so the forensic event ends up High regardless of which rule "won" the tag.
    const rules = compileRuleset({
      svc: { any: [{ field: "message", contains: "7045" }], tags: ["flagged"], severity: "Medium" },
      cred: { any: [{ field: "message", contains: "lsass" }], tags: ["flagged"], severity: "High" },
    });
    const tagsStore = await freshTagsStore();
    const applied = await runAndApplyTagger({
      caseId: "c1",
      events: [suspicious],
      ruleset: rules,
      forensicTimeline: [suspicious],
      tagsStore,
      mutateForensic: true,
    });
    expect(applied.forensicTimeline[0].severity).toBe("High");
  });
});
