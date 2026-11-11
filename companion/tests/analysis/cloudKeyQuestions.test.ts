import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { CLOUD_KEY_QUESTIONS, withCloudSeedQuestions } from "../../src/analysis/cloudKeyQuestions.js";
import { applyIncidentTypeToState, parseIncidentType } from "../../src/analysis/incidentTypes.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";

const bec = parseIncidentType(
  JSON.parse(readFileSync(new URL("../../data/incident-types/bec.json", import.meta.url), "utf8")),
);

const base = (): InvestigationState => emptyState("c1");
const texts = (s: InvestigationState): string[] => s.keyQuestions.map((q) => q.question);
const dupes = (s: InvestigationState): string[] => texts(s).filter((t, i, all) => all.indexOf(t) !== i);

describe("withCloudSeedQuestions (#2555)", () => {
  it("covers mailbox rules, forwarding, delegates, OAuth consent, admin roles, new accounts, sign-ins", () => {
    const all = CLOUD_KEY_QUESTIONS.map((q) => q.question).join(" ");
    for (const topic of [
      /inbox rules/i,
      /forwarding/i,
      /delegate/i,
      /OAuth/,
      /role/i,
      /new user accounts/i,
      /IP addresses/i,
    ])
      expect(all).toMatch(topic);
  });

  it("seeds the cloud questions once, pinned and unknown, on a cloud-only case", () => {
    const out = withCloudSeedQuestions(base(), true);
    expect(out.keyQuestions).toHaveLength(CLOUD_KEY_QUESTIONS.length);
    expect(out.keyQuestions.every((q) => q.pinned && q.status === "unknown")).toBe(true);
    const again = withCloudSeedQuestions(out, true);
    expect(again.keyQuestions).toHaveLength(CLOUD_KEY_QUESTIONS.length);
    expect(dupes(again)).toEqual([]);
  });

  it("adds nothing on a case that is not cloud-only", () => {
    const s = base();
    expect(withCloudSeedQuestions(s, false)).toBe(s);
  });

  it("keeps the model's answer to a seed and re-marks it pinned", () => {
    const [first] = CLOUD_KEY_QUESTIONS;
    const s = {
      ...base(),
      keyQuestions: [
        { ...first, status: "answered" as const, answer: "Yes — rule r1.", pointer: "", pinned: false },
      ],
    };
    const out = withCloudSeedQuestions(s, true);
    const kept = out.keyQuestions.find((q) => q.id === first.id);
    expect(kept?.answer).toBe("Yes — rule r1.");
    expect(kept?.pinned).toBe(true);
    expect(out.keyQuestions.filter((q) => q.id === first.id)).toHaveLength(1);
  });

  it("does not duplicate the BEC type's questions, in either order", () => {
    expect(bec).not.toBeNull();
    const typeFirst = withCloudSeedQuestions(applyIncidentTypeToState(base(), bec!).state, true);
    expect(dupes(typeFirst)).toEqual([]);
    const seedFirst = applyIncidentTypeToState(withCloudSeedQuestions(base(), true), bec!).state;
    expect(dupes(seedFirst)).toEqual([]);
    // The overlap is real: the shared questions are BEC's own wording.
    const typeTotal = bec!.initialKeyQuestions.length + bec!.findingsSeeds.length;
    expect(texts(typeFirst)).toHaveLength(typeTotal + CLOUD_KEY_QUESTIONS.length - 2);
    expect(texts(seedFirst)).toHaveLength(typeTotal + CLOUD_KEY_QUESTIONS.length - 2);
  });

  it("does not mutate the input", () => {
    const s = base();
    withCloudSeedQuestions(s, true);
    expect(s.keyQuestions).toEqual([]);
  });
});
