import { describe, it, expect } from "vitest";
import type { JevAnswer } from "../../src/analysis/ai/jev/jevClient.js";
import {
  CONTAINMENT_QUESTION_IDS,
  QUESTION_LABELS,
  type ContainmentQuestionId,
} from "../../src/analysis/ai/jev/containmentQuestions.js";
import {
  CHOICE_SURE_AT,
  NO_BELOW,
  RULE_VERSION,
  STEP_TITLES,
  YES_AT,
  classifyAnswers,
  suggestSteps,
  type SuggestedStep,
} from "../../src/analysis/ai/jev/containmentRule.js";

// The answer-to-step rule (#1925) is plain code, so every branch is pinned here: the grey zone,
// the order, the priorities, and "nothing applies".

type Over = Partial<Record<ContainmentQuestionId, number | [string, number]>>;

/** Jev's raw answers: every yes/no 0 and both choices sure and narrow, unless overridden. */
function raw(over: Over = {}): Record<string, JevAnswer> {
  const out: Record<string, JevAnswer> = {};
  for (const id of CONTAINMENT_QUESTION_IDS) {
    const v = over[id];
    if (id === "reach" || id === "attack_type") {
      const [choice, confidence] = Array.isArray(v)
        ? v
        : [id === "reach" ? "one_entity" : "host_compromise", 0.9];
      out[id] = { type: "choice", choice, probabilities: {}, confidence };
    } else {
      out[id] = { type: "noul", noul: typeof v === "number" ? v : 0 };
    }
  }
  return out;
}

const steps = (over: Over = {}): SuggestedStep[] => suggestSteps(classifyAnswers(raw(over)));
const ids = (over: Over = {}): string[] => steps(over).map((s) => s.id);
const step = (over: Over, id: string): SuggestedStep => {
  const found = steps(over).find((s) => s.id === id);
  if (!found) throw new Error(`no step ${id}`);
  return found;
};

describe("classifyAnswers", () => {
  it("returns the eleven answers in the fixed question order, labelled from the fixed table", () => {
    const answers = classifyAnswers(raw());
    expect(answers.map((a) => a.id)).toEqual([...CONTAINMENT_QUESTION_IDS]);
    for (const a of answers) expect(a.label).toBe(QUESTION_LABELS[a.id as ContainmentQuestionId]);
  });

  it("sorts a yes/no answer into yes, no or unsure at the grey-zone edges", () => {
    expect([YES_AT, NO_BELOW, CHOICE_SURE_AT]).toEqual([0.6, 0.15, 0.6]);
    const at = (p: number) => classifyAnswers(raw({ persistence: p })).find((a) => a.id === "persistence")!;
    expect(at(0.6)).toMatchObject({ kind: "yesno", value: 0.6, verdict: "yes", checkManually: false });
    expect(at(0.59)).toMatchObject({ verdict: "unsure", checkManually: true });
    expect(at(0.15)).toMatchObject({ verdict: "unsure", checkManually: true });
    expect(at(0.149)).toMatchObject({ verdict: "no", checkManually: false });
    expect(at(0)).toMatchObject({ verdict: "no", checkManually: false });
  });

  it("keeps a choice and its confidence, and marks a low-confidence choice", () => {
    const sure = classifyAnswers(raw({ reach: ["organization", 0.6] })).find((a) => a.id === "reach")!;
    expect(sure).toEqual({
      id: "reach",
      label: QUESTION_LABELS.reach,
      kind: "choice",
      value: 0.6,
      verdict: "organization",
      checkManually: false,
    });
    const unsure = classifyAnswers(raw({ reach: ["workgroup", 0.59] })).find((a) => a.id === "reach")!;
    expect(unsure).toMatchObject({ verdict: "workgroup", checkManually: true });
  });

  it("throws on a missing or mistyped answer rather than guessing", () => {
    const partial = raw();
    delete partial.persistence;
    expect(() => classifyAnswers(partial)).toThrow(/persistence/);
    const mistyped = { ...raw(), reach: { type: "noul", noul: 1 } as JevAnswer };
    expect(() => classifyAnswers(mistyped)).toThrow(/reach/);
  });
});

describe("suggestSteps", () => {
  it("escalates for a manual review when nothing applies, citing every answer", () => {
    const out = steps();
    expect(out).toEqual([
      {
        id: "escalate-manual-review",
        title: STEP_TITLES["escalate-manual-review"],
        priority: "medium",
        basis: [...CONTAINMENT_QUESTION_IDS],
        checkManually: false,
      },
    ]);
  });

  it("blocks this host's egress for traffic on a narrow incident", () => {
    expect(ids({ attacker_traffic: 0.9 })).toEqual(["block-host-egress"]);
    expect(step({ attacker_traffic: 0.9 }, "block-host-egress").basis).toEqual(["attacker_traffic"]);
  });

  it("blocks the destination org-wide when the reach is the organization or it spread", () => {
    expect(ids({ attacker_traffic: 0.9, reach: ["organization", 0.9] })).toEqual(["block-destination-org"]);
    expect(
      step({ attacker_traffic: 0.9, reach: ["organization", 0.9] }, "block-destination-org").basis,
    ).toEqual(["attacker_traffic", "reach"]);
    expect(ids({ attacker_traffic: 0.9, spread_beyond: 0.9 })).toEqual(["block-destination-org"]);
    expect(step({ attacker_traffic: 0.9, spread_beyond: 0.9 }, "block-destination-org").basis).toEqual([
      "attacker_traffic",
      "spread_beyond",
    ]);
  });

  it("revokes sessions for an attacker session, and disables the account when it spread", () => {
    expect(ids({ attacker_session: 0.9 })).toEqual(["revoke-sessions"]);
    expect(ids({ attacker_session: 0.9, spread_beyond: 0.9 })).toEqual([
      "disable-account",
      "revoke-sessions",
    ]);
    expect(step({ attacker_session: 0.9, spread_beyond: 0.9 }, "disable-account").basis).toEqual([
      "attacker_session",
      "spread_beyond",
    ]);
  });

  it("resets exposed credentials and requires re-authentication", () => {
    expect(ids({ credentials_exposed: 0.9 })).toEqual(["revoke-keys-reauth"]);
    expect(STEP_TITLES["revoke-keys-reauth"]).toBe(
      "Reset the exposed credentials and require re-authentication",
    );
  });

  it("blocks the sender for this mailbox on a narrow mail incident, and always purges", () => {
    const out = steps({ mail_delivered: 0.9 });
    expect(out.map((s) => s.id)).toEqual(["block-sender", "purge-mail"]);
    expect(out[0].title).toMatch(/for this mailbox/);
  });

  it("blocks the sender org-wide for a mail campaign or a wider reach", () => {
    const campaign = step({ mail_delivered: 0.9, attack_type: ["mail_campaign", 0.9] }, "block-sender");
    expect(campaign.title).toMatch(/org-wide/);
    expect(campaign.basis).toEqual(["mail_delivered", "attack_type"]);
    const wide = step({ mail_delivered: 0.9, reach: ["workgroup", 0.9] }, "block-sender");
    expect(wide.title).toMatch(/org-wide/);
    expect(wide.basis).toEqual(["mail_delivered", "reach"]);
  });

  it("isolates the host on persistence, otherwise kills the process", () => {
    expect(ids({ persistence: 0.9, malicious_process: 0.9 })).toEqual(["isolate-host"]);
    expect(ids({ malicious_process: 0.9 })).toEqual(["kill-process"]);
    // An unsure persistence does not suppress a sure process kill.
    const out = steps({ persistence: 0.4, malicious_process: 0.9 });
    expect(out.map((s) => [s.id, s.checkManually])).toEqual([
      ["isolate-host", true],
      ["kill-process", false],
    ]);
  });

  it("removes persisted configuration", () => {
    expect(ids({ config_persisted: 0.9 })).toEqual(["remove-config"]);
  });

  it("orders every step by the fixed priority list", () => {
    expect(
      ids({
        attacker_traffic: 0.9,
        attacker_session: 0.9,
        credentials_exposed: 0.9,
        spread_beyond: 0.9,
        mail_delivered: 0.9,
        persistence: 0.9,
        config_persisted: 0.9,
      }),
    ).toEqual([
      "block-destination-org",
      "disable-account",
      "revoke-sessions",
      "revoke-keys-reauth",
      "block-sender",
      "purge-mail",
      "isolate-host",
      "remove-config",
    ]);
  });

  it("raises every step to critical, and an escalation to high, when the activity is in progress", () => {
    expect(steps({ in_progress: 0.9, persistence: 0.9 }).map((s) => s.priority)).toEqual(["critical"]);
    expect(steps({ persistence: 0.9 }).map((s) => s.priority)).toEqual(["high"]);
    expect(steps({ in_progress: 0.9 }).map((s) => [s.id, s.priority])).toEqual([
      ["escalate-manual-review", "high"],
    ]);
  });

  it("still suggests the step for an unsure answer, marked check manually, beside an escalation", () => {
    const out = steps({ config_persisted: 0.3 });
    expect(out.map((s) => [s.id, s.checkManually, s.priority])).toEqual([
      ["remove-config", true, "high"],
      ["escalate-manual-review", false, "medium"],
    ]);
  });

  it("marks a step check manually when a choice it rests on is unsure", () => {
    const s = step({ attacker_traffic: 0.9, reach: ["organization", 0.4] }, "block-destination-org");
    expect(s.checkManually).toBe(true);
  });

  it("takes every title from the fixed table, never from the model", () => {
    for (const s of steps({ attacker_traffic: 0.9, mail_delivered: 0.9, config_persisted: 0.9 })) {
      expect(Object.values(STEP_TITLES)).toContain(s.title);
    }
  });

  it("is deterministic and leaves its inputs untouched", () => {
    const answers = Object.freeze(classifyAnswers(raw({ persistence: 0.9, mail_delivered: 0.3 })));
    for (const a of answers) Object.freeze(a);
    const snapshot = JSON.stringify(answers);
    const a = suggestSteps(answers);
    const b = suggestSteps(answers);
    expect(a).toEqual(b);
    expect(JSON.stringify(answers)).toBe(snapshot);
    expect(RULE_VERSION).toBe("containment-v1");
  });
});
