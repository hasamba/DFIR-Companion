import type { JevAnswer } from "./jevClient.js";
import {
  CONTAINMENT_QUESTION_IDS,
  QUESTION_LABELS,
  type ContainmentQuestionId,
} from "./containmentQuestions.js";
import type { ContainmentAnswer } from "../../playbookContainment.js";

/**
 * The containment check's answer-to-step rule (#1925). Pure code: Jev answers eleven narrow
 * questions, and this file alone decides which containment steps those answers suggest. Every step
 * id, title and basis token comes from the fixed tables below, never from model text, so the step
 * id is safe to use as the Playbook dedup key.
 */

export const RULE_VERSION = "containment-v1";
/** A yes/no answer at or above this probability is a yes. */
export const YES_AT = 0.6;
/** A yes/no answer below this probability is a no. Between the two it is unsure. */
export const NO_BELOW = 0.15;
/** A choice whose confidence is below this is marked "check manually". */
export const CHOICE_SURE_AT = 0.6;

export const STEP_IDS = [
  "block-destination-org",
  "block-host-egress",
  "disable-account",
  "revoke-sessions",
  "revoke-keys-reauth",
  "block-sender",
  "purge-mail",
  "isolate-host",
  "kill-process",
  "remove-config",
  "escalate-manual-review",
] as const;
export type ContainmentStepId = (typeof STEP_IDS)[number];

export const STEP_TITLES: Readonly<Record<ContainmentStepId, string>> = {
  "block-destination-org": "Block the attacker destination across the organization",
  "block-host-egress": "Block this host's egress to the attacker destination",
  "disable-account": "Disable the affected account",
  "revoke-sessions": "Revoke the attacker's sessions and tokens",
  "revoke-keys-reauth": "Reset the exposed credentials and require re-authentication",
  "block-sender": "Block the sender for this mailbox",
  "purge-mail": "Purge the delivered malicious mail from inboxes",
  "isolate-host": "Isolate the host",
  "kill-process": "Kill the malicious process or task",
  "remove-config": "Remove the attacker's forwarding rules, delegations or consents",
  "escalate-manual-review": "Escalate for a manual containment review",
};

/** The org-wide variant of block-sender's title (a campaign, or a reach wider than one entity). */
export const BLOCK_SENDER_ORG_TITLE = "Block the sender org-wide";

export type StepPriorityName = "critical" | "high" | "medium";

export interface SuggestedStep {
  readonly id: ContainmentStepId;
  readonly title: string;
  readonly priority: StepPriorityName;
  readonly basis: string[];
  readonly checkManually: boolean;
}

function classifyOne(id: ContainmentQuestionId, raw: JevAnswer | undefined): ContainmentAnswer {
  const label = QUESTION_LABELS[id];
  const choice = id === "reach" || id === "attack_type";
  if (!raw || raw.type !== (choice ? "choice" : "noul")) {
    throw new Error(`containment answer "${id}" is missing or has the wrong type`);
  }
  if (raw.type === "choice") {
    const sure = raw.confidence >= CHOICE_SURE_AT;
    return { id, label, kind: "choice", value: raw.confidence, verdict: raw.choice, checkManually: !sure };
  }
  if (raw.type !== "noul") throw new Error(`containment answer "${id}" has the wrong type`);
  const p = raw.noul;
  const verdict = p >= YES_AT ? "yes" : p < NO_BELOW ? "no" : "unsure";
  return { id, label, kind: "yesno", value: p, verdict, checkManually: verdict === "unsure" };
}

/** Jev's raw answers → the eleven classified answers, in the fixed question order. */
export function classifyAnswers(raw: Readonly<Record<string, JevAnswer>>): ContainmentAnswer[] {
  return CONTAINMENT_QUESTION_IDS.map((id) => classifyOne(id, raw[id]));
}

interface Draft {
  id: ContainmentStepId;
  basis: ContainmentQuestionId[];
  title?: string;
}

/** The ordered step drafts the answers fire. A trigger fires on yes and on unsure. */
function draftSteps(byId: ReadonlyMap<string, ContainmentAnswer>): Draft[] {
  const v = (id: ContainmentQuestionId): string => byId.get(id)?.verdict ?? "no";
  const fires = (id: ContainmentQuestionId): boolean => v(id) === "yes" || v(id) === "unsure";
  const spread = v("spread_beyond") === "yes";
  const orgReach = v("reach") === "organization";
  const drafts: Draft[] = [];

  if (fires("attacker_traffic")) {
    const extra: ContainmentQuestionId[] = [
      ...(orgReach ? (["reach"] as const) : []),
      ...(spread ? (["spread_beyond"] as const) : []),
    ];
    drafts.push(
      extra.length
        ? { id: "block-destination-org", basis: ["attacker_traffic", ...extra] }
        : { id: "block-host-egress", basis: ["attacker_traffic"] },
    );
  }
  if (fires("attacker_session")) {
    if (spread) drafts.push({ id: "disable-account", basis: ["attacker_session", "spread_beyond"] });
    drafts.push({ id: "revoke-sessions", basis: ["attacker_session"] });
  }
  if (fires("credentials_exposed")) drafts.push({ id: "revoke-keys-reauth", basis: ["credentials_exposed"] });
  if (fires("mail_delivered")) {
    const extra: ContainmentQuestionId[] = [
      ...(v("attack_type") === "mail_campaign" ? (["attack_type"] as const) : []),
      ...(v("reach") !== "one_entity" ? (["reach"] as const) : []),
    ];
    drafts.push({
      id: "block-sender",
      basis: ["mail_delivered", ...extra],
      ...(extra.length ? { title: BLOCK_SENDER_ORG_TITLE } : {}),
    });
    drafts.push({ id: "purge-mail", basis: ["mail_delivered"] });
  }
  if (fires("persistence")) drafts.push({ id: "isolate-host", basis: ["persistence"] });
  // An unsure persistence must not suppress a sure process kill; a sure one makes isolation enough.
  if (fires("malicious_process") && v("persistence") !== "yes")
    drafts.push({ id: "kill-process", basis: ["malicious_process"] });
  if (fires("config_persisted")) drafts.push({ id: "remove-config", basis: ["config_persisted"] });
  return drafts;
}

/**
 * The suggested steps, in priority order. A step rests on the answers in its `basis`, and is marked
 * "check manually" when any of them is. When no step rests on sure answers alone, an escalation for
 * a manual review is added, citing every answer.
 */
export function suggestSteps(answers: readonly ContainmentAnswer[]): SuggestedStep[] {
  const byId = new Map(answers.map((a) => [a.id, a]));
  const inProgress = byId.get("in_progress")?.verdict === "yes";
  const stepPriority: StepPriorityName = inProgress ? "critical" : "high";
  const steps: SuggestedStep[] = draftSteps(byId).map((d) => ({
    id: d.id,
    title: d.title ?? STEP_TITLES[d.id],
    priority: stepPriority,
    basis: [...d.basis],
    checkManually: d.basis.some((id) => byId.get(id)?.checkManually === true),
  }));
  if (steps.some((s) => !s.checkManually)) return steps;
  return [
    ...steps,
    {
      id: "escalate-manual-review",
      title: STEP_TITLES["escalate-manual-review"],
      priority: inProgress ? "high" : "medium",
      basis: [...CONTAINMENT_QUESTION_IDS],
      checkManually: false,
    },
  ];
}
