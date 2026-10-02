import type { JevQuestion } from "./jevClient.js";

/**
 * The eleven questions the per-finding containment check asks Jev (#1925).
 *
 * They live here, not under analysis/ai/prompts/, on purpose: they are a fixed decision contract
 * that containmentRule.ts branches on, not a chat prompt, and the prompt change gate hashes that
 * directory only.
 *
 * Each question names the two keys of the state it judges: `finding` (the AI-written finding) and
 * `events` (the forensic-timeline rows it cites). See containmentState.ts for that shape.
 */

export const YESNO_QUESTION_IDS = [
  "credentials_exposed",
  "attacker_session",
  "mail_delivered",
  "persistence",
  "malicious_process",
  "attacker_traffic",
  "config_persisted",
  "in_progress",
  "spread_beyond",
] as const;

export const CHOICE_QUESTION_IDS = ["reach", "attack_type"] as const;

export type YesNoQuestionId = (typeof YESNO_QUESTION_IDS)[number];
export type ChoiceQuestionId = (typeof CHOICE_QUESTION_IDS)[number];
export type ContainmentQuestionId = YesNoQuestionId | ChoiceQuestionId;

/** Every question id, in the order the analyst sees the answers. */
export const CONTAINMENT_QUESTION_IDS: readonly ContainmentQuestionId[] = [
  ...YESNO_QUESTION_IDS,
  ...CHOICE_QUESTION_IDS,
];

export const REACH_OPTIONS = ["one_entity", "workgroup", "organization"] as const;
export const ATTACK_TYPE_OPTIONS = [
  "host_compromise",
  "account_takeover",
  "mail_campaign",
  "exfiltration",
] as const;

/** What the analyst reads next to each answer. Fixed text, never model output. */
export const QUESTION_LABELS: Readonly<Record<ContainmentQuestionId, string>> = {
  credentials_exposed: "Credentials reached someone unauthorized",
  attacker_session: "A session or token was in use by the attacker",
  mail_delivered: "Malicious mail was delivered to inboxes",
  persistence: "Persistence would bring the activity back after a reboot",
  malicious_process: "A malicious process or task was running",
  attacker_traffic: "Data or command traffic went to an attacker destination",
  config_persisted: "The attacker changed configuration that persists on its own",
  in_progress: "Still in progress at the end of the evidence",
  spread_beyond: "It reached beyond the flagged host or account",
  reach: "Reach",
  attack_type: "Attack type",
};

const ON = "Judge `finding` and the forensic-timeline rows it cites in `events`.";

function yesNo(question: string, yes: string, no: string): JevQuestion {
  return { type: "noul", instructions: `${ON} ${question}`, criteria: { true: yes, false: no } };
}

export const CONTAINMENT_QUESTIONS: Readonly<Record<ContainmentQuestionId, JevQuestion>> = {
  credentials_exposed: yesNo(
    "Have credentials reached someone unauthorized?",
    "The events show a password, hash, ticket, key or token dumped, stolen, phished or used by someone " +
      "who should not have it",
    "Nothing in the events shows a credential leaving its owner's control",
  ),
  attacker_session: yesNo(
    "Was a session or token in use by the attacker?",
    "The events show the attacker logged on, held a session, or used a token or cookie",
    "No attacker-held session or token appears in the events",
  ),
  mail_delivered: yesNo(
    "Was malicious mail delivered to inboxes?",
    "The events show a phishing or malicious message reaching one or more mailboxes",
    "No malicious mail delivery appears in the events",
  ),
  persistence: yesNo(
    "Is there something that would bring the activity back after a reboot?",
    "The events show a run key, service, scheduled task, startup item, WMI subscription or similar " +
      "persistence created by the activity",
    "No persistence mechanism appears in the events",
  ),
  malicious_process: yesNo(
    "Was a malicious process or task running?",
    "The events show a malicious process, script or task executing",
    "No malicious execution appears in the events",
  ),
  attacker_traffic: yesNo(
    "Did data or command traffic go to an attacker destination?",
    "The events show a connection, upload or beacon to an attacker-controlled address or service",
    "No traffic to an attacker destination appears in the events",
  ),
  config_persisted: yesNo(
    "Did the attacker change configuration that persists on its own, such as mail forwarding rules, " +
      "delegations or application consents?",
    "The events show a forwarding rule, delegation, consent grant or similar standing change made by " +
      "the attacker",
    "No standing configuration change by the attacker appears in the events",
  ),
  in_progress: yesNo(
    "Was the activity still in progress at the end of the collected evidence, rather than finished? " +
      "This is a snapshot, not a live status.",
    "The latest events show the activity still running or recurring when collection ended",
    "The activity had stopped or finished before the evidence ends",
  ),
  spread_beyond: yesNo(
    "Did the activity reach beyond the host or account that was flagged?",
    "The events show the same activity on a second host or account",
    "The activity stays on the one flagged host or account",
  ),
  reach: {
    type: "choice",
    instructions: `${ON} How far did the activity reach?`,
    criteria: {
      one_entity: "One host or one account",
      workgroup: "A handful of hosts or accounts, such as one team or one site",
      organization: "Hosts or accounts across the whole organization",
    },
  },
  attack_type: {
    type: "choice",
    instructions: `${ON} Which kind of attack is this mainly?`,
    criteria: {
      host_compromise: "Malicious code or hands-on activity on a host",
      account_takeover: "An attacker using a legitimate account",
      mail_campaign: "Phishing or malicious mail sent to many recipients",
      exfiltration: "Data taken out of the organization",
    },
  },
};
