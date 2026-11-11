// Cloud key questions (#2555). The synthesis prompt's fixed question list is host-centric ("which
// HOSTS are compromised"), and the cloud questions that matter on a tenant-log case — mailbox rules,
// forwarding, delegate access, OAuth consent, admin role changes, new accounts, sign-in sources —
// reached the model only when an analyst picked the BEC type by hand. On a cloud-only case
// (cloudOnlyCase.ts) these are seeded as PINNED questions, so they travel the existing pinned path:
// buildPinnedBlock shows them to the model and the delta fold keeps them across the wholesale
// keyQuestions replace. No prompt text changes.
//
// Deterministic ids, so the prompt-side and fold-side applications agree and a second synthesis adds
// nothing. The two questions BEC also asks use BEC's exact wording (data/incident-types/bec.json), so
// the exact-text dedupe in applyIncidentTypeToState and here never doubles them. Pure, no I/O.

import type { InvestigationQuestion, InvestigationState } from "./stateTypes.js";

export const CLOUD_SEED_ID_PREFIX = "cloud-seed-";

const seed = (slug: string, question: string): Pick<InvestigationQuestion, "id" | "question"> => ({
  id: `${CLOUD_SEED_ID_PREFIX}${slug}`,
  question,
});

export const CLOUD_KEY_QUESTIONS: readonly Pick<InvestigationQuestion, "id" | "question">[] = [
  // BEC's wording, verbatim.
  seed("mailbox-rules", "Were mail-forwarding rules or inbox rules created by the attacker?"),
  seed(
    "delegate-access",
    "Was mailbox delegate access (FullAccess, SendAs, SendOnBehalf) or a folder permission granted to another account?",
  ),
  seed(
    "oauth-consent",
    "Was consent granted to an OAuth application, or a credential added to an app registration or service principal?",
  ),
  seed(
    "admin-roles",
    "Were admin role assignments changed (an account or app added to a privileged directory role)?",
  ),
  seed("new-accounts", "Were new user accounts created, or disabled accounts re-enabled, in the tenant?"),
  // BEC's wording, verbatim.
  seed("signin-sources", "What external IP addresses and user-agents accessed the account?"),
];

/**
 * Merge the cloud questions into `state.keyQuestions` when `cloudOnly`. A seed already present by id
 * keeps its (model-written) answer and is re-marked pinned; one present by exact text under another id
 * (an incident type's copy) is skipped. Returns `state` itself when there is nothing to do.
 */
export function withCloudSeedQuestions(state: InvestigationState, cloudOnly: boolean): InvestigationState {
  if (!cloudOnly) return state;
  const byId = new Set(state.keyQuestions.map((q) => q.id));
  const byText = new Set(state.keyQuestions.map((q) => q.question.trim()));
  const seedIds = new Set(CLOUD_KEY_QUESTIONS.map((q) => q.id));
  const repinned = state.keyQuestions.map((q) =>
    seedIds.has(q.id) && !q.pinned ? { ...q, pinned: true } : q,
  );
  const added: InvestigationQuestion[] = CLOUD_KEY_QUESTIONS.filter(
    (q) => !byId.has(q.id) && !byText.has(q.question),
  ).map((q) => ({ ...q, status: "unknown", answer: "", pointer: "", pinned: true }));
  const changed = added.length > 0 || repinned.some((q, i) => q !== state.keyQuestions[i]);
  return changed ? { ...state, keyQuestions: [...repinned, ...added] } : state;
}
