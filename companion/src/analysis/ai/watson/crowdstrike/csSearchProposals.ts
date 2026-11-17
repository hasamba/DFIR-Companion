import { readSiemLimits, siemConfigured } from "../../../siemSearch.js";
import type { CaseStore } from "../../../../storage/caseStore.js";
import type { Outcome } from "../roundOutcome.js";
import { newWatsonId } from "../roundProposals.js";
import type { WatsonChat, WatsonCsSearchProposal, WatsonRequest } from "../types.js";
import { fingerprintStoreFor } from "../velo/fingerprintIndex.js";
import { checkCsSearch, CS_ALREADY_RAN } from "./csLaunchCheck.js";

// Turns the reply's CrowdStrike search request into a PENDING cs_search card (#2666), the way
// velo/veloLaunchProposals.ts does for Velociraptor. Every request passes the launch check first: a
// refusal never becomes a card, and Watson's turn says there is nothing to approve. Nothing here calls
// Falcon; running the card is the analyst's approval (or Auto's), a later step.

type CsRequest = Extract<WatsonRequest, { kind: "crowdstrike_search" }>;

export interface CsSearchSeams {
  cases: CaseStore;
  chatStore: { load(caseId: string): Promise<WatsonChat> };
}

const NOTE_MAX = 600;
const TITLE_MAX = 200;
const oneLine = (s: string): string => s.replace(/\s+/g, " ").trim();

const skipped = (detail: string): string =>
  oneLine(`(Nothing to approve: Watson did not propose the CrowdStrike search. ${detail})`).slice(
    0,
    NOTE_MAX,
  );

/**
 * The outcome carrying its search card or a turn note. With `allowed` false (a round that may not
 * write) the request is dropped silently. Never throws: a failed read becomes a note.
 */
export async function withCsSearch(
  seams: CsSearchSeams,
  caseId: string,
  outcome: Outcome,
  allowed: boolean,
  env: Readonly<Record<string, string | undefined>> = process.env,
  now = Date.now(),
): Promise<Outcome> {
  const r = outcome.reply?.request;
  if (!r || r.kind !== "crowdstrike_search" || !allowed) return outcome;
  try {
    if (!siemConfigured(env))
      return { ...outcome, csNote: skipped("CrowdStrike Next-Gen SIEM search is not set up.") };
    const limits = readSiemLimits(env);
    const ran = await fingerprintStoreFor(seams.cases).load(caseId);
    const check = checkCsSearch(r, limits, ran, now);
    if (!check.ok) {
      return { ...outcome, csNote: check.duplicate ? skipped(CS_ALREADY_RAN) : skipped(check.reason) };
    }
    const open = (await seams.chatStore.load(caseId)).proposals.some(
      (p) => p.kind === "cs_search" && p.status === "pending" && p.targetId === check.key,
    );
    if (open) {
      return {
        ...outcome,
        csNote:
          "(Watson did not propose the CrowdStrike search again. The same search is already on a card. Use that card.)",
      };
    }
    return { ...outcome, csProposal: proposalOf(r, check, limits.repository) };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ...outcome, csNote: skipped(`Watson could not run the checks (${msg}).`) };
  }
}

function proposalOf(
  r: CsRequest,
  check: { start: string; end: string; key: string },
  repository: string,
): Omit<WatsonCsSearchProposal, "turnId"> {
  return {
    id: newWatsonId("wp"),
    kind: "cs_search",
    status: "pending",
    targetId: check.key,
    title: oneLine(r.title).slice(0, TITLE_MAX) || "CrowdStrike search",
    query: r.query, // byte-for-byte: the card shows exactly what runs
    start: check.start,
    end: check.end,
    repository,
  };
}
