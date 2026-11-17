import type { SiemLimits } from "../../../siemSearch.js";
import {
  WatsonProposalConflict,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
} from "../proposalErrors.js";
import type { WatsonChat, WatsonCsSearchProposal, WatsonProposal } from "../types.js";
import type { HuntFingerprintStore } from "../velo/huntFingerprintStore.js";
import { checkCsSearch, CS_ALREADY_RAN } from "../crowdstrike/csLaunchCheck.js";
import type { WatsonWriter, WriterDeps } from "./writerTypes.js";

// Running a cs_search card (#2666) starts the same `siem-search` job as the analyst's Run on a CQL
// hunt, with the card's query byte-for-byte. Unlike a Velociraptor launch there is no remote call to
// be unsure about here: starting the job is local and quick, so the whole step — recheck, reserve the
// fingerprint, start the job, save `applied` with the job id — is one chat update. If the job does not
// start, the reservation is released and the card stays pending. The search itself, and its import,
// run in the job; its outcome comes back through csSearchWatch.ts.

export interface CsSearchRequest {
  title: string;
  query: string;
  start: string;
  end: string;
  repository: string;
}

/** The route-built seams (analysis/ai may not import routes/ or integrations/). */
export interface CsSearchDeps {
  /** The current caps, or null when the SIEM search client is not set up. */
  limits(): SiemLimits | null;
  /** Start the search job; `proposalId` comes back with its outcome. Throws when it did not start. */
  start(caseId: string, req: CsSearchRequest, actor: string, proposalId: string): Promise<{ jobId: string }>;
  fingerprints: Pick<HuntFingerprintStore, "load" | "reserve" | "release">;
  /** The case is closed or archived: nothing is searched. */
  isFrozen?(caseId: string): Promise<boolean>;
}

export const CS_UNDO_REFUSED = "you cannot undo a search that ran. Use Undo import for its rows";

/** In the writer table so undo is refused; apply goes through applyCsSearch. */
export const csSearchWriter: WatsonWriter<WatsonCsSearchProposal> = {
  selfLocking: true,
  apply: async () => {
    throw new WatsonProposalConflict("a CrowdStrike search is run through applyCsSearch");
  },
  undo: async (_deps, _caseId, p) => {
    throw new WatsonProposalStateError("undo", p.status, CS_UNDO_REFUSED);
  },
};

function find(chat: WatsonChat, id: string): WatsonCsSearchProposal {
  const p = chat.proposals.find((x) => x.id === id);
  if (!p) throw new WatsonProposalNotFoundError(id);
  if (p.kind !== "cs_search") throw new WatsonProposalConflict("This is not a CrowdStrike search proposal");
  return p;
}

const replace = (chat: WatsonChat, next: WatsonProposal): WatsonChat => ({
  ...chat,
  proposals: chat.proposals.map((x) => (x.id === next.id ? next : x)),
});

/** Everything that must still hold when the card runs; throws a conflict when one does not. */
async function recheck(cs: CsSearchDeps, caseId: string, p: WatsonCsSearchProposal): Promise<void> {
  if (await cs.isFrozen?.(caseId))
    throw new WatsonProposalConflict("the case is closed or archived. Nothing was searched");
  const limits = cs.limits();
  if (!limits)
    throw new WatsonProposalConflict("CrowdStrike Next-Gen SIEM search is not set up on this server");
  if (limits.repository !== p.repository) {
    throw new WatsonProposalConflict(
      "the SIEM repository changed in Settings after Watson proposed this search. Ask Watson again",
    );
  }
  const ran = await cs.fingerprints.load(caseId);
  const check = checkCsSearch({ query: p.query, start: p.start, end: p.end }, limits, ran, Date.now());
  if (!check.ok) throw new WatsonProposalConflict(`Watson will not run this. ${check.reason}`);
  if (check.key !== p.targetId)
    throw new WatsonProposalConflict("the search no longer matches what Watson proposed");
}

/** Run one cs_search card: recheck, reserve, start the job, save `applied` — or leave it pending. */
export async function applyCsSearch(
  deps: WriterDeps,
  caseId: string,
  proposalId: string,
  actor = "analyst",
  opts: { auditSuffix?: string } = {},
): Promise<{ chat: WatsonChat }> {
  const cs = deps.csSearch;
  if (!cs) throw new WatsonProposalConflict("CrowdStrike Next-Gen SIEM search is not set up on this server");
  let done: WatsonCsSearchProposal | undefined;
  const chat = await deps.chatStore.update(caseId, async (c) => {
    const p = find(c, proposalId);
    if (p.status !== "pending") throw new WatsonProposalStateError("apply", p.status);
    await recheck(cs, caseId, p);
    const reserved = await cs.fingerprints.reserve(caseId, [p.targetId]);
    if (!reserved.ok) throw new WatsonProposalConflict(`Watson will not run this. ${CS_ALREADY_RAN}`);
    let jobId: string;
    try {
      const req = { title: p.title, query: p.query, start: p.start, end: p.end, repository: p.repository };
      ({ jobId } = await cs.start(caseId, req, actor, p.id));
    } catch (err) {
      await cs.fingerprints.release(caseId, reserved.added).catch(() => undefined);
      throw new WatsonProposalConflict(`The search did not start: ${(err as Error).message}`);
    }
    const at = new Date().toISOString();
    done = {
      ...p,
      status: "applied",
      launched: { jobId, at, by: actor },
      watch: { state: "running" },
      appliedAt: at,
      appliedBy: actor,
    };
    return replace(c, done);
  });
  if (done) {
    await deps.activity.add(caseId, {
      actor,
      category: "ai",
      action: "watson.apply",
      detail:
        `Applied Watson's CrowdStrike NG-SIEM search: ${done.title}`.slice(0, 200) + (opts.auditSuffix ?? ""),
      targetType: "hunt",
      targetId: done.targetId,
    });
  }
  return { chat };
}
