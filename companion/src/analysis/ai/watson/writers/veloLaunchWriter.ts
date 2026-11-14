import {
  WatsonLaunchUncertain,
  WatsonProposalConflict,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
} from "../proposalErrors.js";
import type { WatsonChat, WatsonProposal, WatsonVeloLaunchProposal } from "../types.js";
import { ALREADY_RAN, checkLaunch } from "../velo/launchCheck.js";
import { clearInFlight, markInFlight } from "../velo/launchInFlight.js";
import type { VeloLaunchDeps, VeloLaunchOutcome, VeloLaunchRequest } from "../velo/launchTypes.js";
import { initialWatch } from "../velo/launchWatch.js";
import { loadVeloFleet } from "../velo/veloFleet.js";
import type { WatsonWriter, WriterDeps } from "./writerTypes.js";

// Applying a velo_launch proposal launches a Velociraptor hunt or collection through the existing
// deploy path, exactly once. The intent is saved BEFORE the external call (status `launching`, with
// the fingerprint keys it reserved) and the ids right AFTER it, in a second save. Between the two the
// chat is not locked, so the launch never holds up the panel. A failure known to come before the
// call returns the proposal to pending and releases its keys; anything else is `uncertain` and waits
// for the analyst (launchResolve.ts) — it is never retried automatically.

export const UNDO_REFUSED = "a launched hunt cannot be undone";

/** In the writer table so undo is refused; apply goes through applyVeloLaunch (two saves). */
export const veloLaunchWriter: WatsonWriter<WatsonVeloLaunchProposal> = {
  selfLocking: true,
  apply: async () => {
    throw new WatsonProposalConflict("a Velociraptor launch is applied through applyVeloLaunch");
  },
  undo: async (_deps, _caseId, p) => {
    throw new WatsonProposalStateError("undo", p.status, UNDO_REFUSED);
  },
};

/** Statuses that mean this launch ran, is running or may have run. */
const LIVE: ReadonlySet<WatsonProposal["status"]> = new Set(["launching", "applied", "uncertain"]);

const keysOf = (p: WatsonVeloLaunchProposal): string[] => [p.fingerprint, ...p.fingerprints].filter(Boolean);

function sameLaunchLive(chat: WatsonChat, p: WatsonVeloLaunchProposal): boolean {
  const mine = new Set(keysOf(p));
  return chat.proposals.some(
    (x) =>
      x.id !== p.id && x.kind === "velo_launch" && LIVE.has(x.status) && keysOf(x).some((k) => mine.has(k)),
  );
}

function findLaunch(chat: WatsonChat, proposalId: string): WatsonVeloLaunchProposal {
  const p = chat.proposals.find((x) => x.id === proposalId);
  if (!p) throw new WatsonProposalNotFoundError(proposalId);
  if (p.kind !== "velo_launch") throw new WatsonProposalConflict("not a Velociraptor launch proposal");
  return p;
}

const replace = (chat: WatsonChat, next: WatsonProposal): WatsonChat => ({
  ...chat,
  proposals: chat.proposals.map((x) => (x.id === next.id ? next : x)),
});

/** Re-run every launch check against the current fleet and index; throws a conflict when one fails. */
async function recheck(v: VeloLaunchDeps, caseId: string, p: WatsonVeloLaunchProposal): Promise<string[]> {
  const fleet = await loadVeloFleet(v.fleet, caseId);
  if (!fleet) throw new WatsonProposalConflict("this case has no Velociraptor server");
  const deployed = await v.fingerprints.load(caseId);
  const input = { vql: p.vql, mode: p.mode, ...(p.hostname ? { hostname: p.hostname } : {}) };
  const check = checkLaunch(input, { inventory: fleet.records, deployed, matchClient: v.matchClient });
  if (!check.ok) throw new WatsonProposalConflict(`Watson will not launch this: ${check.reason}`);
  if (check.fingerprint !== p.fingerprint || (check.clientHost ?? "") !== (p.hostname ?? "")) {
    throw new WatsonProposalConflict("the launch no longer matches what Watson proposed");
  }
  return check.fingerprints;
}

/**
 * Save #1: checks pass, keys reserved, status `launching`. Returns the keys this call reserved and
 * the proposal as saved (the launch uses it — no reload between the two saves). Only
 * the caller that passed the status check marks the launch in flight (a losing double-click must
 * never clear the winner's mark, or its running launch would look stranded).
 */
async function saveIntent(deps: WriterDeps, v: VeloLaunchDeps, caseId: string, id: string, by: string) {
  let added: string[] = [];
  let marked = false;
  let saved: WatsonVeloLaunchProposal | undefined;
  try {
    await deps.chatStore.update(caseId, async (c) => {
      const p = findLaunch(c, id);
      if (p.status !== "pending") throw new WatsonProposalStateError("apply", p.status);
      if (sameLaunchLive(c, p))
        throw new WatsonProposalConflict("an identical launch already ran or is running");
      const keys = await recheck(v, caseId, p);
      const r = await v.fingerprints.reserve(caseId, keys);
      if (!r.ok) throw new WatsonProposalConflict(`Watson will not launch this: ${ALREADY_RAN}`);
      added = r.added;
      markInFlight(caseId, id);
      marked = true;
      const launching = { at: new Date().toISOString(), by, fingerprint: p.fingerprint, reserved: added };
      saved = { ...p, status: "launching", launching };
      return replace(c, saved);
    });
  } catch (err) {
    if (marked) clearInFlight(caseId, id);
    if (added.length) await releaseOrLog(v, caseId, added); // no call was made
    throw err; // the original error, even when the release failed too
  }
  if (!saved) throw new WatsonProposalConflict("the launch intent was not saved");
  return { added, proposal: saved };
}

/** Release keys this call reserved; a failure is logged, never thrown. True when released. */
async function releaseOrLog(v: VeloLaunchDeps, caseId: string, keys: string[]): Promise<boolean> {
  try {
    await v.fingerprints.release(caseId, keys);
    return true;
  } catch (err) {
    v.log?.(`[watson] releasing reserved hunt fingerprints failed: ${(err as Error).message}`);
    return false;
  }
}

/** Save #2: the outcome. `fn` maps the stored launching proposal to its next state. */
function saveOutcome(
  deps: WriterDeps,
  caseId: string,
  id: string,
  fn: (p: WatsonVeloLaunchProposal) => WatsonVeloLaunchProposal,
): Promise<WatsonChat> {
  return deps.chatStore.update(caseId, (c) => {
    const p = findLaunch(c, id);
    if (p.status !== "launching") throw new WatsonProposalStateError("apply", p.status);
    return replace(c, fn(p));
  });
}

async function runLaunch(
  v: VeloLaunchDeps,
  caseId: string,
  p: WatsonVeloLaunchProposal,
  actor: string,
): Promise<VeloLaunchOutcome> {
  let req: VeloLaunchRequest;
  try {
    req = { mode: p.mode, vql: p.vql, title: p.title, ...(p.hostname ? { hostname: p.hostname } : {}) };
  } catch (err) {
    return { phase: "before-launch", error: (err as Error).message }; // the launch was never called
  }
  try {
    return await v.launch(caseId, req, actor);
  } catch (err) {
    return { phase: "launch-unknown", error: (err as Error).message };
  }
}

const nothingRan = (o: VeloLaunchOutcome): boolean =>
  !o.launched && (o.phase === "invalid" || o.phase === "before-launch");

async function audit(
  deps: WriterDeps,
  caseId: string,
  p: WatsonVeloLaunchProposal,
  actor: string,
  ok: boolean,
) {
  await deps.activity.add(caseId, {
    actor,
    category: "ai",
    action: "watson.apply",
    detail: (ok
      ? `Applied Watson's Velociraptor ${p.mode}: ${p.title}`
      : `Watson's Velociraptor ${p.mode} could not be confirmed (check Velociraptor): ${p.title}`
    ).slice(0, 200),
    targetType: "hunt",
    targetId: p.targetId,
    ...(ok ? {} : { outcome: "error" as const }),
  });
}

/** Apply one velo_launch proposal: launch once, record the ids, or leave it uncertain. */
export async function applyVeloLaunch(
  deps: WriterDeps,
  caseId: string,
  proposalId: string,
  actor = "analyst",
): Promise<{ chat: WatsonChat }> {
  const v = deps.veloLaunch;
  if (!v) throw new WatsonProposalConflict("Velociraptor launches are not configured");
  const { added, proposal: p } = await saveIntent(deps, v, caseId, proposalId, actor); // marks it in flight
  try {
    const outcome = await runLaunch(v, caseId, p, actor);
    return await settle(deps, v, caseId, p, outcome, added, actor);
  } finally {
    clearInFlight(caseId, proposalId);
  }
}

async function settle(
  deps: WriterDeps,
  v: VeloLaunchDeps,
  caseId: string,
  p: WatsonVeloLaunchProposal,
  outcome: VeloLaunchOutcome,
  added: string[],
  actor: string,
): Promise<{ chat: WatsonChat }> {
  const at = new Date().toISOString();
  if (outcome.launched) {
    const launched = { ...outcome.launched, at, by: actor };
    const watch = initialWatch(p, launched, at); // saved WITH the ids: no applied collection goes unwatched
    const chat = await saveOutcome(deps, caseId, p.id, (s) => ({
      ...s,
      status: "applied",
      launched,
      ...(watch ? { watch } : {}),
      appliedAt: at,
      appliedBy: actor,
    }));
    if (watch) v.onLaunched?.(caseId, p.id);
    await audit(deps, caseId, p, actor, true);
    return { chat };
  }
  const why = outcome.error ?? "the launch did not complete";
  if (nothingRan(outcome)) {
    const released = await releaseOrLog(v, caseId, added);
    if (released) {
      await saveOutcome(deps, caseId, p.id, (s) => ({ ...s, status: "pending", launching: undefined }));
      throw new WatsonProposalConflict(`Velociraptor refused the launch, nothing ran: ${why}`);
    }
  }
  await saveOutcome(deps, caseId, p.id, (s) => ({
    ...s,
    status: "uncertain",
    launching: {
      ...(s.launching ?? { at, by: actor, fingerprint: s.fingerprint, reserved: added }),
      error: why,
    },
  }));
  await audit(deps, caseId, p, actor, false);
  throw new WatsonLaunchUncertain(
    `Watson could not confirm the launch (${why}). Check Velociraptor, then mark it launched or try again.`,
  );
}
