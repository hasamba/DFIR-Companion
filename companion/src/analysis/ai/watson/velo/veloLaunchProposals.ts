import type { CaseStore } from "../../../../storage/caseStore.js";
import type { Outcome } from "../roundOutcome.js";
import { newWatsonId } from "../roundProposals.js";
import type { WatsonChat, WatsonRequest, WatsonVeloLaunchProposal } from "../types.js";
import { fingerprintStoreFor } from "./fingerprintIndex.js";
import { checkLaunch, type LaunchClient, type LaunchContext } from "./launchCheck.js";
import { loadVeloFleet, type VeloFleetSeams } from "./veloFleet.js";

// Turns the reply's Velociraptor request into a PENDING velo_launch proposal (launching is the
// analyst's approval, a later step). Every request passes checkLaunch first: risky VQL, a re-run, or
// an unknown host never becomes a proposal and the Watson turn says why (P2). Nothing here reaches a
// server or an endpoint.

type VeloRequest = Extract<WatsonRequest, { kind: "velociraptor" }>;

export interface VeloLaunchSeams extends VeloFleetSeams {
  cases: CaseStore;
  chatStore: { load(caseId: string): Promise<WatsonChat> };
  /** The inventory host matcher, injected (analysis/ai may not import integrations). */
  matchClient?: LaunchContext["matchClient"];
}

const NOTE_MAX = 600;
const TITLE_MAX = 200;
const oneLine = (s: string): string => s.replace(/\s+/g, " ").trim();

const wanted = (r: VeloRequest): string => `Watson wanted to run a ${r.mode} but`;
const skipped = (r: VeloRequest, why: string): string =>
  oneLine(`(${wanted(r)} ${why}, so it proposed nothing.)`).slice(0, NOTE_MAX);

/** The reason a failed check gives, in a sentence: a blocked request names the calls. */
function reasonText(reason: string, reasons?: string[]): string {
  return reasons?.length ? `it was blocked: ${reasons.join("; ")}` : reason;
}

async function check(
  seams: VeloLaunchSeams,
  caseId: string,
  r: VeloRequest,
  inventory: readonly LaunchClient[],
) {
  if (!seams.matchClient) return { ok: false as const, reason: "the host matcher is not available" };
  const deployed = await fingerprintStoreFor(seams.cases).load(caseId);
  const input = { vql: r.vql, mode: r.mode, ...(r.hostname ? { hostname: r.hostname } : {}) };
  return checkLaunch(input, { inventory, deployed, matchClient: seams.matchClient });
}

/**
 * The outcome carrying its launch proposal or a turn note. With `allowed` false (a round that may
 * not write) the request is dropped silently. Never throws: a failed read becomes a note.
 */
export async function withVeloLaunch(
  seams: VeloLaunchSeams,
  caseId: string,
  outcome: Outcome,
  allowed: boolean,
): Promise<Outcome> {
  const r = outcome.reply?.request;
  if (!r || r.kind !== "velociraptor" || !allowed) return outcome;
  try {
    const fleet = await loadVeloFleet(seams, caseId);
    if (!fleet) return { ...outcome, veloNote: skipped(r, "this case has no Velociraptor server") };
    const result = await check(seams, caseId, r, fleet.records);
    if (!result.ok) {
      const why = reasonText(result.reason, "reasons" in result ? result.reasons : undefined);
      return { ...outcome, veloNote: skipped(r, why) };
    }
    const fingerprints = result.fingerprints;
    const open = (await seams.chatStore.load(caseId)).proposals.some(
      (p) => p.kind === "velo_launch" && p.status === "pending" && p.targetId === fingerprints[0],
    );
    if (open) return { ...outcome, veloNote: skipped(r, "an identical launch is already proposed") };
    const proposal: Omit<WatsonVeloLaunchProposal, "turnId"> = {
      id: newWatsonId("wp"),
      kind: "velo_launch",
      status: "pending",
      targetId: fingerprints[0],
      mode: result.mode,
      ...(result.clientHost ? { hostname: result.clientHost } : {}),
      title: oneLine(r.title).slice(0, TITLE_MAX),
      vql: r.vql,
      fingerprint: result.fingerprint,
      fingerprints,
    };
    return { ...outcome, veloProposal: proposal };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ...outcome, veloNote: skipped(r, `the checks could not run (${msg})`) };
  }
}
