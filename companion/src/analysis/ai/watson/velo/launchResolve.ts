import type { ActivityLogStore } from "../../../activityLog.js";
import type { HuntDeployInput } from "../../../huntOutcomes.js";
import type { WatsonChatStore } from "../chatStore.js";
import {
  WatsonProposalConflict,
  WatsonProposalNotFoundError,
  WatsonProposalStateError,
} from "../proposalErrors.js";
import type { WatsonChat, WatsonProposal, WatsonVeloLaunchProposal } from "../types.js";
import type { HuntFingerprintStore } from "./huntFingerprintStore.js";
import { isInFlight } from "./launchInFlight.js";

// The analyst's answer to an uncertain launch (phase 3): "launched" — they checked Velociraptor and it
// ran, so the proposal is applied (no ids: Watson never learned them); "retry" — it did not run, so
// its reserved keys are released FIRST and then it is pending again, to be applied like any other.
// Also the boot sweep: a `launching` proposal no live request owns becomes `uncertain`.

export type LaunchResolution = "launched" | "retry";

export interface LaunchResolveDeps {
  chatStore: WatsonChatStore;
  activity: ActivityLogStore;
  fingerprints: Pick<HuntFingerprintStore, "release">;
  /** Records the hunt outcome of a launch the analyst confirmed (ctx.recordHuntDeploy). */
  recordDeploy?(caseId: string, input: HuntDeployInput): Promise<void>;
}

/** The outcome a confirmed launch records: source watson, the original launch time, no ids. */
export function confirmedLaunchOutcome(p: WatsonVeloLaunchProposal): HuntDeployInput {
  return {
    source: "watson",
    title: p.title,
    vql: p.vql,
    ...(p.hostname ? { hostname: p.hostname } : {}),
    ...(p.mode === "collection" ? { coverage: "snapshot" as const } : {}),
    deployedAt: p.launching?.at || p.appliedAt || new Date().toISOString(),
  };
}

export const STRANDED = "the server stopped before the launch was confirmed";

const stranded = (caseId: string, p: WatsonProposal): p is WatsonVeloLaunchProposal =>
  p.kind === "velo_launch" && p.status === "launching" && !isInFlight(caseId, p.id);

function resolvable(caseId: string, p: WatsonVeloLaunchProposal): boolean {
  return p.status === "uncertain" || stranded(caseId, p);
}

function resolved(
  p: WatsonVeloLaunchProposal,
  outcome: LaunchResolution,
  actor: string,
): WatsonVeloLaunchProposal {
  const at = new Date().toISOString();
  if (outcome === "retry") return { ...p, status: "pending", launching: undefined };
  return { ...p, status: "applied", launched: { at, by: actor }, appliedAt: at, appliedBy: actor };
}

export async function resolveVeloLaunch(
  deps: LaunchResolveDeps,
  caseId: string,
  proposalId: string,
  outcome: LaunchResolution,
  actor = "analyst",
): Promise<{ chat: WatsonChat }> {
  let done: WatsonVeloLaunchProposal | undefined;
  const chat = await deps.chatStore.update(caseId, async (c) => {
    const p = c.proposals.find((x) => x.id === proposalId);
    if (!p) throw new WatsonProposalNotFoundError(proposalId);
    if (p.kind !== "velo_launch") throw new WatsonProposalConflict("not a Velociraptor launch proposal");
    if (!resolvable(caseId, p)) {
      throw new WatsonProposalStateError(
        "apply",
        p.status,
        `Only an uncertain launch can be resolved (${p.status})`,
      );
    }
    if (outcome === "retry") await deps.fingerprints.release(caseId, p.launching?.reserved ?? []);
    done = resolved(p, outcome, actor);
    const next = done;
    return { ...c, proposals: c.proposals.map((x) => (x.id === proposalId ? next : x)) };
  });
  if (done && outcome === "launched") await deps.recordDeploy?.(caseId, confirmedLaunchOutcome(done));
  if (done) {
    const what = outcome === "launched" ? "marked as launched" : "returned to pending to try again";
    await deps.activity.add(caseId, {
      actor,
      category: "hunt",
      action: "watson.resolve",
      detail: `Watson's Velociraptor ${done.mode} ${what}: ${done.title}`.slice(0, 200),
      targetType: "hunt",
      targetId: done.targetId,
    });
  }
  return { chat };
}

/** Boot sweep for one case: stranded `launching` proposals become `uncertain`. Writes only when needed. */
export async function markStrandedLaunches(chatStore: WatsonChatStore, caseId: string): Promise<number> {
  const before = await chatStore.load(caseId);
  if (!before.proposals.some((p) => stranded(caseId, p))) return 0;
  let count = 0;
  await chatStore.update(caseId, (c) => ({
    ...c,
    proposals: c.proposals.map((p) => {
      if (!stranded(caseId, p)) return p;
      count++;
      const launching = p.launching
        ? { ...p.launching, error: STRANDED }
        : { at: "", by: "", fingerprint: p.fingerprint, reserved: [], error: STRANDED };
      return { ...p, status: "uncertain" as const, launching };
    }),
  }));
  return count;
}
