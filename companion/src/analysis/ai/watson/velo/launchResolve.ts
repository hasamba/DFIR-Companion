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
  // Who launched it stays who launched it (an Auto launch stays "Watson (Auto)"); the analyst who
  // confirmed it is recorded apart (G10).
  const by = p.launching?.by || actor;
  const launchedAt = p.launching?.at || at;
  return {
    ...p,
    status: "applied",
    launched: { at: launchedAt, by },
    appliedAt: launchedAt,
    appliedBy: by,
    resolvedBy: actor,
  };
}

/** The chat as the dashboard sees it: a `launching` launch no live request owns is flagged (G11). */
export function withStalledLaunches(caseId: string, chat: WatsonChat): WatsonChat {
  if (!chat.proposals.some((p) => stranded(caseId, p))) return chat;
  return {
    ...chat,
    proposals: chat.proposals.map((p) => (stranded(caseId, p) ? { ...p, stalled: true as const } : p)),
  };
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
  // After the audit (G17): a failed outcome record never leaves the resolve unaudited.
  if (done && outcome === "launched") await recordConfirmed(deps, caseId, done, actor);
  return { chat };
}

async function recordConfirmed(
  deps: LaunchResolveDeps,
  caseId: string,
  p: WatsonVeloLaunchProposal,
  actor: string,
): Promise<void> {
  try {
    await deps.recordDeploy?.(caseId, confirmedLaunchOutcome(p));
  } catch (err) {
    await deps.activity.add(caseId, {
      actor,
      category: "hunt",
      action: "watson.resolve",
      detail: `The hunt outcome of Watson's ${p.mode} could not be recorded: ${(err as Error).message}`.slice(
        0,
        200,
      ),
      targetType: "hunt",
      targetId: p.targetId,
      outcome: "error",
    });
  }
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
