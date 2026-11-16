import type { ActivityLogStore } from "../../activityLog.js";
import type { StateLock } from "../../stateLock.js";
import type { StateStore } from "../../stateStore.js";
import type { WatsonChatStore } from "./chatStore.js";
import type { WatsonProposal } from "./types.js";

// The leaf of the proposal modules: the deps every proposal decision needs and the errors a route
// maps to a status code. proposals.ts re-exports all of it; the writers import it from here so the
// dispatcher and the writers never import each other in a cycle.

export type WatsonProposalAction = "apply" | "reject" | "undo";

export interface WatsonProposalDeps {
  stateStore: StateStore;
  stateLock: StateLock;
  chatStore: WatsonChatStore;
  activity: ActivityLogStore;
}

/** No proposal with that id on this case (route → 404). */
export class WatsonProposalNotFoundError extends Error {
  constructor(proposalId: string) {
    super(`Watson proposal ${proposalId} does not exist`);
    this.name = "WatsonProposalNotFoundError";
  }
}

/** The action is not allowed from the proposal's status (route → 409). */
export class WatsonProposalStateError extends Error {
  constructor(action: WatsonProposalAction | "add", status: WatsonProposal["status"], message?: string) {
    super(
      message ??
        (action === "add"
          ? `This answer is already in the open questions (${status})`
          : `You cannot ${action} a proposal that is ${status}`),
    );
    this.name = "WatsonProposalStateError";
  }
}

/** The stored item changed since the proposal was made or applied; nothing was written (route → 409). */
export class WatsonProposalConflict extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WatsonProposalConflict";
  }
}

/** A Velociraptor launch whose outcome is unknown: the proposal is now `uncertain` (route → 409). */
/** An Auto chain launch found the chain stopped while it saved its intent: it stays pending. */
export class WatsonChainStopped extends Error {
  constructor() {
    super("The analyst stopped the Auto chain.");
    this.name = "WatsonChainStopped";
  }
}

export class WatsonLaunchUncertain extends WatsonProposalConflict {
  constructor(message: string) {
    super(message);
    this.name = "WatsonLaunchUncertain";
  }
}

/** A risky launch applied without the analyst's explicit acceptRisk (Task 9, route → 409 with reasons). */
export class WatsonRiskNotAccepted extends WatsonProposalConflict {
  /** `display` is the STE copy of the reasons (Task 10); a proposal saved before it has only `reasons`. */
  constructor(
    readonly reasons: readonly string[],
    display?: readonly string[],
  ) {
    super(
      display?.length
        ? `This query is risky. ${display.join(" ")} Read the query. Then confirm that you accept the risk to launch it.`
        : `This query is risky (${reasons.join("; ")}). Read it. Then confirm that you accept the risk to launch it.`,
    );
    this.name = "WatsonRiskNotAccepted";
  }
}
