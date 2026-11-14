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
    super(`No Watson proposal ${proposalId}`);
    this.name = "WatsonProposalNotFoundError";
  }
}

/** The action is not allowed from the proposal's status (route → 409). */
export class WatsonProposalStateError extends Error {
  constructor(action: WatsonProposalAction | "add", status: WatsonProposal["status"], message?: string) {
    super(
      message ??
        (action === "add"
          ? `This answer was already added to the open questions (${status})`
          : `Cannot ${action} a proposal that is ${status}`),
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
export class WatsonLaunchUncertain extends WatsonProposalConflict {
  constructor(message: string) {
    super(message);
    this.name = "WatsonLaunchUncertain";
  }
}

/** A risky launch applied without the analyst's explicit acceptRisk (Task 9, route → 409 with reasons). */
export class WatsonRiskNotAccepted extends WatsonProposalConflict {
  constructor(readonly reasons: readonly string[]) {
    super(
      `This is a risky query (${reasons.join("; ")}). Read it, then confirm you accept the risk to launch it.`,
    );
    this.name = "WatsonRiskNotAccepted";
  }
}
