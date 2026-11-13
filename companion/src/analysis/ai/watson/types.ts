import type { InvestigationQuestion } from "../../stateTypes.js";

// Watson: the per-case AI investigation chat agent. These types describe the persisted chat
// (state/watson-chat.json). Chat text and pasted content may carry adversary-controlled strings,
// so every consumer must escape on render.

export type WatsonRequest =
  | { kind: "query"; language: string; query: string; why: string }
  | { kind: "import"; what: string; why: string };

export interface WatsonTurn {
  id: string;
  at: string;
  role: "analyst" | "watson" | "system";
  text: string;
  actor?: string;
  workingOn?: string;
  learned?: string;
  request?: WatsonRequest;
  proposalIds?: string[];
  pasteId?: string;
  error?: boolean;
  costUSD?: number;
}

export interface WatsonProposal {
  id: string;
  turnId: string;
  kind: "question_update" | "question_new";
  questionId: string;
  before?: InvestigationQuestion;
  after: InvestigationQuestion;
  status: "pending" | "applied" | "rejected" | "undone";
}

export interface WatsonPaste {
  id: string;
  storedName: string;
  filename: string;
  bytes: number;
  lines: number;
  at: string;
}

export interface WatsonChat {
  turns: WatsonTurn[];
  proposals: WatsonProposal[];
  pastes: WatsonPaste[];
  memory: string;
  pendingCaseEvents: string[];
  costUSD: number;
  /** Input + output tokens Watson used on this case: the limit for providers that report no cost. */
  tokens: number;
  calls: number;
}

export function emptyWatsonChat(): WatsonChat {
  return {
    turns: [],
    proposals: [],
    pastes: [],
    memory: "",
    pendingCaseEvents: [],
    costUSD: 0,
    tokens: 0,
    calls: 0,
  };
}
