import type { InvestigationQuestion, QuestionStatus } from "../../stateTypes.js";

// Watson: the per-case AI investigation chat agent. These types describe the persisted chat
// (state/watson-chat.json). Chat text and pasted content may carry adversary-controlled strings,
// so every consumer must escape on render.

export type WatsonRequest =
  | { kind: "query"; language: string; query: string; why: string }
  | { kind: "import"; what: string; why: string };

/** How much of the in-scope forensic timeline a round carried; stored only when it was trimmed. */
export interface WatsonCoverage {
  usedEvents: number;
  eventCount: number;
  /** The analyst's decisions (hypotheses, host scope, marks, notebook) were cut to fit. */
  decisionsTrimmed?: boolean;
  /** The synthesis context, graph and findings were cut to fit. */
  headTrimmed?: boolean;
}

/** Watson's answer to a free-form question from the analyst (what Ask used to return). */
export interface WatsonAnswer {
  question: string;
  status: QuestionStatus;
  answer: string;
  pointer: string;
  /** Forensic-timeline event ids the answer cites, already checked against the case. */
  relatedEventIds: string[];
}

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
  coverage?: WatsonCoverage;
  answer?: WatsonAnswer;
  /** The proposal made when the analyst added this turn's answer to the open questions. */
  answerProposalId?: string;
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
  /** Pastes no successful round has read yet, oldest first. The next round attaches the newest. */
  unreadPasteIds: string[];
  memory: string;
  pendingCaseEvents: string[];
  costUSD: number;
  /** Input + output tokens Watson used on this case: the limit for providers that report no cost. */
  tokens: number;
  calls: number;
  /** ISO time of the last "New thread": RECENT CHAT in the prompt starts here. Memory is kept. */
  threadStartAt?: string;
}

export function emptyWatsonChat(): WatsonChat {
  return {
    turns: [],
    proposals: [],
    pastes: [],
    unreadPasteIds: [],
    memory: "",
    pendingCaseEvents: [],
    costUSD: 0,
    tokens: 0,
    calls: 0,
  };
}
