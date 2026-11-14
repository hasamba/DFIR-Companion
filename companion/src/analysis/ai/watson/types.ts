import type {
  Finding,
  ForensicEvent,
  InvestigationQuestion,
  NextStep,
  QuestionStatus,
} from "../../stateTypes.js";

// Watson: the per-case AI investigation chat agent. These types describe the persisted chat
// (state/watson-chat.json). Chat text and pasted content may carry adversary-controlled strings,
// so every consumer must escape on render.

export type WatsonRequest =
  | { kind: "query"; language: string; query: string; why: string }
  | { kind: "import"; what: string; why: string }
  /** Run VQL on the case's Velociraptor: a fleet hunt, or a collection on one host. */
  | {
      kind: "velociraptor";
      mode: "hunt" | "collection";
      hostname?: string;
      title: string;
      vql: string;
      why: string;
    };

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

export type WatsonProposalStatus = "pending" | "applied" | "rejected" | "undone";

/** Fields every proposal kind carries. `appliedBy`/`appliedAt` are stamped when an analyst applies it. */
interface WatsonProposalCommon {
  id: string;
  turnId: string;
  status: WatsonProposalStatus;
  appliedBy?: string;
  appliedAt?: string;
}

/** What an applied proposal wrote into the forensic timeline: undo removes exactly these rows. */
export interface WatsonCreatedRows {
  /** Rows the apply appended (they did not exist before). A row that existed is never in here. */
  createdEventIds?: string[];
  /** The `promotedAt` stamp the apply put on those rows; undo refuses a row that lost it. */
  promotedAt?: string;
}

/**
 * Phase 1 shape, unchanged so an old chat file loads as it was: the target is `questionId`.
 * `targetId` is optional here only; read the target through proposalTargetId().
 */
export interface WatsonQuestionProposal extends WatsonProposalCommon {
  kind: "question_update" | "question_new";
  questionId: string;
  targetId?: string;
  before?: InvestigationQuestion;
  after: InvestigationQuestion;
}

/** A finding Watson drafted. On apply, `after` becomes the finding as written (live citations only). */
export interface WatsonFindingProposal extends WatsonProposalCommon, WatsonCreatedRows {
  kind: "finding_new" | "finding_update";
  targetId: string;
  /** finding_update only: the Watson-authored finding as it was when Watson proposed the change. */
  before?: Finding;
  after: Finding;
  /** One event per cited paste line, built when proposed; appended on apply if not already there. */
  pasteLineEvents: ForensicEvent[];
  /** Set on undo: rows the apply created that stayed because other findings cite them. */
  keptEventIds?: string[];
}

export interface WatsonNextStepProposal extends WatsonProposalCommon {
  kind: "next_step_new";
  targetId: string;
  after: NextStep;
}

export interface WatsonReportTextProposal extends WatsonProposalCommon {
  kind: "report_text";
  targetId: string;
  field: "conclusions" | "investigationLimitations";
  before: string;
  after: string;
}

/** A promoted row as it landed (lab normalisation or a name carry may change it): undo compares these. */
export interface WatsonLandedRow {
  id: string;
  severity: ForensicEvent["severity"];
  description: string;
}

/** Rows of a parsed paste the content tagger graded above Info, held for the analyst (spec §14). */
export interface WatsonEventPromoteProposal extends WatsonProposalCommon, WatsonCreatedRows {
  kind: "event_promote";
  targetId: string;
  /** The raised copies, kept after undo so a re-apply needs nothing else. */
  events: ForensicEvent[];
  pasteId: string;
  /** Set on apply: the rows this proposal added, as they landed. */
  landedRows?: WatsonLandedRow[];
}

/**
 * A Velociraptor hunt or single-host collection Watson wants to run. Built only after checkLaunch
 * passed; `fingerprints` is the exact list a launch reserves, and `targetId` is the first of them.
 * Launching an endpoint cannot be undone, so the proposal has no undo.
 */
export interface WatsonVeloLaunchProposal extends WatsonProposalCommon {
  kind: "velo_launch";
  targetId: string;
  mode: "hunt" | "collection";
  /** The inventory's name for the host (collection only). */
  hostname?: string;
  title: string;
  vql: string;
  fingerprint: string;
  fingerprints: string[];
  launched?: { huntId?: string; clientId?: string; flowId?: string; at: string; by: string };
}

export type WatsonProposal =
  | WatsonQuestionProposal
  | WatsonFindingProposal
  | WatsonNextStepProposal
  | WatsonReportTextProposal
  | WatsonEventPromoteProposal
  | WatsonVeloLaunchProposal;

export type WatsonProposalKind = WatsonProposal["kind"];

export const isQuestionProposal = (p: WatsonProposal): p is WatsonQuestionProposal =>
  p.kind === "question_new" || p.kind === "question_update";

/** The item a proposal targets: question id, finding id, step id, report field or first event id. */
export const proposalTargetId = (p: WatsonProposal): string =>
  isQuestionProposal(p) ? (p.targetId ?? p.questionId) : p.targetId;

/** What parsing a paste did: rows from a known format, or why it stayed searchable text. */
export type WatsonPasteParsed =
  { kind: string; rows: number; held: number } | { kind: "text"; reason: string };

export interface WatsonPaste {
  id: string;
  storedName: string;
  filename: string;
  bytes: number;
  lines: number;
  at: string;
  parsed?: WatsonPasteParsed;
}

/** Something that changed in the case since Watson's last round (spec §4.6). */
export interface WatsonCaseEvent {
  kind: "import" | "notebook" | "star" | "other";
  text: string;
  at: string;
}

/** Why automatic reactions stopped; the next analyst message clears it. */
export type WatsonReactionsPaused = "presidio" | "limit" | "errors";

export interface WatsonChat {
  turns: WatsonTurn[];
  proposals: WatsonProposal[];
  pastes: WatsonPaste[];
  /** Pastes no successful round has read yet, oldest first. The next round attaches the newest. */
  unreadPasteIds: string[];
  memory: string;
  pendingCaseEvents: WatsonCaseEvent[];
  /** Set when an automatic reaction hit a Presidio hold or a cost/token limit. */
  reactionsPaused?: WatsonReactionsPaused;
  /** Reaction rounds that failed in a row (reset by a success or an analyst message). */
  reactionFailures?: number;
  /** An analyst has messaged Watson on this case; survives the turn cap (reactions need it). */
  analystEngaged?: boolean;
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
