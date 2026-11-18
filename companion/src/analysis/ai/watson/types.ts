import type { WatsonMaskRoster } from "./superRoster.js";
import type {
  Finding,
  ForensicEvent,
  InvestigationQuestion,
  NextStep,
  QuestionStatus,
  Severity,
} from "../../stateTypes.js";
import type { WatsonReviewAction } from "../../watsonItemTypes.js";

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
    }
  /** #2666: run a CQL search on the case's CrowdStrike Next-Gen SIEM (only when its client is set up). */
  | {
      kind: "crowdstrike_search";
      title: string;
      query: string;
      /** ISO 8601; both absent = the last N days (the window cap). */
      start?: string;
      end?: string;
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

/**
 * One forensic-timeline lookup Watson asked for (Task 11). Id lists union; the window, host and text
 * narrow. Checked by lookupSchema.ts before it is run.
 */
export interface WatsonLookup {
  findingIds?: string[];
  eventIds?: string[];
  /** ISO timestamps; both or neither, at most 7 days apart. */
  from?: string;
  to?: string;
  host?: string;
  text?: string;
  /** Absent = the forensic timeline; "supertimeline" = a targeted search of the analyst-only super-timeline. */
  source?: "supertimeline";
  /** MD5, SHA-1 or SHA-256 hex; super-timeline searches only. */
  hash?: string;
}

/** What a round's lookup showed Watson, stored on its turn so the card can disclose it (#452). */
export interface WatsonLookedUp {
  shown: number;
  matched: number;
  /** The lookup in plain words (server-built from the checked request). */
  what: string;
  source?: "supertimeline" | "paste" | "history";
  /** The match count is a lower bound: the search stopped counting at its scan limit. */
  matchedIsFloor?: boolean;
  /** Rows evicted by the search's result cap. */
  capEvicted?: number;
  /** Ids of the rows the search showed (at most 100); the earlier-round check reads them. */
  shownIds?: string[];
}

/** Watson's answer to a free-form question from the analyst (what Ask used to return). */
export interface WatsonAnswer {
  question: string;
  status: QuestionStatus;
  answer: string;
  pointer: string;
  /** Forensic-timeline event ids the answer cites, already checked against the case. */
  relatedEventIds: string[];
  /** The id of the key question on the board that asks the same thing; checked against the case. */
  matchesQuestionId?: string;
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
  /** #2663: all input this round's model calls read, and how much of it came from the provider's cache. */
  inputTokens?: number;
  cacheReadTokens?: number;
  coverage?: WatsonCoverage;
  answer?: WatsonAnswer;
  /** The proposal made when the analyst added this turn's answer to the open questions. */
  answerProposalId?: string;
  /** H1: the canonical ids of promoted super-timeline rows the answer rests on. Set only by the server. */
  answerRawEvidenceIds?: string[];
  /**
   * The server's Velociraptor launch note ("Nothing to approve: …" / "Risky query: …"), also appended
   * to `text`. Set only by the server, so the dashboard's warning block cannot be forged by the model.
   */
  veloNote?: string;
  /** The forensic-timeline events this turn's lookup showed Watson. Set only by the server. */
  lookedUp?: WatsonLookedUp;
  /** Tool mode: every lookup the round made, in order (also on an error turn). Set only by the server. */
  lookups?: WatsonLookedUp[];
  /** Tool mode: Watson asked for a super-timeline search past the 2-search limit. Set only by the server. */
  superCapHit?: boolean;
  /** The super-timeline search limit that `superCapHit` refers to, so the card never hardcodes it. */
  superCapLimit?: number;
}

/**
 * `launching` / `uncertain` are velo_launch only: the launch intent is saved before the Velociraptor
 * call (launching); a launch whose outcome is unknown (the call failed after it may have reached the
 * server, or the server stopped mid-launch) is `uncertain` and waits for the analyst — never retried.
 */
export type WatsonProposalStatus = "pending" | "applied" | "rejected" | "undone" | "launching" | "uncertain";

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
 * The canonical forensic ids of super-timeline rows Watson promoted that this item rests on (D9b):
 * its apply is refused once one is gone, and the promotion's undo is refused while it is applied.
 */
export interface WatsonRawEvidence {
  rawEvidenceIds?: string[];
}

/**
 * Phase 1 shape, unchanged so an old chat file loads as it was: the target is `questionId`.
 * `targetId` is optional here only; read the target through proposalTargetId().
 */
export interface WatsonQuestionProposal extends WatsonProposalCommon, WatsonRawEvidence {
  kind: "question_update" | "question_new";
  questionId: string;
  targetId?: string;
  before?: InvestigationQuestion;
  after: InvestigationQuestion;
}

/** A finding Watson drafted. On apply, `after` becomes the finding as written (live citations only). */
export interface WatsonFindingProposal extends WatsonProposalCommon, WatsonCreatedRows, WatsonRawEvidence {
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

export interface WatsonNextStepProposal extends WatsonProposalCommon, WatsonRawEvidence {
  kind: "next_step_new";
  targetId: string;
  after: NextStep;
}

/**
 * A change to a next step already in the case (user decision of 2026-11-16). `after` null marks it
 * done: it leaves the list, and undo puts `before` back at `index`. Otherwise `after` is the step with
 * the new priority. Apply and undo refuse when someone changed the step in between.
 */
export interface WatsonNextStepUpdateProposal extends WatsonProposalCommon, WatsonRawEvidence {
  kind: "next_step_update";
  targetId: string;
  before: NextStep;
  after: NextStep | null;
  why: string;
  index: number;
}

/**
 * #2682: Watson's verdict on a finding synthesis wrote (never one Watson or the analyst wrote): a
 * lower severity, or dismissed, with the reason and the forensic events that disprove it. `before`
 * is the finding as Watson read it; apply refuses when it changed. On apply the case keeps the
 * verdict under `key`, so later synthesis runs apply it again (timeline/watsonVerdicts.ts).
 */
export interface WatsonFindingReviewProposal extends WatsonProposalCommon, WatsonRawEvidence {
  kind: "finding_review";
  targetId: string;
  action: WatsonReviewAction;
  /** demote only: the lower severity. */
  severity?: Severity;
  why: string;
  eventIds: string[];
  before: Finding;
  /** Set on apply: the verdict's key in the case. */
  key?: string;
}

export interface WatsonReportTextProposal extends WatsonProposalCommon, WatsonRawEvidence {
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

/**
 * Rows of a parsed paste the content tagger graded above Info, held for the analyst (spec §14), or
 * (`source: "supertimeline"`) the super-timeline rows Watson cited, promoted by the round itself.
 */
export interface WatsonEventPromoteProposal extends WatsonProposalCommon, WatsonCreatedRows {
  kind: "event_promote";
  targetId: string;
  /** The raised copies, kept after undo so a re-apply needs nothing else. */
  events: ForensicEvent[];
  /** The paste the rows came from; absent for a super-timeline promotion. */
  pasteId?: string;
  source?: "supertimeline";
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
  /** `serverSetId`: the server set the launch went to; its results are read from that set (G6). */
  launched?: {
    huntId?: string;
    clientId?: string;
    flowId?: string;
    serverSetId?: string;
    at: string;
    by: string;
    /** The analyst launched it despite Watson's risk warning (Task 9). */
    riskAccepted?: WatsonRiskAccepted;
  };
  /** The query failed only RISKY rules (vqlRiskClass.ts): it waits for an analyst, never Auto (Task 9). */
  risk?: WatsonLaunchRisk;
  /** The launch intent, saved before the call: `reserved` is exactly what a retry may release. */
  launching?: WatsonLaunchIntent;
  /** The analyst who confirmed an uncertain launch ran ("Mark as launched"); `launched.by` stays the launcher (G10). */
  resolvedBy?: string;
  /** View-only (never stored): `launching`, but no live request owns it — the card offers the uncertain actions (G11). */
  stalled?: true;
  /** Watson reading the result back (Task 5): a collection's watch, or a fleet hunt's one note. */
  watch?: WatsonLaunchWatch;
}

/**
 * Reading a launch's result back. `ingested` is claimed BEFORE the rows are read and `notified` is
 * set with the `hunt` event, each inside one chat update, so neither ever happens twice. `rows`,
 * `added` and `proposalIds` are saved with the ingest so a restart can still send the event.
 */
export interface WatsonLaunchWatch {
  deadline: string;
  state: "watching" | "finished" | "failed" | "timeout";
  ingested?: true;
  /** Set just before the ingest is called: a restart that finds it knows rows may be in the case. */
  ingesting?: true;
  notified?: true;
  rows?: number;
  /** The read was cut by the collection row cap; `total` is what Velociraptor counted (0 = unknown). */
  truncated?: true;
  total?: number;
  added?: number;
  proposalIds?: string[];
  error?: string;
}

/** `reasons` is plain English for the warning; `checks` the raw reasons a recheck must stay within. */
export interface WatsonLaunchRisk {
  reasons: string[];
  checks: string[];
  /** The checks as ASD-STE100 sentences, for display only (Task 10). Older proposals have none. */
  display?: string[];
}

/** Who launched a risky query despite the warning, and the reasons they saw. */
export interface WatsonRiskAccepted {
  by: string;
  at: string;
  reasons: string[];
}

export interface WatsonLaunchIntent {
  at: string;
  by: string;
  fingerprint: string;
  /** The keys the launch will reserve, saved BEFORE the reservation (final review G5). */
  planned?: string[];
  reserved: string[];
  /** Why the launch became uncertain. */
  error?: string;
  /** Set when an analyst approved a risky query with acceptRisk (Task 9). */
  riskAccepted?: WatsonRiskAccepted;
}

/**
 * #2666: a CrowdStrike Next-Gen SIEM search Watson wants to run. Built only after its launch check
 * passed (crowdstrike/csLaunchCheck.ts). Running it starts the same `siem-search` job as the
 * analyst's Run on a CQL hunt; the rows are imported as evidence. The search ran, so no undo.
 */
export interface WatsonCsSearchProposal extends WatsonProposalCommon {
  kind: "cs_search";
  /** The fingerprint key (query + repository + range): a repeat is refused. */
  targetId: string;
  title: string;
  /** Run byte-for-byte as shown on the card. */
  query: string;
  start: string;
  end: string;
  /** The repository the check used; the run is refused when Settings changed it since. */
  repository: string;
  launched?: { jobId: string; at: string; by: string };
  /** The search's outcome, saved with its case event (`notified` is set once). */
  watch?: WatsonCsSearchWatch;
}

export interface WatsonCsSearchWatch {
  state: "running" | "finished" | "failed";
  rows?: number;
  added?: number;
  truncated?: true;
  /** The outcome sentence (analysis/siemSearch.ts siemSearchText). */
  text?: string;
  notified?: true;
}

export type WatsonProposal =
  | WatsonQuestionProposal
  | WatsonFindingProposal
  | WatsonNextStepProposal
  | WatsonNextStepUpdateProposal
  | WatsonFindingReviewProposal
  | WatsonReportTextProposal
  | WatsonEventPromoteProposal
  | WatsonVeloLaunchProposal
  | WatsonCsSearchProposal;

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
  /** "continue": Watson's own next round in Auto mode (autoApply.ts), re-checked before it runs. */
  kind: "import" | "notebook" | "star" | "hunt" | "other" | "continue";
  text: string;
  at: string;
  /** A `hunt` event: the held-promotion proposals its result created (Auto may apply them). */
  proposalIds?: string[];
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
  /**
   * Collections Auto launched from Watson's own rounds since the analyst's last message (autoChain.ts).
   * Cleared by an analyst message; at the chain limit, reaction rounds launch nothing more.
   */
  autoChainLaunches?: number;
  /** The case's Auto chain limit, set in the Watson panel: 0..50, 0 = no limit (default 3). Kept. */
  autoChainMax?: number;
  /** The analyst pressed Stop chain: no chained launch until the analyst's next message. */
  autoChainStopped?: boolean;
  /** Watson's own rounds in a row with no progress: at the limit, Auto sets the item aside (autoProgress.ts). */
  autoIdleRounds?: number;
  /** Keys of the searches and lookups Watson ran since the analyst's last message (autoProgress.ts). */
  autoSearchesRun?: string[];
  /** The items the current idle streak worked on: a round on another item starts a new streak. */
  autoIdleFocus?: string[];
  /** Key Question and next-step ids Auto set aside since the analyst's last message (autoProgress.ts). */
  autoSetAside?: string[];
  costUSD: number;
  /** Input + output tokens Watson used on this case: the limit for providers that report no cost. */
  tokens: number;
  calls: number;
  /** ISO time of the last "New thread": RECENT CHAT in the prompt starts here. Memory is kept. */
  threadStartAt?: string;
  /**
   * Names Watson's super-timeline searches showed it (raw-only hosts, users, IPs). Every later AI call
   * on the case masks them (H3), since a restored reply can carry them into memory, chat and applied
   * items (D2d). A host or user is never evicted (H5). Case-private.
   */
  maskRoster?: WatsonMaskRoster;
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
