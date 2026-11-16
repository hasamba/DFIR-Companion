import { runWithoutIdentity } from "../../../auth/identityContext.js";
import type { AiControl } from "../../aiControl.js";
import {
  CHAIN_STOPPED_WAIT,
  continueRefusedText,
  type ChainPlace,
  isChainLaunch,
  releaseChainPlace,
  reserveChainPlace,
} from "./autoChain.js";
import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import { WatsonChainStopped, WatsonLaunchUncertain } from "./proposalErrors.js";
import { applyWatsonProposal } from "./proposals.js";
import { stepChange } from "./writers/nextStepUpdateWriter.js";
import { rawEvidenceOf } from "./rawEvidence.js";
import { newWatsonId } from "./roundProposals.js";
import { watsonRunMode } from "./runMode.js";
import type { WatsonCaseEvent, WatsonChat, WatsonProposal, WatsonTurn } from "./types.js";
import type { WriterDeps } from "./writers/writerTypes.js";

// Auto mode (phase 3, user decisions P1/P3). After a round is saved, Watson applies its own
// proposals of THAT round, through the same applyWatsonProposal an analyst's click uses (so the
// status check under the chat lock decides a race: exactly one apply wins).
//
//   - Case writes apply from every round, reaction rounds included (P3).
//   - A single-host collection launches from a round an analyst started (P1, no cap). From a
//     reaction round (Watson's own, for example the one reading its own result) it launches only as
//     a short chain: at most the case's chain limit since the analyst's last message, unless the
//     analyst stopped the chain (autoChain.ts).
//   - A fleet-wide hunt always waits for an analyst, and so does a risky query (Task 9).
//
// The eligible set is the round's Watson-turn proposals, plus held promotions the round carried
// (its shown result events, its paste). Nothing else, ever: no sweep of older pending proposals.
//
// U5 (phase 5): a case write that rests on rows Watson saw in the super-timeline or in a paste waits
// for an analyst, from every round source. Promotions stay automatic: they are evidence, badged and
// undoable. Only the conclusions that cite raw rows are held.

export const WATSON_AUTO_ACTOR = "Watson (Auto)";

/** Where a round came from. Explicit: an unknown source never launches in Auto mode (G12). */
export type WatsonRoundSource = "dashboard" | "slash";

/** The ai-control fields Auto reads: the mode and the persisted who/when of the switch. */
export type WatsonAutoControl = Pick<AiControl, "watsonRunMode" | "watsonAutoSince" | "watsonAutoBy"> & {
  /** The case's AI switch: off stops Auto as surely as a switch to Approve. */
  enabled?: boolean;
  /** The case is closed or archived: Auto does nothing on it (final review G4). */
  frozen?: boolean;
};

const autoOn = (c: WatsonAutoControl | null): boolean =>
  !!c && watsonRunMode(c) === "auto" && c.enabled !== false && !c.frozen;

/** What a round needs to act in Auto mode (route-built: the same seams an analyst's apply uses). */
export interface WatsonAutoDeps {
  /** The case's ai-control, read after the round, so a switch to Approve mid-round is honoured. */
  control(caseId: string): Promise<WatsonAutoControl>;
  writer: WriterDeps;
  onStateChanged?(caseId: string): void;
  /** Start Watson's own next round (a "continue" case event, re-checked by the reactor before it runs). */
  continueLater?(caseId: string, text: string): void;
}

export interface WatsonAutoRound {
  /** The round's Watson turn. */
  turnId: string;
  /** A round Watson started itself (reactor.ts): it launches only within the short chain (autoChain.ts). */
  reaction: boolean;
  /** Where the round came from: only "dashboard" (an analyst's message or paste) may launch (G12). */
  source?: WatsonRoundSource;
  /** Held promotions from the result events the round showed. */
  heldIds?: readonly string[];
  /** The held promotions the round's own paste created. */
  paste?: { pasteId: string; proposalIds: readonly string[] };
  /** The round's stop signal: once aborted, Auto applies nothing more (an action running finishes). */
  signal?: AbortSignal;
  /**
   * Auto keeps going (user goal of 2026-11-16: with no limit, Watson works until no question is open
   * or every remaining step needs a person). true: continue. false: Watson waits (a request, or what it
   * needs from a person, in `waitingFor`). Absent: continue while any Key Question is still open.
   */
  continue?: boolean;
  /** Only with continue false: what Watson needs, and from whom. Shown on a system turn. */
  waitingFor?: string;
}

const ANALYST_STOP_WHY = "An analyst stopped Watson.";

const isHeldPromotion = (p: WatsonProposal): boolean => p.kind === "event_promote" && p.status === "pending";
/** The round's own super-timeline promotion: applied by the round; a stuck one waits for an analyst's Apply. */
const isRoundPromotion = (p: WatsonProposal): boolean =>
  p.kind === "event_promote" && p.source === "supertimeline";

/** U5: a write resting on super-timeline rows (rawEvidenceIds) or on cited paste lines. */
export const isRawCited = (p: WatsonProposal): boolean =>
  rawEvidenceOf(p).length > 0 ||
  ((p.kind === "finding_new" || p.kind === "finding_update") && (p.pasteLineEvents?.length ?? 0) > 0);

export const RAW_CITED_WAIT =
  "Waits for you: it rests on rows Watson saw in the super-timeline or in a paste.";

const ownIds = (chat: WatsonChat, round: WatsonAutoRound): Set<string> =>
  new Set(chat.turns.find((t) => t.id === round.turnId && t.role === "watson")?.proposalIds ?? []);

/** The round's own pending writes that Auto holds because they cite raw rows (U5), in chat order. */
export function rawCitedHeld(chat: WatsonChat, round: WatsonAutoRound): WatsonProposal[] {
  const own = ownIds(chat, round);
  return chat.proposals.filter(
    (p) => p.status === "pending" && own.has(p.id) && p.turnId === round.turnId && isRawCited(p),
  );
}

/** The round's eligible proposals, in chat order. */
export function eligibleProposals(chat: WatsonChat, round: WatsonAutoRound): WatsonProposal[] {
  const own = ownIds(chat, round);
  const held = new Set(round.heldIds ?? []);
  const pasted = new Set(round.paste?.proposalIds ?? []);
  return chat.proposals.filter((p) => {
    if (p.status !== "pending" || isRoundPromotion(p) || isRawCited(p)) return false;
    if (own.has(p.id) && p.turnId === round.turnId) return true;
    if (held.has(p.id)) return isHeldPromotion(p);
    const pasteId = "pasteId" in p ? p.pasteId : undefined;
    return pasted.has(p.id) && isHeldPromotion(p) && !!pasteId && pasteId === round.paste?.pasteId;
  });
}

/** A risky launch waits, in STE; a proposal saved before Task 10 has no display copy. */
const riskyWait = (risk: { reasons: readonly string[]; display?: readonly string[] }): string =>
  risk.display?.length
    ? `It waits for your approval, because the query is risky. ${risk.display.join(" ")}`
    : `It waits for your approval, because the query is risky (${risk.reasons.join("; ")}).`;

/** Why Auto leaves a proposal for an analyst, in full sentences; null when Auto applies it. */
function waitReason(p: WatsonProposal, round: WatsonAutoRound): string | null {
  if (p.kind !== "velo_launch") return null;
  // Task 9: a risky query waits for an analyst in every mode and from every round source.
  if (p.risk) return riskyWait(p.risk);
  if (p.mode !== "collection") return "A fleet-wide hunt always waits for an analyst.";
  if (round.reaction && round.source === undefined) return null; // the chain decides (autoChain.ts)
  if (round.source === "slash")
    return "Watson does not launch from a chat-bot command. Approve it in the Watson panel.";
  if (round.source !== "dashboard")
    return "Watson launches on its own only from a message in the Watson panel. Approve it there.";
  return null;
}

/** The exact text of what Auto did or left: the title/text of a write, the target and VQL of a launch. */
function what(p: WatsonProposal): string {
  switch (p.kind) {
    case "question_new":
      return `new key question "${p.after.question}"${p.after.answer ? `: ${p.after.answer}` : ""}`;
    case "question_update":
      return `key question "${p.after.question}" (${p.after.status}): ${p.after.answer}`;
    case "finding_new":
      return `new finding: ${p.after.title}`;
    case "finding_update":
      return `finding update: ${p.after.title}`;
    case "next_step_new":
      return `next step: ${p.after.action}`;
    case "next_step_update":
      return `${stepChange(p)} (${p.why})`;
    case "report_text":
      return `report text (${p.field === "conclusions" ? "Conclusions" : "Investigation limitations"}): ${p.after}`;
    case "event_promote":
      return p.source === "supertimeline"
        ? `promotion of ${p.events.length} super-timeline row${p.events.length === 1 ? "" : "s"} Watson cited`
        : `promotion of ${p.events.length} held row${p.events.length === 1 ? "" : "s"}`;
    case "velo_launch":
      return p.mode === "collection"
        ? `Velociraptor collection on ${p.hostname ?? "?"}: ${p.title}`
        : `Velociraptor fleet-wide hunt: ${p.title}`;
  }
}

/** One listed action: its line, and the launch's VQL (kept whole, or pointed at — never cut). */
interface Listed {
  line: string;
  vql?: string;
}

const vqlOf = (p: WatsonProposal): string | undefined => (p.kind === "velo_launch" ? p.vql : undefined);

/**
 * The listing as one or more system-turn texts, each within the turn cap, so no action is ever cut
 * off the end. A VQL too long for a turn of its own is pointed at, never cut.
 */
export function listingTurns(by: string, listed: readonly Listed[], allLeft = false): string[] {
  // F8: a listing where Watson applied nothing says so in its heading.
  const lead = allLeft
    ? "Watson left these actions for you in Auto mode."
    : "Watson did these actions in Auto mode.";
  const head = `${lead} ${by.slice(0, 200)} set Auto mode.`;
  const more = "More Auto actions:";
  const turns: string[][] = [[head]];
  let used = head.length;
  const push = (text: string) => {
    if (used + text.length + 1 > WATSON_TURN_TEXT_MAX && turns[turns.length - 1].length > 1) {
      turns.push([more]);
      used = more.length;
    }
    turns[turns.length - 1].push(text);
    used += text.length + 1;
  };
  for (const { line, vql } of listed) {
    const room = WATSON_TURN_TEXT_MAX - Math.max(head.length, more.length) - 1;
    const whole = vql === undefined ? line : `${line}\n  VQL:\n${vql}`;
    const pointer = `${line.slice(0, room - 120)}\n  VQL: ${vql?.length ?? 0} characters. It is too long to repeat here. The launch card shows all of it.`;
    if (whole.length <= room) push(whole);
    else if (vql !== undefined) push(pointer);
    else for (let i = 0; i < line.length; i += room) push(line.slice(i, i + room)); // a long write's text, in parts
  }
  return turns.map((t) => t.join("\n"));
}

/** A proposal Auto leaves for an analyst, with the reason and the launch's VQL. */
function leftLine(p: WatsonProposal, wait: string): Listed {
  const vql = vqlOf(p);
  return {
    line: `- Watson left this for an analyst: ${what(p)}. ${wait}`,
    ...(vql !== undefined ? { vql } : {}),
  };
}

const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err)).slice(0, 300);

/** The activity detail suffix: who switched Auto on and when, from the persisted control. */
export function autoDetail(control: WatsonAutoControl): string {
  const by = control.watsonAutoBy?.name ?? "an unrecorded analyst";
  return `; Auto mode on since ${control.watsonAutoSince ?? "an unrecorded time"}, switched on by ${by}`;
}

async function applyOne(
  deps: WriterDeps,
  caseId: string,
  p: WatsonProposal,
  detailSuffix: string,
  chainPlace?: ChainPlace,
): Promise<Listed & { state: boolean }> {
  const vql = vqlOf(p);
  const listed = (line: string, state = false) => ({ line, state, ...(vql !== undefined ? { vql } : {}) });
  try {
    const r = await runWithoutIdentity(() =>
      applyWatsonProposal(deps, caseId, p.id, "apply", WATSON_AUTO_ACTOR, {
        detailSuffix,
        pendingOnly: true,
        ...(chainPlace !== undefined ? { chained: true } : {}),
      }),
    );
    if (chainPlace !== undefined) {
      const place =
        chainPlace.max === 0
          ? `${chainPlace.place} in a row`
          : `${chainPlace.place} of ${chainPlace.max} in a row`;
      return listed(`- Watson launched this follow-up by itself (${place}): ${what(p)}`, !!r.state);
    }
    const verb = p.kind === "velo_launch" ? "Launched" : "Applied";
    return listed(`- ${verb} ${what(p)}`, !!r.state);
  } catch (err) {
    if (err instanceof WatsonChainStopped)
      return listed(`- Watson left this for an analyst: ${what(p)}. ${CHAIN_STOPPED_WAIT}`);
    if (err instanceof WatsonLaunchUncertain) {
      return listed(
        `- Watson could not confirm the launch of ${what(p)}. Check Velociraptor. Then mark it as launched or try again.`,
      );
    }
    return listed(`- Watson did not apply ${what(p)}: ${errText(err)}. It stays pending.`);
  }
}

/**
 * Apply the round's eligible proposals when the case is in Auto mode, one at a time, then append one
 * system turn listing every action. Never throws for a single proposal: a refused apply stays pending
 * and is listed. Returns the chat as saved (unchanged in Approve mode or when nothing is eligible).
 */
export async function autoApply(
  deps: WriterDeps & {
    onStateChanged?(caseId: string): void;
    /** Re-read before each apply: a switch to Approve (or AI off) stops the rest of the batch. */
    recheck?(): Promise<WatsonAutoControl>;
  },
  caseId: string,
  round: WatsonAutoRound,
  control: WatsonAutoControl,
): Promise<WatsonChat> {
  const chat = await deps.chatStore.load(caseId);
  if (!autoOn(control)) return chat;
  const todo = eligibleProposals(chat, round);
  const rawHeld = rawCitedHeld(chat, round);
  if (!todo.length && !rawHeld.length) return chat;
  const suffix = autoDetail(control);
  const lines: Listed[] = rawHeld.map((p) => ({
    line: `- Watson left this for an analyst: ${what(p)}. ${RAW_CITED_WAIT}`,
  }));
  let stateChanged = false;
  let tried = false;
  let stopped = false;
  let stopReason = "Auto mode is no longer on for this case.";
  for (const p of todo) {
    if (!stopped && round.signal?.aborted) [stopped, stopReason] = [true, ANALYST_STOP_WHY];
    if (!stopped && deps.recheck && !waitReason(p, round)) {
      const now = await deps.recheck().catch(() => null);
      stopped = !autoOn(now);
      if (now?.frozen) stopReason = "Someone closed or archived the case.";
      if (round.signal?.aborted) [stopped, stopReason] = [true, ANALYST_STOP_WHY];
    }
    let wait = stopped ? stopReason : waitReason(p, round);
    const chained = !wait && isChainLaunch(p, round.reaction);
    const reserved = chained ? await reserveChainPlace(deps.chatStore, caseId) : null;
    if (reserved && "wait" in reserved) wait = reserved.wait;
    const place = reserved && "place" in reserved ? reserved : null;
    if (wait) {
      lines.push(leftLine(p, wait));
      continue;
    }
    tried = true;
    const r = await applyOne(deps, caseId, p, suffix, place ?? undefined);
    if (place !== null) await releaseChainPlace(deps.chatStore, caseId, p.id);
    lines.push({ line: r.line, ...(r.vql !== undefined ? { vql: r.vql } : {}) });
    stateChanged ||= r.state;
  }
  if (stateChanged) deps.onStateChanged?.(caseId);
  const by = control.watsonAutoBy?.name ?? "an analyst";
  const at = new Date().toISOString();
  const turns: WatsonTurn[] = listingTurns(by, lines, !tried).map((text) => ({
    id: newWatsonId("wt"),
    at,
    role: "system",
    text,
  }));
  return saveListing(deps.chatStore, caseId, turns);
}

/**
 * Listings whose save failed twice after their applies succeeded (each apply is audited already).
 * Kept in memory and added on the case's next Auto pass, so the chat still tells what Watson did.
 */
const unsavedListings = new Map<string, WatsonTurn[]>();

/** Thrown when a listing could not be saved after one retry; it is kept for the next pass. */
export class WatsonAutoListingUnsaved extends Error {
  constructor(cause: unknown) {
    super(
      `Watson applied its Auto actions, but it could not save their list. Watson keeps the list for the next round: ${errText(cause)}`,
    );
    this.name = "WatsonAutoListingUnsaved";
  }
}

async function saveListing(
  store: WriterDeps["chatStore"],
  caseId: string,
  turns: readonly WatsonTurn[],
): Promise<WatsonChat> {
  const all = [...(unsavedListings.get(caseId) ?? []), ...turns];
  const save = () => store.update(caseId, (c) => ({ ...c, turns: [...c.turns, ...all] }));
  try {
    const chat = await save().catch(() => save()); // one retry
    unsavedListings.delete(caseId);
    return chat;
  } catch (err) {
    unsavedListings.set(caseId, all);
    throw new WatsonAutoListingUnsaved(err);
  }
}

/** Add a listing an earlier pass could not save. A failure keeps it for the pass after. */
async function flushUnsaved(store: WriterDeps["chatStore"], caseId: string): Promise<WatsonChat | null> {
  if (!unsavedListings.has(caseId)) return null;
  return saveListing(store, caseId, []);
}

/**
 * Auto keeps going (user decision of 2026-11-16): when Watson said it can take its next step itself,
 * start its next round, taking a place in the chain. A full or stopped chain leaves a note instead, so
 * the analyst knows why Watson waits. A recheck of the mode and the stop signal comes first.
 */
async function continueIfAsked(
  auto: WatsonAutoDeps,
  caseId: string,
  round: WatsonAutoRound,
  chat: WatsonChat,
): Promise<WatsonChat> {
  if (!auto.continueLater || round.signal?.aborted) return chat;
  if (!autoOn(await auto.control(caseId).catch(() => null))) return chat;
  if (round.continue === false) {
    return round.waitingFor
      ? note(auto, caseId, `Watson stops here and waits for you: ${round.waitingFor}`)
      : chat;
  }
  if (round.continue === undefined && !(await hasOpenQuestion(auto, caseId))) {
    return note(auto, caseId, "Watson stops here: every Key Question is answered or not answerable.");
  }
  const r = await reserveChainPlace(auto.writer.chatStore, caseId);
  if ("place" in r) {
    const of = r.max === 0 ? `step ${r.place}` : `step ${r.place} of ${r.max}`;
    auto.continueLater(caseId, `Watson continues with its next step by itself (Auto chain ${of}).`);
    return chat;
  }
  return note(auto, caseId, continueRefusedText(r));
}

/** A Key Question is open while its status is unknown or partial. A state that cannot be read: open. */
async function hasOpenQuestion(auto: WatsonAutoDeps, caseId: string): Promise<boolean> {
  const state = await auto.writer.stateStore.load(caseId).catch(() => null);
  if (!state) return true;
  return (state.keyQuestions ?? []).some((q) => q.status !== "answered" && q.status !== "unanswerable");
}

/** One system turn on the chat (text cut to the turn limit). */
function note(auto: WatsonAutoDeps, caseId: string, text: string): Promise<WatsonChat> {
  const turn: WatsonTurn = {
    id: newWatsonId("wt"),
    at: new Date().toISOString(),
    role: "system",
    text: text.slice(0, WATSON_TURN_TEXT_MAX),
  };
  return auto.writer.chatStore.update(caseId, (c) => ({ ...c, turns: [...c.turns, turn] }));
}

/** The held promotions a reaction carries: ids the reactor passed AND the result events it showed. */
export function carriedHeldIds(
  reaction: boolean,
  passed: readonly string[] | undefined,
  shown: readonly WatsonCaseEvent[],
): string[] {
  if (!reaction || !passed?.length) return [];
  const onShown = new Set(shown.flatMap((e) => (e.kind === "hunt" ? (e.proposalIds ?? []) : [])));
  return passed.filter((id) => onShown.has(id));
}

/**
 * Auto after a saved round (round.ts). Reads the control now, so a switch to Approve during the model
 * call is honoured. A failure here never fails the saved round: it is logged and the chat returned.
 */
export async function autoAfterRound(
  auto: WatsonAutoDeps,
  caseId: string,
  round: WatsonAutoRound,
  saved: WatsonChat,
  warn: (line: string) => void,
): Promise<WatsonChat> {
  try {
    const flushed = await flushUnsaved(auto.writer.chatStore, caseId); // whatever the mode is now
    const control = await auto.control(caseId);
    if (round.signal?.aborted || !autoOn(control)) return flushed ?? saved;
    const deps = { ...auto.writer, onStateChanged: auto.onStateChanged, recheck: () => auto.control(caseId) };
    const applied = await autoApply(deps, caseId, round, control);
    return await continueIfAsked(auto, caseId, round, applied);
  } catch (err) {
    warn(`Watson Auto mode could not act: ${errText(err)}`);
    return saved;
  }
}
