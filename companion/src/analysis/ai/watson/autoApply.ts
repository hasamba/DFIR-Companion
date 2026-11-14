import { runWithoutIdentity } from "../../../auth/identityContext.js";
import type { AiControl } from "../../aiControl.js";
import { WATSON_TURN_TEXT_MAX } from "./chatStore.js";
import { WatsonLaunchUncertain } from "./proposalErrors.js";
import { applyWatsonProposal } from "./proposals.js";
import { newWatsonId } from "./roundProposals.js";
import { watsonRunMode } from "./runMode.js";
import type { WatsonCaseEvent, WatsonChat, WatsonProposal, WatsonTurn } from "./types.js";
import type { WriterDeps } from "./writers/writerTypes.js";

// Auto mode (phase 3, user decisions P1/P3). After a round is saved, Watson applies its own
// proposals of THAT round, through the same applyWatsonProposal an analyst's click uses (so the
// status check under the chat lock decides a race: exactly one apply wins).
//
//   - Case writes apply from every round, reaction rounds included (P3).
//   - A single-host collection launches only from a round an analyst started (P1, no cap). A
//     reaction round — Watson's own, including the one reading its own result — never launches.
//   - A fleet-wide hunt always waits for an analyst.
//
// The eligible set is the round's Watson-turn proposals, plus held promotions the round carried
// (its shown result events, its paste). Nothing else, ever: no sweep of older pending proposals.

export const WATSON_AUTO_ACTOR = "Watson (Auto)";

/** The ai-control fields Auto reads: the mode and the persisted who/when of the switch. */
export type WatsonAutoControl = Pick<AiControl, "watsonRunMode" | "watsonAutoSince" | "watsonAutoBy">;

/** What a round needs to act in Auto mode (route-built: the same seams an analyst's apply uses). */
export interface WatsonAutoDeps {
  /** The case's ai-control, read after the round, so a switch to Approve mid-round is honoured. */
  control(caseId: string): Promise<WatsonAutoControl>;
  writer: WriterDeps;
  onStateChanged?(caseId: string): void;
}

export interface WatsonAutoRound {
  /** The round's Watson turn. */
  turnId: string;
  /** A round Watson started itself (reactor.ts): it never launches. */
  reaction: boolean;
  /** Held promotions from the result events the round showed. */
  heldIds?: readonly string[];
  /** The held promotions the round's own paste created. */
  paste?: { pasteId: string; proposalIds: readonly string[] };
}

const isHeldPromotion = (p: WatsonProposal): boolean => p.kind === "event_promote" && p.status === "pending";

/** The round's eligible proposals, in chat order. */
export function eligibleProposals(chat: WatsonChat, round: WatsonAutoRound): WatsonProposal[] {
  const turn = chat.turns.find((t) => t.id === round.turnId && t.role === "watson");
  const own = new Set(turn?.proposalIds ?? []);
  const held = new Set(round.heldIds ?? []);
  const pasted = new Set(round.paste?.proposalIds ?? []);
  return chat.proposals.filter((p) => {
    if (p.status !== "pending") return false;
    if (own.has(p.id) && p.turnId === round.turnId) return true;
    if (held.has(p.id)) return isHeldPromotion(p);
    return pasted.has(p.id) && isHeldPromotion(p) && "pasteId" in p && p.pasteId === round.paste?.pasteId;
  });
}

/** Why Auto leaves a proposal for an analyst; null when Auto applies it. */
function waitReason(p: WatsonProposal, round: WatsonAutoRound): string | null {
  if (p.kind !== "velo_launch") return null;
  if (p.mode !== "collection") return "fleet-wide hunts always wait for an analyst";
  if (round.reaction) return "Watson does not launch from a round it started itself";
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
    case "report_text":
      return `report text (${p.field === "conclusions" ? "Conclusions" : "Investigation limitations"}): ${p.after}`;
    case "event_promote":
      return `promotion of ${p.events.length} held row${p.events.length === 1 ? "" : "s"}`;
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

/** The turn text. A VQL that would push the turn past its cap is pointed at, never cut. */
export function listingText(by: string, listed: readonly Listed[]): string {
  const parts = [`Watson acted on its own (Auto mode, switched on by ${by}):`];
  let used = parts[0].length;
  for (const { line, vql } of listed) {
    const whole = vql === undefined ? line : `${line}\n  VQL:\n${vql}`;
    const pointer = `${line}\n  VQL: ${vql?.length ?? 0} characters, too long to repeat here; shown whole on the launch card.`;
    const text = used + whole.length + 1 <= WATSON_TURN_TEXT_MAX || vql === undefined ? whole : pointer;
    parts.push(text);
    used += text.length + 1;
  }
  return parts.join("\n").slice(0, WATSON_TURN_TEXT_MAX);
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
): Promise<Listed & { state: boolean }> {
  const vql = vqlOf(p);
  const listed = (line: string, state = false) => ({ line, state, ...(vql !== undefined ? { vql } : {}) });
  try {
    const r = await runWithoutIdentity(() =>
      applyWatsonProposal(deps, caseId, p.id, "apply", WATSON_AUTO_ACTOR, {
        detailSuffix,
        pendingOnly: true,
      }),
    );
    const verb = p.kind === "velo_launch" ? "Launched" : "Applied";
    return listed(`- ${verb} ${what(p)}`, !!r.state);
  } catch (err) {
    if (err instanceof WatsonLaunchUncertain) {
      return listed(
        `- Could not confirm the launch of ${what(p)} — check Velociraptor, then mark it launched or try again.`,
      );
    }
    return listed(`- Did not apply ${what(p)}: ${errText(err)}. It stays pending.`);
  }
}

/**
 * Apply the round's eligible proposals when the case is in Auto mode, one at a time, then append one
 * system turn listing every action. Never throws for a single proposal: a refused apply stays pending
 * and is listed. Returns the chat as saved (unchanged in Approve mode or when nothing is eligible).
 */
export async function autoApply(
  deps: WriterDeps & { onStateChanged?(caseId: string): void },
  caseId: string,
  round: WatsonAutoRound,
  control: WatsonAutoControl,
): Promise<WatsonChat> {
  const chat = await deps.chatStore.load(caseId);
  if (watsonRunMode(control) !== "auto") return chat;
  const todo = eligibleProposals(chat, round);
  if (!todo.length) return chat;
  const suffix = autoDetail(control);
  const lines: Listed[] = [];
  let stateChanged = false;
  for (const p of todo) {
    const wait = waitReason(p, round);
    if (wait) {
      const vql = vqlOf(p);
      lines.push({
        line: `- Left for an analyst: ${what(p)} — ${wait}.`,
        ...(vql !== undefined ? { vql } : {}),
      });
      continue;
    }
    const r = await applyOne(deps, caseId, p, suffix);
    lines.push({ line: r.line, ...(r.vql !== undefined ? { vql: r.vql } : {}) });
    stateChanged ||= r.state;
  }
  if (stateChanged) deps.onStateChanged?.(caseId);
  const by = control.watsonAutoBy?.name ?? "an analyst";
  const turn: WatsonTurn = {
    id: newWatsonId("wt"),
    at: new Date().toISOString(),
    role: "system",
    text: listingText(by, lines),
  };
  return deps.chatStore.update(caseId, (c) => ({ ...c, turns: [...c.turns, turn] }));
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
    const control = await auto.control(caseId);
    if (watsonRunMode(control) !== "auto") return saved;
    return await autoApply({ ...auto.writer, onStateChanged: auto.onStateChanged }, caseId, round, control);
  } catch (err) {
    warn(`Watson Auto mode could not act: ${errText(err)}`);
    return saved;
  }
}
