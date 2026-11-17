import type { ToolCall } from "../../../providers/toolCalling.js";
import type { ForensicEvent, InvestigationState } from "../../stateTypes.js";
import { lookupKey } from "./autoProgress.js";
import { isSuperLookup, parseLookup } from "./lookupSchema.js";
import { lookupBlock, pasteBlock, superBlock } from "./promptBuilder.js";
import type { WatsonRoundContext } from "./roundContext.js";
import { maskingOn, REACTION_WHY, UNWIRED_WHY } from "./roundHop.js";
import { excerptRoster } from "./rowTextHosts.js";
import { maskRosterFull, type WatsonMaskRoster } from "./superRoster.js";
import { searchSuperTimeline, type WatsonRawSearchDeps } from "./superTimelineSearch.js";
import { lookupTimeline } from "./timelineLookup.js";
import { runHistoryTool, runPasteTool, type PasteToolRun } from "./toolPaste.js";
import { isWatsonTool, unknownKey, WATSON_TOOL, type WatsonToolName } from "./toolSpecs.js";
import type { WatsonChat, WatsonLookedUp, WatsonLookup } from "./types.js";

// Runs one of Watson's tool calls (phase 5). Every tool only reads. Each call goes through the same
// checks the one-step hop uses (roundHop.ts): the lookup schema, the reaction and seam refusals and
// the full-roster refusal. This is the only new Watson file that reaches the rawSearch seam, and it
// hands the reader to superTimelineSearch.ts, the one file that reads the store. A call that is not
// valid never runs: the model reads "Lookup not run: …" and no lookup record is made.

/** One call's outcome. `lookedUp` only for a call that ran; the loop folds the rest into the round. */
export interface ToolRun {
  result: { content: string; isError?: boolean };
  lookedUp?: WatsonLookedUp;
  superShown?: ForensicEvent[];
  roster?: WatsonMaskRoster;
  /** Paste searches only, never the history. */
  readPasteId?: string;
  /** The super-timeline store was read, even if nothing was shown: the call counts toward R2's cap. */
  superQueried?: boolean;
  /** A search that ran: Auto's progress-ledger key, the same one the one-step hop records (#2652). */
  key?: string;
}

export interface ToolRunOptions {
  /** An automatic reaction round: never a super-timeline search (D6, U4). */
  reaction: boolean;
  /** Super-timeline searches this question may still run (R2). Anything but a positive number refuses. */
  superLeft: number;
  /** The tool names this round offered: a call to any other tool is refused. */
  offered: readonly string[];
}

const RESULT_MAX = 600;
const flat = (s: string, max: number): string => s.replace(/\s+/g, " ").trim().slice(0, max);
const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err));
const notRun = (why: string): ToolRun => ({
  result: { content: flat(`Lookup not run: ${why}`, RESULT_MAX), isError: true },
});
/** The model reads one fixed line: a file path or a stack never leaves the server (I1). */
const FAILED = "Lookup failed: The lookup failed. Try a different lookup.";
const failedRun = (ctx: WatsonRoundContext, caseId: string, name: string, err: unknown): ToolRun => {
  ctx.log?.warn(`Watson tool call ${name} failed: ${errText(err)}`, { caseId });
  return { result: { content: FAILED, isError: true } };
};
const BAD_KEY_WHY = "The lookup has a field it does not accept.";
const NOT_OFFERED_WHY = "this tool is not available in this round";
export const ROSTER_FULL_WHY = "the list of masked names is full";
const NO_SUPER_LEFT_WHY = "this question used all its super-timeline searches";

/** The refusals that need no I/O: unknown tool, bad argument keys, and the super-timeline gates. */
function refusal(ctx: WatsonRoundContext, call: ToolCall, o: ToolRunOptions): string | null {
  if (!isWatsonTool(call.name)) return "unknown tool";
  if (call.name === WATSON_TOOL.super) {
    if (o.reaction) return REACTION_WHY;
    if (!ctx.rawSearch) return UNWIRED_WHY;
    if (!(typeof o.superLeft === "number" && o.superLeft > 0)) return NO_SUPER_LEFT_WHY;
  }
  if (!o.offered.includes(call.name)) return NOT_OFFERED_WHY;
  const input: unknown = call.input;
  if (!input || typeof input !== "object" || Array.isArray(input)) return "the arguments are not an object";
  return unknownKey(call.name, input as Record<string, unknown>) === null ? null : BAD_KEY_WHY;
}

/** The checked lookup for a forensic or super tool, its source set by the tool name only. */
function checkedLookup(name: WatsonToolName, input: Record<string, unknown>): WatsonLookup | { why: string } {
  const isSuper = name === WATSON_TOOL.super;
  const ask = parseLookup({ ...input, source: isSuper ? "supertimeline" : "forensic" });
  if (!ask) return { why: "it named nothing to look up" };
  if (!ask.ok) return { why: ask.why };
  return isSuperLookup(ask.query) === isSuper ? ask.query : { why: "the source does not match the tool" };
}

/** Run one tool call. Never throws: a failure is an error result the model reads. */
export async function runWatsonTool(
  ctx: WatsonRoundContext,
  caseId: string,
  chat: WatsonChat,
  state: InvestigationState,
  call: ToolCall,
  o: ToolRunOptions,
): Promise<ToolRun> {
  const refused = refusal(ctx, call, o);
  if (refused) return notRun(refused);
  const name = call.name as WatsonToolName;
  try {
    if (name === WATSON_TOOL.paste) return pasteRun(await runPasteTool(ctx, caseId, chat, call.input));
    if (name === WATSON_TOOL.history) return pasteRun(await runHistoryTool(ctx, caseId, chat, call.input));
    const query = checkedLookup(name, call.input);
    if ("why" in query) return notRun(query.why);
    if (name === WATSON_TOOL.super) return await superRun(ctx, caseId, chat, state, query);
    const { excerpt, lookedUp } = await lookupTimeline(ctx, caseId, state, query);
    return { result: { content: lookupBlock(excerpt, false) }, lookedUp, key: lookupKey(query) };
  } catch (error) {
    // A super call reaches the store before anything can fail after it: count it as run (M2).
    const failed = failedRun(ctx, caseId, name, error);
    return name === WATSON_TOOL.super ? { ...failed, superQueried: true } : failed;
  }
}

function pasteRun(run: PasteToolRun | { why: string }): ToolRun {
  if ("why" in run) return notRun(run.why);
  const roster = excerptRoster(run.excerpt.text);
  return {
    result: { content: pasteBlock(run.excerpt) },
    lookedUp: run.lookedUp,
    key: run.key,
    ...(run.readPasteId ? { readPasteId: run.readPasteId } : {}),
    ...(roster ? { roster } : {}),
  };
}

/** One bounded super-timeline search. Rows whose names do not fit the roster are never shown (H5). */
async function superRun(
  ctx: WatsonRoundContext,
  caseId: string,
  chat: WatsonChat,
  state: InvestigationState,
  query: WatsonLookup,
): Promise<ToolRun> {
  const raw = ctx.rawSearch as WatsonRawSearchDeps;
  const found = await searchSuperTimeline(ctx, raw.reader, caseId, state, query);
  if (maskRosterFull(chat.maskRoster, found.roster) && (await maskingOn(ctx, caseId))) {
    return { ...notRun(ROSTER_FULL_WHY), superQueried: true };
  }
  const shownIds = found.shown.map((e) => e.id);
  return {
    result: { content: superBlock(found.excerpt, false) },
    lookedUp: { ...found.lookedUp, shownIds },
    superShown: found.shown,
    roster: found.roster,
    superQueried: true,
    key: lookupKey(query),
  };
}
