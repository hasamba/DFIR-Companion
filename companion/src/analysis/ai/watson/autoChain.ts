import type { WatsonChat, WatsonProposal } from "./types.js";
import type { WriterDeps } from "./writers/writerTypes.js";

// The short Auto chain (user decisions of 2026-11-15 and 2026-11-16). In Auto mode Watson may launch a
// follow-up single-host collection from a round it started itself (a reaction round), and start its
// own next round when it says it can continue by itself ('continue' in its reply). Both take a place
// in the chain: up to the case's chain limit of steps since the analyst's last message. The analyst sets the limit per case in the
// Watson panel (default WATSON_AUTO_CHAIN_DEFAULT; 0 = no limit) and can stop the chain at any time:
// Stop chain keeps Auto on but launches nothing more from Watson's own rounds until the analyst's next
// message. The count, the limit and the stop are saved in the chat, so they survive a restart; any
// analyst-asked round clears the count and the stop (reactionState.ts `engaged`), never the limit. A
// count that cannot be read or saved counts as full: Watson then leaves the launch for an analyst.
//
// A fleet hunt and a risky query never take a place: they wait for an analyst before the chain is
// checked (autoApply.ts `waitReason`).

export const WATSON_AUTO_CHAIN_DEFAULT = 3;
/** The highest limit the panel accepts. 0 (no limit) is separate. */
export const WATSON_AUTO_CHAIN_LIMIT_MAX = 50;
/** A count read as "full" whatever the limit: a malformed saved count fails closed. */
const FULL = Number.MAX_SAFE_INTEGER;

const inRange = (n: unknown): n is number =>
  typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= WATSON_AUTO_CHAIN_LIMIT_MAX;

/** The case's limit: a whole number 0..WATSON_AUTO_CHAIN_LIMIT_MAX (0 = no limit), else the default. */
export const chainMaxOf = (raw: unknown): number => (inRange(raw) ? raw : WATSON_AUTO_CHAIN_DEFAULT);

/** A limit an analyst sent: the same range, or null when it is not one. */
export function parseChainMax(raw: unknown): number | null {
  const n = typeof raw === "string" && raw.trim() !== "" ? Number(raw) : raw;
  return inRange(n) ? n : null;
}

export const chainLimitText = (max: number): string => (max === 0 ? "no limit" : String(max));

/** Why a chained launch waits when the chain is full. */
export const chainFullWait = (max: number): string =>
  `Watson took ${max} step${max === 1 ? "" : "s"} in a row without a message from you. ` +
  "Launch this one, or send a message to let Watson continue.";

/** Why Watson does not start its own next round (user decision of 2026-11-16: Auto keeps going). */
export const continueRefusedText = (r: ChainRefusal): string =>
  r.wait.startsWith("You stopped")
    ? "Watson has a next step, but you stopped the Auto chain. Send a message to let Watson continue."
    : "Watson has a next step, but it reached the Auto chain limit. Send a message to let Watson continue, or raise the limit.";

export const CHAIN_STOPPED_WAIT =
  "You stopped the Auto chain. Launch this one, or send a message to let Watson continue.";

/** The saved count, read strictly: a value that is present but not a whole count reads as full. */
export function chainCountOf(raw: unknown): number | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw === "number" && Number.isInteger(raw) && raw >= 0) return raw;
  return FULL;
}

const countIn = (chat: WatsonChat): number => chainCountOf(chat.autoChainLaunches) ?? 0;

/** A launch Auto may make from a reaction round only when a place in the chain is free. */
export const isChainLaunch = (p: WatsonProposal, reaction: boolean): boolean =>
  reaction && p.kind === "velo_launch" && p.mode === "collection" && !p.risk;

/** A taken place: its number (1-based) and the limit it was counted against (0 = no limit). */
export interface ChainPlace {
  place: number;
  max: number;
}

/** A refused place: why the launch waits. */
export interface ChainRefusal {
  wait: string;
}

/** Decide one place against the saved chat. */
function placeIn(c: WatsonChat): ChainPlace | ChainRefusal {
  const max = chainMaxOf(c.autoChainMax);
  const n = countIn(c);
  if (c.autoChainStopped) return { wait: CHAIN_STOPPED_WAIT };
  if (n === FULL || (max !== 0 && n >= max)) return { wait: chainFullWait(max) };
  return { place: n + 1, max };
}

/**
 * Take one place in the chain, checked and counted in one chat update. Returns the place, or why the
 * launch waits: the analyst stopped the chain, the chain is full, or the count could not be saved
 * (fail closed).
 */
export async function reserveChainPlace(
  store: WriterDeps["chatStore"],
  caseId: string,
): Promise<ChainPlace | ChainRefusal> {
  let out: ChainPlace | ChainRefusal = { wait: chainFullWait(WATSON_AUTO_CHAIN_DEFAULT) };
  try {
    await store.update(caseId, (c) => {
      out = placeIn(c);
      return "place" in out ? { ...c, autoChainLaunches: out.place } : c;
    });
  } catch {
    return { wait: chainFullWait(WATSON_AUTO_CHAIN_DEFAULT) }; // fail closed: the caller leaves the launch
  }
  return out;
}

/**
 * Give a place back after Auto's apply left the launch pending (a definite refusal: nothing ran). A
 * launch that may have run (launching, uncertain) keeps its place. A failed save keeps it too: the
 * chain then stops one launch early, which is the safe side.
 */
export async function releaseChainPlace(
  store: WriterDeps["chatStore"],
  caseId: string,
  proposalId: string,
): Promise<void> {
  await store
    .update(caseId, (c) => {
      const p = c.proposals.find((x) => x.id === proposalId);
      const n = countIn(c);
      if (p?.status !== "pending" || n === 0 || n === FULL) return c;
      return { ...c, autoChainLaunches: n - 1 };
    })
    .catch(() => undefined); // fail closed, see above
}

/** The chat with a new chain limit (the count is kept: a lower limit takes effect at once). */
export const withChainMax = (chat: WatsonChat, max: number): WatsonChat => ({ ...chat, autoChainMax: max });

/** The chat with the chain stopped until the analyst's next message. */
export const withChainStopped = (chat: WatsonChat): WatsonChat => ({ ...chat, autoChainStopped: true });
