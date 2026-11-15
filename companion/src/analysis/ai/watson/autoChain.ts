import type { WatsonChat, WatsonProposal } from "./types.js";
import type { WriterDeps } from "./writers/writerTypes.js";

// The short Auto chain (user decision of 2026-11-15). In Auto mode Watson may launch a follow-up
// single-host collection from a round it started itself (a reaction round), up to
// WATSON_AUTO_CHAIN_MAX launches since the analyst's last message. The count is saved in the chat, so
// it survives a restart; any analyst-asked round clears it (reactionState.ts `engaged`). A count that
// cannot be read or saved counts as the cap: Watson then leaves the launch for an analyst.
//
// A fleet hunt and a risky query never take a place: they wait for an analyst before the chain is
// checked (autoApply.ts `waitReason`).

export const WATSON_AUTO_CHAIN_MAX = 3;

export const CHAIN_FULL_WAIT =
  `Watson launched ${WATSON_AUTO_CHAIN_MAX} collections in a row without a message from you. ` +
  "Launch this one, or send a message to let Watson continue.";

/** The saved count, read strictly: a value that is present but not a whole count reads as the cap. */
export function chainCountOf(raw: unknown): number | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw === "number" && Number.isInteger(raw) && raw >= 0) return raw;
  return WATSON_AUTO_CHAIN_MAX;
}

const countIn = (chat: WatsonChat): number => chainCountOf(chat.autoChainLaunches) ?? 0;

/** A launch Auto may make from a reaction round only when a place in the chain is free. */
export const isChainLaunch = (p: WatsonProposal, reaction: boolean): boolean =>
  reaction && p.kind === "velo_launch" && p.mode === "collection" && !p.risk;

/**
 * Take one place in the chain, checked and counted in one chat update. Returns the launch's place
 * (1-based), or null when the chain is full or the count could not be saved (fail closed).
 */
export async function reserveChainPlace(
  store: WriterDeps["chatStore"],
  caseId: string,
): Promise<number | null> {
  let place: number | null = null;
  try {
    await store.update(caseId, (c) => {
      const n = countIn(c);
      place = n < WATSON_AUTO_CHAIN_MAX ? n + 1 : null;
      return place === null ? c : { ...c, autoChainLaunches: place };
    });
  } catch {
    return null; // fail closed: the caller leaves the launch for an analyst
  }
  return place;
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
      if (p?.status !== "pending" || n === 0) return c;
      return { ...c, autoChainLaunches: n - 1 };
    })
    .catch(() => undefined); // fail closed, see above
}
