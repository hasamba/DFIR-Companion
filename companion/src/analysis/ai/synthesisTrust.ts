// Which forensic rows synthesis is told are from an analyst-marked trusted source (#2561). Loaded
// ONCE per run and used for both the skip-hash and the prompt marker, so the two never disagree.
// Only the forensic timeline's own rows are read — never the super-timeline. Fail-soft: an
// unreadable label file or tag store means no row is marked trusted, the safe direction.

import type { Logger } from "../../logging/logger.js";
import type { IocAttributionStore } from "../iocAttributionStore.js";
import type { ForensicEvent } from "../stateTypes.js";
import type { TagsStore } from "../tags.js";
import { TRUSTED_AUTHOR_PREFIX, honouredTrustedRows, type HonouredTrust } from "../trustedSourceMarks.js";

export type TrustedRows = ReadonlyMap<string, HonouredTrust>;

export interface SynthesisTrustContext {
  readonly log?: Pick<Logger, "warn">;
  readonly opts: { tagsStore?: TagsStore; iocAttributionStore?: IocAttributionStore };
}

export async function loadTrustedRows(
  ctx: SynthesisTrustContext,
  caseId: string,
  rows: readonly ForensicEvent[],
): Promise<TrustedRows> {
  const { tagsStore, iocAttributionStore } = ctx.opts;
  if (!tagsStore || !iocAttributionStore || !rows.length) return new Map();
  try {
    const map = await iocAttributionStore.load(caseId);
    if (!Object.keys(map).length) return new Map();
    const tags = (
      await tagsStore.taggerTagsFor(
        caseId,
        rows.map((r) => r.id),
      )
    ).filter((t) => t.author.startsWith(TRUSTED_AUTHOR_PREFIX));
    return tags.length ? honouredTrustedRows(rows, tags, map) : new Map();
  } catch (err) {
    ctx.log?.warn(
      `[synthesis] trusted-activity marks unreadable, no row marked trusted: ${(err as Error).message}`,
      { caseId },
    );
    return new Map();
  }
}

/** The skip-hash input: a new, cleared or relabelled mark must re-run synthesis. */
export function trustedSignature(trusted: TrustedRows): string[] {
  return [...trusted].map(([id, t]) => `${id}:${t.label}:${t.value}`).sort();
}

/** The marker a trusted row carries in the prompt. Self-describing: no shared prompt text changes. */
export function trustedPromptTag(t: HonouredTrust | undefined): string {
  return t ? ` [analyst-marked trusted source (${t.label}): ${t.value} — not proven benign]` : "";
}
