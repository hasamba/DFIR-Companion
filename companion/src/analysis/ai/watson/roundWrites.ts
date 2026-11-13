import type { Finding } from "../../stateTypes.js";
import { isWatsonItem } from "../../timeline/watsonItems.js";
import type { WatsonReply } from "./replySchema.js";
import type { Outcome } from "./roundOutcome.js";
import type { WatsonRoundContext } from "./roundContext.js";
import type { WatsonPaste } from "./types.js";
import { emptyWrites, type WatsonCitationSets } from "./writesSchema.js";
import { readPasteLines } from "./writers/pasteLineEvents.js";
import type { WatsonReportFields } from "./writers/writerTypes.js";

// What turning a reply's writes into proposals needs from disk, read once after the model calls so
// mergeOutcome stays pure: the text of every cited paste line (so the analyst sees the exact rows a
// finding will add), the Watson findings an update names, and the report text Watson would replace.
// A read that fails drops what it would have supported, never the reply.

export interface WatsonWriteInputs {
  /** Watson-authored findings by id: the `before` of a finding_update. */
  findings: ReadonlyMap<string, Finding>;
  pastes: ReadonlyMap<string, WatsonPaste>;
  /** Cited paste lines that read, keyed `pasteId:line`. */
  lines: ReadonlyMap<string, string>;
  /** The report text now; absent when the report details cannot be read (no report_text proposal). */
  report?: Pick<WatsonReportFields, "conclusions" | "investigationLimitations">;
}

export const pasteLineKey = (pasteId: string, line: number): string => `${pasteId}:${line}`;

const isWatsonFinding = (f: Finding): boolean => isWatsonItem(f) && f.id.startsWith("f-watson-");

/** What a round's finding drafts may cite: the stored pastes' line counts and Watson's own findings. */
export function citationSets(
  pastes: readonly WatsonPaste[],
  findings: readonly Finding[],
): WatsonCitationSets {
  return {
    pasteLines: new Map(pastes.map((p) => [p.id, p.lines] as const)),
    watsonFindingIds: new Set(findings.filter(isWatsonFinding).map((f) => f.id)),
  };
}

async function readCitedLines(
  ctx: WatsonRoundContext,
  caseId: string,
  reply: WatsonReply,
  pastes: ReadonlyMap<string, WatsonPaste>,
): Promise<Map<string, string>> {
  const cited = reply.writes.findings.flatMap((f) => f.pasteLines);
  const out = new Map<string, string>();
  for (const pasteId of new Set(cited.map((c) => c.pasteId))) {
    const paste = pastes.get(pasteId);
    if (!paste) continue;
    const wanted = cited.filter((c) => c.pasteId === pasteId).map((c) => c.line);
    const read = await readPasteLines(ctx.cases, caseId, paste, wanted).catch(
      () => new Map<number, string>(),
    );
    for (const [line, text] of read) out.set(pasteLineKey(pasteId, line), text);
  }
  return out;
}

async function resolve(
  ctx: WatsonRoundContext,
  caseId: string,
  reply: WatsonReply,
): Promise<WatsonWriteInputs> {
  const { pastes } = await ctx.chatStore.load(caseId);
  const byId = new Map(pastes.map((p) => [p.id, p] as const));
  const { findings } = await ctx.stateStore.loadOverview(caseId);
  const report = reply.writes.report.length
    ? await ctx.reportText?.load(caseId).catch(() => undefined)
    : undefined;
  return {
    findings: new Map(findings.filter(isWatsonFinding).map((f) => [f.id, f] as const)),
    pastes: byId,
    lines: await readCitedLines(ctx, caseId, reply, byId),
    ...(report
      ? {
          report: {
            conclusions: report.conclusions,
            investigationLimitations: report.investigationLimitations,
          },
        }
      : {}),
  };
}

const hasWrites = (r: WatsonReply): boolean =>
  r.writes.findings.length + r.writes.nextSteps.length + r.writes.report.length > 0;

/**
 * The outcome with what its writes need (spec §4.4: with `allowWrites` false the writes are dropped,
 * question proposals stay). Never throws: a failed read leaves the reply without its writes.
 */
export async function withWriteInputs(
  ctx: WatsonRoundContext,
  caseId: string,
  outcome: Outcome,
  allowWrites: boolean,
): Promise<Outcome> {
  const { reply } = outcome;
  if (!reply || !hasWrites(reply)) return outcome;
  const dropped: Outcome = { ...outcome, reply: { ...reply, writes: emptyWrites() } };
  if (!allowWrites) return dropped;
  try {
    return { ...outcome, writeInputs: await resolve(ctx, caseId, reply) };
  } catch (err) {
    ctx.log?.warn(
      `Watson could not prepare its proposed writes: ${err instanceof Error ? err.message : String(err)}`,
      {
        caseId,
      },
    );
    return dropped;
  }
}
