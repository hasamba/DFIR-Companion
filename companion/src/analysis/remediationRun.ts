import type { InvestigationState } from "./stateTypes.js";
import type { ForensicEvent } from "./stateTypes.js";
import type { SuperTimelineMeta } from "./superTimelineStore.js";
import type { ClockSkewRecord } from "./clockSkewStore.js";
import { effectiveOffsets } from "./clockSkew.js";
import { loadHostAliasIndex, type HostScopeSources } from "./hostScopeLoad.js";
import { boundaryWindow, type RemediationBoundary } from "./remediationBoundary.js";
import { verifyBoundary, VERIFY_ROW_BUDGET, type VerifyFacts } from "./remediationVerify.js";

// The store recipe behind a verify (#969): load what the pure verify needs, capture the
// super-timeline's generation before and after the read so the receipt can say whether the
// stores moved under it, and read the super-timeline ONLY inside the window and under the row
// budget — the analyst-initiated, ephemeral read ARCHITECTURE.md allows, and nothing else.

export interface RemediationRunSources {
  state: { load(caseId: string): Promise<InvestigationState> };
  superTimeline: {
    meta(caseId: string): Promise<SuperTimelineMeta>;
    scanWindow(
      caseId: string,
      time: { from: string; to: string },
      budget: number,
    ): AsyncGenerator<ForensicEvent>;
    cap: number;
  };
  clockSkew?: { load(caseId: string): Promise<ClockSkewRecord> };
  importMeta?: { load(caseId: string): Promise<{ lastImportedAt: string }> };
  assetOverrides?: HostScopeSources["assetOverrides"];
  fleet?: HostScopeSources["fleet"];
}

export async function runRemediationVerify(
  src: RemediationRunSources,
  caseId: string,
  boundary: RemediationBoundary,
  now: string = new Date().toISOString(),
): Promise<VerifyFacts> {
  const before = await src.superTimeline.meta(caseId);
  const state = await src.state.load(caseId);
  const win = boundaryWindow(boundary, now);
  const superRows: ForensicEvent[] = [];
  let read = 0;
  for await (const e of src.superTimeline.scanWindow(
    caseId,
    { from: new Date(win.fromMs).toISOString(), to: new Date(win.toMs).toISOString() },
    VERIFY_ROW_BUDGET,
  )) {
    superRows.push(e);
    read += 1;
  }
  const after = await src.superTimeline.meta(caseId);
  const skew = src.clockSkew ? await src.clockSkew.load(caseId).catch(() => undefined) : undefined;
  const offsets = skew?.alignEnabled ? effectiveOffsets(skew.results, skew.overrides) : undefined;
  const meta = src.importMeta ? await src.importMeta.load(caseId).catch(() => undefined) : undefined;
  const aliasIndex = await loadHostAliasIndex(
    {
      ...(src.assetOverrides ? { assetOverrides: src.assetOverrides } : {}),
      ...(src.fleet ? { fleet: src.fleet } : {}),
    },
    caseId,
  );
  return verifyBoundary({
    boundary,
    now,
    forensic: state.forensicTimeline,
    superRows,
    superTruncated: read >= VERIFY_ROW_BUDGET,
    superMeta: { ...before, atCap: before.rows >= src.superTimeline.cap },
    superMetaAfter: { rows: after.rows, generation: after.generation },
    forensicMeta: { rows: state.forensicTimeline.length, updatedAt: state.updatedAt ?? "" },
    aliasIndex,
    ...(offsets && offsets.size ? { offsets } : {}),
    lastImportedAt: meta?.lastImportedAt ?? "",
  });
}
