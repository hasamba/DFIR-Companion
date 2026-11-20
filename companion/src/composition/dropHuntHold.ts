import type { DropLogEntry } from "../analysis/dropLog.js";
import type { HuntPlan } from "../analysis/veloHuntLayout.js";
import { huntArtifactLimitsFromEnv, planHolds } from "../analysis/huntArtifactLimits.js";
import type { HuntHeldStore } from "../analysis/huntHeldStore.js";
import { writeZipMember, type ZipFile, type ZipMember } from "../storage/zipMembers.js";
import type { HuntZipLedger } from "./dropHuntZipLedger.js";
import { extractHeldMember } from "./dropHuntExtract.js";

/**
 * A hunt zip's members over the size limits (#2746, #2755). Each is extracted to
 * `drop/_held/<zip stem>/<member>` — a drop-folder file the analyst imports (Import anyway moves it back
 * into drop/) or skips (moved to `_skipped/`) — and recorded in the zip's ledger as `held`, neither
 * imported nor failed. The zip then completes as usual: it no longer waits in drop/.
 *
 * Only members not yet in the ledger are measured; a member whose extraction fails stays unrecorded
 * and is tried again on the next run (the zip stays in drop/, see `failedHolds`).
 */
export interface ZipHoldResult {
  /** Members on hold (this run or recorded earlier): not imported. */
  held: ReadonlySet<string>;
  /** Members that should be held but could not be extracted: the zip must run again. */
  failedHolds: number;
}

export const HOLD_REASON = "held over the hunt artifact size limit — Import anyway or Skip in the dashboard";

export async function holdZipMembers(a: {
  store: HuntHeldStore;
  caseId: string;
  dropDir: string;
  zipRel: string;
  zip: ZipFile;
  plans: readonly HuntPlan[];
  byName: ReadonlyMap<string, ZipMember>;
  ledger: HuntZipLedger;
  log: DropLogEntry[];
}): Promise<ZipHoldResult> {
  const held = new Set([...a.ledger.done].filter(([, o]) => o.held).map(([name]) => name));
  const limits = huntArtifactLimitsFromEnv();
  const holds = a.plans.flatMap((p) =>
    planHolds(
      p.imports.map((i) => ({ ...i, bytes: a.byName.get(i.path)?.entry.uncompressedSize ?? 0 })),
      limits,
    ),
  );
  let failedHolds = 0;
  for (const h of holds) {
    if (a.ledger.done.has(h.path)) continue; // imported, failed or held already
    const member = a.byName.get(h.path)!;
    try {
      const rel = await extractHeldMember(a.dropDir, a.zipRel, h.path, (out) =>
        writeZipMember(a.zip, member.entry, out),
      );
      await a.store.putHeld(a.caseId, {
        ...{ rel, origin: "zip", source: a.zipRel, artifact: h.artifact, host: h.host, bytes: h.bytes },
        ...{ groupBytes: h.groupBytes, reason: h.reason, limitMb: h.limitMb },
      });
      await a.ledger.record(h.path, { ok: false, held: true, reason: `${HOLD_REASON} (${rel})` });
      a.log.push({
        status: "SKIPPED",
        relpath: `${a.zipRel}!${h.path}`,
        reason: `${HOLD_REASON} — in ${rel}`,
      });
      held.add(h.path);
    } catch (e) {
      failedHolds += 1;
      held.add(h.path); // never imported past its limit; the next run tries the hold again
      a.log.push({
        status: "FAILED",
        relpath: `${a.zipRel}!${h.path}`,
        reason: `over the hunt artifact size limit, could not be set aside (${(e as Error).message}) — retried on the next sweep`,
      });
    }
  }
  return { held, failedHolds };
}
