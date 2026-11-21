import { rm } from "node:fs/promises";
import { join } from "node:path";
import { withCaseWrite } from "../storage/caseIncarnation.js";
import {
  artifactRowHold,
  huntArtifactLimitsFromEnv,
  type HeldArtifactRows,
} from "../analysis/huntArtifactLimits.js";
import { huntHeldStoreFor } from "../analysis/huntHeldStore.js";
import { DROP_HELD } from "../analysis/dropScan.js";
import type { SkippedArtifact } from "../integrations/velociraptor/velociraptorApi.js";
import { writeHeldText } from "./dropHeld.js";

/**
 * One bundle-hunt collect pass's size holds (#2753, #2755). Each downloaded artifact is measured before
 * it imports. One over a limit is held as a whole, unless the analyst already decided for it (a decision
 * every later pass of the hunt follows):
 *
 * - undecided → saved as a drop-folder file, `drop/_held/<hunt id>/<artifact>.json` (Velociraptor JSON
 *   Lines, one row per line), and not imported. Import anyway moves that file into drop/ and the drop
 *   sweep imports it — nothing is downloaded again; Skip moves it to `_skipped/`.
 * - import → imported by this pass; skip → left out, whatever its size now.
 *
 * A held artifact is still stored as evidence, and it is reported with the pass's skipped artifacts so
 * the hunt's coverage says it was not analysed and why.
 */
export interface HuntHolds {
  /** Measure one downloaded artifact; how many of its rows this pass imports (0 when held or skipped). */
  note(name: string, rows: readonly unknown[]): Promise<number>;
  /** `list` without the artifacts this pass does not import. */
  importable<T extends { name: string }>(list: readonly T[]): T[];
  /** The artifacts left out, as skipped-artifact records. */
  skippedRecords(): SkippedArtifact[];
}

const MB = 1024 * 1024;
const mb = (n: number): string => (n / MB).toFixed(n < 10 * MB ? 1 : 0);

function why(h: Pick<HeldArtifactRows, "reason" | "overBytes" | "limitMb">): string {
  return h.reason === "host"
    ? `${mb(h.overBytes)} MB from one PC (limit ${h.limitMb} MB per PC)`
    : `${mb(h.overBytes)} MB of rows with no PC (limit ${h.limitMb} MB for several PCs)`;
}

/** An artifact (or artifact/source) name as one safe file name: `/` as Velociraptor writes it, `%2F`. */
export function heldArtifactFileName(artifact: string): string {
  return `${artifact.replace(/\//g, "%2F").replace(/[\\:*?"<>|\u0000-\u001f]/g, "_")}.json`;
}

/** Remove an earlier held copy of an artifact this collect imports (it is a copy; the evidence is kept). */
async function supersede(dropDir: string, rel: string): Promise<void> {
  await withCaseWrite(dropDir, () => rm(join(dropDir, ...rel.split("/")), { force: true })).catch(
    () => undefined,
  );
}

export async function loadHuntHolds(
  cases: { stateDir: (caseId: string) => string; caseDir: (caseId: string) => string },
  caseId: string,
  huntId: string,
  superOnly = false,
): Promise<HuntHolds> {
  const store = huntHeldStoreFor(cases);
  const dropDir = join(cases.caseDir(caseId), "drop");
  const limits = huntArtifactLimitsFromEnv();
  const left = new Map<string, string>(); // artifact → why it is not imported
  return {
    async note(name, rows) {
      // A super-timeline-only hunt never reaches the forensic timeline and has its own cap: never held,
      // since a released held file would import through the normal drop path instead (§7).
      if (superOnly) return rows.length;
      const hold = artifactRowHold(name, rows, limits);
      // Read per artifact: a decision made while this pass downloads is followed.
      const decision = (await store.huntDecisions(caseId, huntId))[name];
      if (decision === "skip") {
        left.set(
          name,
          `over the hunt artifact size limit${hold ? ` (${why(hold)})` : ""} — skipped by the analyst`,
        );
        return 0;
      }
      const rel = `${DROP_HELD}/${huntId}/${heldArtifactFileName(name)}`;
      if (!hold || decision === "import") {
        await supersede(dropDir, rel); // imported by this collect: an earlier held copy must not import again
        return rows.length;
      }
      await writeHeldText(dropDir, rel, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
      await store.putHeld(caseId, {
        ...{ rel, origin: "hunt", source: huntId, huntId, artifact: name, host: hold.hosts.join(", ") },
        ...{ bytes: hold.bytes, groupBytes: hold.overBytes },
        ...{ reason: hold.reason, limitMb: hold.limitMb },
      });
      left.set(
        name,
        `held over the hunt artifact size limit (${why(hold)}) — saved in ${rel}; Import anyway or Skip in the dashboard`,
      );
      return 0;
    },
    importable: (list) => list.filter((f) => !left.has(f.name)),
    skippedRecords: () => [...left].map(([name, error]) => ({ name, error })),
  };
}
