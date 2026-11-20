import { artifactRowHold, huntArtifactLimitsFromEnv } from "../analysis/huntArtifactLimits.js";
import { huntHeldStoreFor, type HeldHuntEntry } from "../analysis/huntHeldStore.js";
import type { SkippedArtifact } from "../integrations/velociraptor/velociraptorApi.js";

/**
 * One bundle-hunt collect pass's size holds (#2753). Each downloaded artifact is measured before it
 * imports; one over a limit is held as a whole unless the analyst chose Import anyway for it (a
 * decision every later pass of the hunt follows). A held artifact is still stored as evidence — only
 * its import is left out — and it is reported with the pass's skipped artifacts, so the hunt's
 * coverage says it was not analysed and why.
 */
export interface HuntHolds {
  /** Measure one downloaded artifact; returns how many of its rows this pass imports (0 when held). */
  note(name: string, rows: readonly unknown[]): number;
  /** `list` without the artifacts this pass does not import. */
  importable<T extends { name: string }>(list: readonly T[]): T[];
  /** Persist this pass's holds; the artifacts left out, as skipped-artifact records. */
  save(): Promise<SkippedArtifact[]>;
}

const MB = 1024 * 1024;
const mb = (n: number): string => (n / MB).toFixed(n < 10 * MB ? 1 : 0);

function why(h: Pick<HeldHuntEntry, "reason" | "bytes" | "hostBytes" | "limitMb">): string {
  return h.reason === "host"
    ? `${mb(h.hostBytes)} MB from one PC (limit ${h.limitMb} MB per PC)`
    : `${mb(h.bytes)} MB across all PCs (limit ${h.limitMb} MB)`;
}

export async function loadHuntHolds(
  cases: { stateDir: (caseId: string) => string },
  caseId: string,
  huntId: string,
): Promise<HuntHolds> {
  const store = huntHeldStoreFor(cases);
  const limits = huntArtifactLimitsFromEnv();
  const prior = (await store.listHunts(caseId)).find((h) => h.huntId === huntId)?.entries ?? [];
  const decisions = new Map(prior.map((e) => [e.artifact, e.decision]));
  const downloaded: string[] = [];
  const held: HeldHuntEntry[] = [];
  const left = new Map<string, string>(); // artifact → why it is not imported
  return {
    note(name, rows) {
      downloaded.push(name);
      const hold = artifactRowHold(name, rows, limits);
      if (hold) held.push(hold);
      const decision = decisions.get(name);
      // Skip wins whatever the size now: raised limits or a smaller download never bring it back.
      if (decision === "skip") {
        const size = hold ?? prior.find((e) => e.artifact === name);
        left.set(
          name,
          `over the hunt artifact size limit${size ? ` (${why(size)})` : ""} — skipped by the analyst`,
        );
        return 0;
      }
      if (!hold || decision === "import") return rows.length;
      left.set(
        name,
        `held over the hunt artifact size limit (${why(hold)}) — Import anyway or Skip in the dashboard`,
      );
      return 0;
    },
    importable: (list) => list.filter((f) => !left.has(f.name)),
    async save() {
      await store.putHuntHolds(caseId, huntId, downloaded, held);
      return [...left].map(([name, error]) => ({ name, error }));
    },
  };
}
