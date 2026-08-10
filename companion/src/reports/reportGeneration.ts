import { writeFile, rename, unlink } from "node:fs/promises";
import { atomicTempPath } from "../storage/atomicWrite.js";

// A report is not one file, it is eight — markdown, HTML, four CSVs, the state export, and the
// analysis-run provenance record. They were written one after another, straight over the previous
// report's files. Any interruption between them (a crash, a full disk, a permission error, or a
// failed provenance write) left some artifacts from the NEW report sitting beside artifacts from
// the OLD one.
//
// Every individual file stays readable, which is what makes this dangerous rather than merely
// annoying: nothing looks broken. A report directory can present a findings CSV from one
// generation, a narrative from another, and provenance for a run that never finished — and for a
// forensic deliverable, internally inconsistent claims with stale provenance are worse than a
// missing report, because someone will rely on them.
//
// So: render everything, stage everything, and only then publish. Nothing in the reports directory
// changes until every artifact AND the provenance record have succeeded.

interface Staged {
  tmp: string;
  target: string;
}

/**
 * A report generation held in staging, publishable as a unit.
 *
 * Staged files use atomicWrite's temp-path form, so the export walker and anything else that
 * inspects a case already treats them as a write in progress rather than case content.
 */
export class ReportGeneration {
  private readonly staged: Staged[] = [];
  private published = false;

  /** Write one artifact into staging. Nothing is visible at its real path until publish(). */
  async stage(target: string, contents: string): Promise<void> {
    const tmp = atomicTempPath(target);
    await writeFile(tmp, contents, "utf8");
    this.staged.push({ tmp, target });
  }

  /**
   * Move every staged artifact into place.
   *
   * Renames within one directory are the most reliable operation available here — no bytes move and
   * each replacement is atomic — so the window in which a mixed generation could be observed shrinks
   * from the whole render (seconds: rendering, disk writes, a provenance round-trip) to the few
   * microseconds between renames. It is NOT a single atomic swap of the whole directory, and this
   * comment is the place that says so rather than leaving a reader to assume otherwise; a directory
   * swap would break the other files that legitimately live in reports/ (custody manifests, exports).
   *
   * A failure part-way through leaves the remaining staged files in place rather than deleting them,
   * so the bytes are still on disk for an operator to inspect.
   */
  async publish(): Promise<void> {
    for (const { tmp, target } of this.staged) {
      await rename(tmp, target);
    }
    this.published = true;
    this.staged.length = 0;
  }

  /**
   * Throw away everything staged. Called when rendering or provenance failed, so a half-built
   * generation never reaches the reports directory — and never accumulates as debris either.
   */
  async discard(): Promise<void> {
    if (this.published) return;
    await Promise.all(
      this.staged.map(({ tmp }) =>
        unlink(tmp).catch(() => {
          /* already gone, or never created — nothing to undo */
        }),
      ),
    );
    this.staged.length = 0;
  }
}
