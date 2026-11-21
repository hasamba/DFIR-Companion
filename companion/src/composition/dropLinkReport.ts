/**
 * Reports symlinks and hardlinks the drop-folder walk refused (#2788). They are never imported —
 * see the threat model in dropFolder.ts — but refusing them silently left the analyst with a file
 * that sat in drop/ forever and no word why. Each link is now reported ONCE: a server log line and
 * a drop-log.txt SKIPPED line. It is remembered while it stays in place, so a poll every few
 * seconds does not repeat the line; once it is gone it is forgotten, so a link planted again later
 * is reported again. Memory is per case incarnation (CaseKeyedMap), like the sweep's other state.
 */
import { appendDropLog, formatDropLogLines, type DropLogEntry } from "../analysis/dropLog.js";
import { CaseKeyedMap } from "../storage/caseKeyedState.js";

export type DropLinkKind = "symlink" | "hardlink";

export interface DropLink {
  relpath: string;
  kind: DropLinkKind;
}

export interface DropLinkReporterDeps {
  casesRoot: () => string;
  log: (line: string) => void;
}

export interface DropLinkReporter {
  /** Report the links in this listing not yet reported. Never rejects. */
  report(caseId: string, dropDir: string, links: readonly DropLink[]): Promise<void>;
}

const KIND_LABEL: Record<DropLinkKind, string> = {
  symlink: "symbolic link",
  hardlink: "hardlink",
};

export function linkSkipReason(kind: DropLinkKind): string {
  return `${KIND_LABEL[kind]} — not imported (security)`;
}

export function createDropLinkReporter(deps: DropLinkReporterDeps): DropLinkReporter {
  const reported = new CaseKeyedMap<ReadonlySet<string>>(deps.casesRoot);

  async function report(caseId: string, dropDir: string, links: readonly DropLink[]): Promise<void> {
    const before = reported.get(caseId) ?? new Set<string>();
    const fresh = links.filter((l) => !before.has(l.relpath));
    const current = new Set(links.map((l) => l.relpath));
    if (fresh.length > 0) {
      const entries = fresh.map((l): DropLogEntry => ({
        status: "SKIPPED",
        relpath: l.relpath,
        reason: linkSkipReason(l.kind),
      }));
      for (const l of fresh) deps.log(`[drop] ${caseId}: skipped ${l.relpath} — ${linkSkipReason(l.kind)}`);
      try {
        await appendDropLog(dropDir, formatDropLogLines(entries, new Date().toISOString()));
      } catch (e) {
        // Still remembered: the server log above has the line, and retrying every poll would
        // repeat it (and this failure) forever while drop-log.txt stays unwritable.
        deps.log(`[drop] ${caseId}: log append failed for refused links: ${(e as Error).message}`);
      }
    }
    reported.set(caseId, current);
  }

  return { report };
}
