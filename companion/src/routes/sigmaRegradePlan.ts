// Re-grade an imported case with the current Sigma rules (#2206): read what the plan needs. It
// reads the case's forensic rows, its super-timeline rows and the stored import files, and writes
// nothing. The pure diff is analysis/sigmaRegrade.ts.

import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { ForensicEvent } from "../analysis/stateTypes.js";
import { sourceArtifactHash } from "../analysis/canonicalEvent.js";
import { fileIsGzip } from "../analysis/cloudStreamReader.js";
import {
  GZIP_MAX_RATIO,
  GZIP_RATIO_SLACK_BYTES,
  REGRADE_TEXT_MAX_BYTES,
} from "../analysis/cloudStreamLimits.js";
import { readStoredImportText } from "./storedImportText.js";
import type { ForensicRowStore } from "../analysis/forensicRows.js";
import type { SigmaGradingSnapshot } from "../analysis/sigmaImportGrade.js";
import type { Severity } from "../analysis/stateTypes.js";
import {
  planSigmaRegrade,
  type RegradeFileInput,
  type RegradePlan,
  type SigmaRuleMitre,
  type StoredRow,
} from "../analysis/sigmaRegrade.js";
import {
  regradeImporterOf,
  reparseForRegrade,
  storedFileChanged,
  storedFileOf,
} from "../analysis/sigmaRegradeSources.js";

export interface RegradePlanDeps {
  stateStore: Pick<ForensicRowStore, "forensicTimelineBatches">;
  superTimelineStore?: { eventBatches(caseId: string): AsyncIterable<ForensicEvent[]> };
  importsDir: string;
  snapshot: SigmaGradingSnapshot;
  gate: Severity;
  ruleMitre: SigmaRuleMitre;
  /** Decoded bytes read from one stored file (test seam); REGRADE_TEXT_MAX_BYTES by default. */
  maxTextBytes?: number;
}

const MISSING = "(no stored file)";

async function storedFiles(dir: string): Promise<Set<string>> {
  try {
    return new Set(await readdir(dir));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return new Set();
    throw err;
  }
}

/**
 * The most text a re-grade can read from a gzip file of `size` compressed bytes (#2353): the
 * decompression-ratio bound past its slack, never past the re-grade's own cap. Never the gzip
 * trailer's size, which describes only the last member of a concatenated file.
 */
function gzipReadBound(size: number): number {
  return Math.min(REGRADE_TEXT_MAX_BYTES, Math.max(GZIP_RATIO_SLACK_BYTES, size * GZIP_MAX_RATIO));
}

/**
 * The bytes a re-grade re-reads: every stored import file of the case (#2227). It sizes the apply
 * for the memory guard; the files are already stored, so a refusal loses nothing. A gzip file is
 * read decompressed (#2353), so it counts at the most it can decompress to.
 */
export async function storedImportBytes(dir: string): Promise<number> {
  let total = 0;
  for (const file of await storedFiles(dir)) {
    try {
      const path = join(dir, file);
      const s = await stat(path);
      if (s.isFile()) total += s.size > 1 && (await fileIsGzip(path)) ? gzipReadBound(s.size) : s.size;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
  }
  return total;
}

interface Group {
  importer: string;
  rows: Map<string, StoredRow>;
}

function addRow(
  groups: Map<string, Group>,
  files: ReadonlySet<string>,
  e: ForensicEvent,
  copy: "forensic" | "super",
): void {
  const importer = regradeImporterOf(e);
  if (!importer) return;
  const file = storedFileOf(e, files) ?? MISSING;
  const group = groups.get(file) ?? { importer, rows: new Map<string, StoredRow>() };
  groups.set(file, group);
  group.rows.set(e.id, { ...group.rows.get(e.id), [copy]: e });
}

async function fileInput(
  dir: string,
  file: string,
  g: Group,
  deps: Pick<RegradePlanDeps, "snapshot" | "maxTextBytes">,
): Promise<RegradeFileInput> {
  const base = { file, importer: g.importer, rows: g.rows };
  if (file === MISSING) return { ...base, reparsed: { skipped: "file-missing" } };
  // Decoded as the import did (BOM honoured) and, for a .gz upload (#2303), decompressed (#2353),
  // so the text hashes to what the rows carry (#2337). Bounded: a file past the cap is skipped.
  const read = await readStoredImportText(join(dir, file), deps.maxTextBytes);
  if ("skipped" in read) return { ...base, reparsed: { skipped: read.skipped } };
  const textHash = sourceArtifactHash(read.text); // once per file, never per row
  const rows = [...g.rows.values()].map((r) => (r.forensic ?? r.super)!);
  if (rows.some((e) => storedFileChanged(e, textHash)))
    return { ...base, reparsed: { skipped: "file-changed" } };
  return { ...base, reparsed: reparseForRegrade(g.importer, read.text, deps.snapshot) };
}

/** The re-grade plan for one case, from what is stored now. Read-only. */
export async function loadRegradePlan(deps: RegradePlanDeps, caseId: string): Promise<RegradePlan> {
  const files = await storedFiles(deps.importsDir);
  const groups = new Map<string, Group>();
  for await (const batch of deps.stateStore.forensicTimelineBatches(caseId))
    for (const e of batch) addRow(groups, files, e, "forensic");
  if (deps.superTimelineStore)
    for await (const batch of deps.superTimelineStore.eventBatches(caseId))
      for (const e of batch) addRow(groups, files, e, "super");
  const inputs: RegradeFileInput[] = [];
  for (const [file, g] of groups) inputs.push(await fileInput(deps.importsDir, file, g, deps));
  return planSigmaRegrade({
    files: inputs,
    token: deps.snapshot.token,
    gate: deps.gate,
    ruleMitre: deps.ruleMitre,
  });
}

/** Plain-English sentences for the preview; the counts are in the answer beside them. */
export function regradeNotes(plan: RegradePlan): string[] {
  const c = plan.counts;
  const notes: string[] = [];
  const never = plan.files.filter((f) => f.status === "never").length;
  if (never) notes.push(`${never} import(s) were never graded by Sigma.`);
  if (c.notKept)
    notes.push(
      `${c.notKept} record(s) match a rule now but were not kept as their own row by the import ` +
        "(severity floor, event cap or grouping) — re-import the file to add them.",
    );
  if (c.counted)
    notes.push(`${c.counted} grouped row(s) are re-graded on the record that sets their identity.`);
  if (c.unmatched)
    notes.push(
      `${c.unmatched} row(s) could not be paired with their stored record (file missing, changed, ` +
        "too large to re-read or unreadable, or the record reads differently now) and stay as they are.",
    );
  const unresolved = new Set(plan.rows.flatMap((r) => r.unresolvedRules));
  if (unresolved.size)
    notes.push(
      `${unresolved.size} earlier rule(s) are not in the installed release; their ATT&CK techniques stay on the rows.`,
    );
  return notes;
}
