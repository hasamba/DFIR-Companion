// Re-grade an imported case with the current Sigma rules (#2206): read what the plan needs. It
// reads the case's forensic rows, its super-timeline rows and the stored import files, and writes
// nothing. The pure diff is analysis/sigmaRegrade.ts.

import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import type { ForensicEvent } from "../analysis/stateTypes.js";
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
 * The bytes a re-grade re-reads: every stored import file of the case (#2227). It sizes the apply
 * for the memory guard; the files are already stored, so a refusal loses nothing.
 */
export async function storedImportBytes(dir: string): Promise<number> {
  let total = 0;
  for (const file of await storedFiles(dir)) {
    try {
      const s = await stat(join(dir, file));
      if (s.isFile()) total += s.size;
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
  snapshot: SigmaGradingSnapshot,
): Promise<RegradeFileInput> {
  const base = { file, importer: g.importer, rows: g.rows };
  if (file === MISSING) return { ...base, reparsed: { skipped: "file-missing" } };
  let text: string;
  try {
    text = await readFile(join(dir, file), "utf8");
  } catch {
    return { ...base, reparsed: { skipped: "file-missing" } };
  }
  const rows = [...g.rows.values()].map((r) => (r.forensic ?? r.super)!);
  if (rows.some((e) => storedFileChanged(e, text))) return { ...base, reparsed: { skipped: "file-changed" } };
  return { ...base, reparsed: reparseForRegrade(g.importer, text, snapshot) };
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
  for (const [file, g] of groups) inputs.push(await fileInput(deps.importsDir, file, g, deps.snapshot));
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
      `${c.unmatched} row(s) could not be paired with their stored record (file missing or changed, ` +
        "or the record reads differently now) and stay as they are.",
    );
  const unresolved = new Set(plan.rows.flatMap((r) => r.unresolvedRules));
  if (unresolved.size)
    notes.push(
      `${unresolved.size} earlier rule(s) are not in the installed release; their ATT&CK techniques stay on the rows.`,
    );
  return notes;
}
