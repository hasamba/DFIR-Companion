import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { CaseStore } from "../storage/caseStore.js";
import { atomicWrite } from "../storage/atomicWrite.js";
import type { TimelineDiff } from "./timelineDiff.js";
import type { IocsDiff } from "./iocsDiff.js";

// Lightweight per-case record of the LAST import: when it ran, the detected kind/file, and what it
// added to (or merged in) the forensic timeline. Kept in a side file (`state/import-meta.json`) so
// the dashboard can show "last import 3 min ago - +N new events" and a what-was-added view above
// the timeline. This is the timeline analog of synth-meta.json (the findings what-changed view).
// NOT part of InvestigationState; written by the unified /import route after the importer completes.

const diffEventSchema = z.object({
  timestamp: z.string().catch(""),
  description: z.string().catch(""),
  severity: z.string().catch("Info"),
});

const diffIocSchema = z.object({
  value: z.string().catch(""),
  type: z.string().catch("other"),
});

export const importMetaSchema = z.object({
  lastImportedAt: z.string().catch(""),
  lastImportKind: z.string().catch(""),
  lastImportFile: z.string().catch(""),
  // Forensic-timeline diff (events the import added / correlation absorbed).
  addedCount: z.number().catch(0),     // true total added (the detail list may be capped)
  removedCount: z.number().catch(0),   // true total absorbed/merged by correlation
  lastDiff: z.object({
    added: z.array(diffEventSchema).catch([]),
    removed: z.array(diffEventSchema).catch([]),
  }).nullable().catch(null),
  // IOC diff (indicators the import added). Older import-meta.json files predate these — the
  // .catch defaults make them load cleanly as "no IOC change".
  iocsAddedCount: z.number().catch(0),
  iocsRemovedCount: z.number().catch(0),
  iocsDiff: z.object({
    added: z.array(diffIocSchema).catch([]),
    removed: z.array(diffIocSchema).catch([]),
  }).nullable().catch(null),
  // Source-yield instrumentation (investigation-guidance #10): the RAW input size and which extraction
  // path ran, so a big file that produced ZERO events via AI triage (northpeak's 27,290-line proxy log,
  // silently read as "clean") can be flagged instead of shown as a bland "+0 events". Optional/lenient —
  // older import-meta.json files load with linesIn 0 / path "" and simply never trip the check.
  linesIn: z.number().catch(0),                                  // raw input lines/rows the import read
  path: z.enum(["deterministic", "ai", ""]).catch(""),           // "ai" = the log/CSV AI-triage path; "" = unknown/legacy
});

export type ImportMeta = z.infer<typeof importMetaSchema>;

const EMPTY: ImportMeta = {
  lastImportedAt: "", lastImportKind: "", lastImportFile: "",
  addedCount: 0, removedCount: 0, lastDiff: null,
  iocsAddedCount: 0, iocsRemovedCount: 0, iocsDiff: null,
  linesIn: 0, path: "",
};

// Cap how many added/removed events we store in the detail list — a single import can add
// hundreds of events. The banner shows the true total (addedCount); the list (and the dashboard's
// per-row "new" highlight that reads it) covers the first N to keep the side file small.
const MAX_LISTED = 500;

export interface ImportRecord {
  kind: string;   // detected import kind: "thor" | "siem" | "chainsaw" | ...
  file: string;   // stored filename of the imported evidence
  diff: TimelineDiff;   // forensic-timeline diff
  iocsDiff: IocsDiff;   // IOC diff
  linesIn?: number;                          // raw input lines/rows the import read (#10)
  path?: "deterministic" | "ai";             // which extraction path ran (#10)
}

export class ImportMetaStore {
  constructor(private readonly cases: CaseStore) {}

  private path(caseId: string): string {
    return join(this.cases.stateDir(caseId), "import-meta.json");
  }

  async load(caseId: string): Promise<ImportMeta> {
    try {
      return importMetaSchema.parse(JSON.parse(await readFile(this.path(caseId), "utf8")));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { ...EMPTY };
      throw err;
    }
  }

  // Record a completed import: stamp the time, the kind/file, and the (capped) timeline diff.
  async record(caseId: string, rec: ImportRecord, at: string = new Date().toISOString()): Promise<ImportMeta> {
    const meta: ImportMeta = {
      lastImportedAt: at,
      lastImportKind: rec.kind,
      lastImportFile: rec.file,
      addedCount: rec.diff.added.length,
      removedCount: rec.diff.removed.length,
      lastDiff: {
        added: rec.diff.added.slice(0, MAX_LISTED),
        removed: rec.diff.removed.slice(0, MAX_LISTED),
      },
      iocsAddedCount: rec.iocsDiff.added.length,
      iocsRemovedCount: rec.iocsDiff.removed.length,
      iocsDiff: {
        added: rec.iocsDiff.added.slice(0, MAX_LISTED),
        removed: rec.iocsDiff.removed.slice(0, MAX_LISTED),
      },
      linesIn: Math.max(0, Math.floor(rec.linesIn ?? 0)),
      path: rec.path ?? "",
    };
    await atomicWrite(this.path(caseId), JSON.stringify(meta, null, 2));
    return meta;
  }

  // Reset the record to "no import" — used when an import is UNDONE (#76), so the dashboard's
  // "📥 last import - +N new events" banner and the per-row NEW highlights no longer describe a
  // change that has been rolled back. Writes EMPTY rather than deleting the file (no ENOENT race).
  async clear(caseId: string): Promise<ImportMeta> {
    const meta: ImportMeta = { ...EMPTY };
    await atomicWrite(this.path(caseId), JSON.stringify(meta, null, 2));
    return meta;
  }
}

// Source-yield anomaly (investigation-guidance #10). Trigger (a): a large file run through the AI-triage
// path (log/CSV) that produced ZERO graded events — the northpeak failure, where a 27,290-line proxy
// log contributed nothing and read as "source clean". Deterministic + pure over the persisted meta.
export interface ImportYieldWarning {
  reason: "zero_yield_ai";
  file: string;
  kind: string;
  linesIn: number;
  message: string;            // directive next-action for the analyst
  inferredPhases: string[];   // ATT&CK phases this source type would have evidenced (for the gap panel)
}

export const ZERO_YIELD_MIN_LINES_DEFAULT = 500;

// The ATT&CK phases a dropped source type would most likely have evidenced — so a zero-yield proxy log
// becomes "you may be missing Discovery / C2 / Exfiltration", not just "0 events". Best-effort by name.
function inferPhasesFromSource(kind: string, file: string): string[] {
  const t = `${kind} ${file}`.toLowerCase();
  if (/proxy|squid|bluecoat|web[_-]?access|http/.test(t)) return ["Discovery", "Command and Control", "Exfiltration"];
  if (/\bdns\b/.test(t)) return ["Command and Control", "Exfiltration"];
  if (/firewall|fw|netflow|flow|zeek|bro|conn/.test(t)) return ["Command and Control", "Exfiltration"];
  if (/vpn|auth|radius|okta|sso/.test(t)) return ["Initial Access", "Lateral Movement"];
  if (/mail|smtp|exchange|o365|m365/.test(t)) return ["Initial Access"];
  return [];
}

export function classifyImportYield(
  meta: Pick<ImportMeta, "path" | "addedCount" | "linesIn" | "lastImportKind" | "lastImportFile">,
  opts: { minLines?: number } = {},
): ImportYieldWarning | null {
  const minLines = opts.minLines ?? ZERO_YIELD_MIN_LINES_DEFAULT;
  if (meta.path !== "ai") return null;                 // only the AI-triage path can silently drop everything
  if ((meta.addedCount ?? 0) > 0) return null;         // it produced events → not a blind spot
  const linesIn = meta.linesIn ?? 0;
  if (linesIn < minLines) return null;                 // a genuinely tiny/empty file isn't a coverage gap
  const label = meta.lastImportFile || meta.lastImportKind || "an imported file";
  return {
    reason: "zero_yield_ai",
    file: meta.lastImportFile,
    kind: meta.lastImportKind,
    linesIn,
    message: `${label}: ${linesIn.toLocaleString()} lines → 0 events via AI triage — re-run triage or grep the raw file for the case's IOCs/hosts before treating this source as clean`,
    inferredPhases: inferPhasesFromSource(meta.lastImportKind, meta.lastImportFile),
  };
}
