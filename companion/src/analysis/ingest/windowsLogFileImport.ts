import { readFile } from "node:fs/promises";
import { parseSiemExport } from "../siemImport.js";
import { parseSiemJsonLinesFile } from "../siemJsonLinesFile.js";
import { parseEvtxXmlFile } from "../evtxXmlFile.js";
import { decodeImportedText } from "../../ingest/decodeText.js";
import type { ImportDebugRecorder } from "../importDebug.js";
import type { InvestigationState, Severity } from "../stateTypes.js";
import type { ImportContext } from "./importContext.js";
import { commitEvtxXmlParsed, commitSiemParsed, evtxXmlParseProgress } from "./platformImports.js";

/**
 * The two Windows-log importers that measured a memory peak following the FILE (#2814), read from the
 * stored evidence file in parts (#2823): a SIEM / EDR JSON Lines export and a Windows Event XML
 * export. Each parses with its streamed twin (analysis/siemJsonLinesFile.ts, analysis/evtxXmlFile.ts)
 * and commits through the very tail its whole-text importer uses (platformImports.ts), so the events,
 * IOCs, timeline note, severity floor and capped-import note are the whole-text importer's.
 *
 * The route decides a file streams (routes/importWindowsLogStream.ts) only when it can: UTF-8, 32 MB
 * or more, and for SIEM a JSON Lines head. A SIEM file whose JSON Lines lines yield no record at all is
 * parsed whole here after all — the whole-text importer's last-resort branch, which needs the text.
 */

export type WindowsLogStreamKind = "siem" | "evtxxml";

export interface WindowsLogFileOptions {
  label: string;
  idPrefix: string;
  importedAt: string;
  minSeverity?: Severity;
  onProgress?: (done: number, total: number) => void | Promise<void>;
  onParseProgress?: (done: number, total: number, detail?: string) => void | Promise<void>;
  debug?: ImportDebugRecorder;
  signal?: AbortSignal;
  startBatch?: number;
}

export async function importWindowsLogFile(
  ctx: ImportContext,
  caseId: string,
  kind: WindowsLogStreamKind,
  storedPath: string,
  opts: WindowsLogFileOptions,
): Promise<InvestigationState> {
  const siem = { debug: opts.debug };
  if (kind === "siem") {
    const parsed =
      (await parseSiemJsonLinesFile(storedPath, siem, { signal: opts.signal })) ??
      parseSiemExport(decodeImportedText(await readFile(storedPath)), siem);
    return commitSiemParsed(ctx, caseId, parsed, opts);
  }
  if ((opts.startBatch ?? 0) >= 1) {
    // A resumed job whose one batch already committed, as importEvtxXml answers it.
    await opts.onProgress?.(1, 1);
    return ctx.opts.stateStore.load(caseId);
  }
  const progress = evtxXmlParseProgress(opts.onParseProgress);
  const parsed = await parseEvtxXmlFile(storedPath, siem, progress.read, progress.process, opts.signal);
  return commitEvtxXmlParsed(ctx, caseId, parsed, opts);
}
