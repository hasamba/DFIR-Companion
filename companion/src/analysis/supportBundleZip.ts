import { createZip, type ZipEntry } from "./zipArchive.js";
import type { ImportShape } from "./importShape.js";
import type { ImportDebugSummary } from "./importDebug.js";

// Pure pieces of the redacted support bundle (#1735): the line-safe log tail, the README, and the
// archive layout. The I/O and the redaction order live in reports/supportBundleBuilder.ts. Nothing
// here sees an unredacted value: every string that reaches assembleSupportBundle has already been
// through the support redactor, so this module only arranges and describes.

/** Per-log caps on what goes into the zip. Big enough for a session's worth of import lines, small
 * enough that redacting and zipping one request stays well under a few seconds. */
export const SUPPORT_LOG_CAPS = {
  sessionBytes: 5 * 1024 * 1024,
  caseBytes: 5 * 1024 * 1024,
  debugBytes: 10 * 1024 * 1024,
} as const;

export const SUPPORT_MAX_SHAPE_REPORTS = 10;

/**
 * The last `maxBytes` of `buf`, cut on a line boundary. A byte-offset tail can start halfway through
 * an API key or a hostname, and the half that is left no longer matches the value the redactor knows,
 * so the first partial line is always dropped. The result is decoded only after the cut, so a
 * multi-byte character is never split either.
 */
export function tailLines(buf: Buffer, maxBytes: number): { text: string; truncated: boolean } {
  if (buf.length <= maxBytes) return { text: buf.toString("utf8"), truncated: false };
  const start = buf.length - maxBytes;
  const nl = buf.indexOf(0x0a, start);
  if (nl === -1) return { text: "", truncated: true };
  return { text: buf.subarray(nl + 1).toString("utf8"), truncated: true };
}

/** Same rule for a string that is already redacted (tokens can make a line longer than its source). */
export function tailText(text: string, maxBytes: number): { text: string; truncated: boolean } {
  return tailLines(Buffer.from(text, "utf8"), maxBytes);
}

/** A row number, only when the error message itself states one. Never guessed from the file. */
export function rowFromMessage(message: string): number | undefined {
  const m = /\b(?:line|row|record)\s*[:#]?\s*(\d{1,12})\b/i.exec(message);
  return m ? Number(m[1]) : undefined;
}

export interface SupportImportReport {
  at: string;
  kind: string;
  caseToken: string;
  fileToken: string;
  error: string;
  row?: number;
  shape?: ImportShape;
  /** What the importer decided before it failed (#1736). Sanitized at record time and again here. */
  importer?: ImportDebugSummary;
  /** Why no shape: the file is gone, the case is locked, the scan budget ran out, … */
  shapeUnavailable?: string;
}

export interface SupportLogPart {
  text: string;
  truncated: boolean;
  /** Present when the log was not included; says why (in plain words, no values). */
  omitted?: string;
}

export interface SupportBundleParts {
  generatedAt: string;
  version: string;
  diagnosticsText: string;
  supportJson: string;
  sessionLog: SupportLogPart;
  debugLog: SupportLogPart;
  caseLog?: SupportLogPart;
  caseToken?: string;
  imports: SupportImportReport[];
  importsOmitted: string[];
  summary: Record<string, number>;
  withheldCases: number;
}

export function supportBundleFilename(generatedAt: string): string {
  const stamp = generatedAt.replace(/[:.]/g, "-").slice(0, 19);
  return `dfir-companion-support-${stamp}.zip`;
}

function describeLog(label: string, file: string, part: SupportLogPart | undefined): string {
  if (!part) return `- ${file}: not requested.`;
  if (part.omitted) return `- ${file}: not included — ${part.omitted}`;
  const cut = part.truncated ? " Only the newest part is included (size cap)." : "";
  return `- ${file}: ${label}.${cut}`;
}

export function buildSupportReadme(p: SupportBundleParts): string {
  const counts = Object.entries(p.summary)
    .filter(([, n]) => n > 0)
    .map(([cat, n]) => `  ${cat}: ${n}`)
    .join("\n");
  return [
    "DFIR Companion — redacted support bundle",
    "",
    `Generated: ${p.generatedAt}`,
    `Version:   ${p.version}`,
    "",
    "WHAT IS IN THIS ZIP",
    "- diagnostics.txt: the Settings → Diagnostics report (versions, settings state, error lists).",
    "- support.json: evidence-free performance and capacity metrics.",
    describeLog("the server log for this run", "logs/session.log", p.sessionLog),
    describeLog(
      "every log line at every level, including debug (always recorded)",
      "logs/debug.log",
      p.debugLog,
    ),
    describeLog(
      `the log of the open case${p.caseToken ? ` (${p.caseToken})` : ""}`,
      "logs/case.log",
      p.caseLog,
    ),
    "- imports/failure-N.json: one per failed import — format, encoding, row count and column TYPES.",
    "  Column NAMES appear only when they are generic forensic names from a fixed list; anything",
    "  else shows as <unlisted>. No cell value from any file is included.",
    ...p.importsOmitted.map((why) => `  Not included: ${why}`),
    "- redaction-summary.json: how many values of each kind were replaced. Never the values.",
    "",
    "HOW IT WAS REDACTED",
    "Every case name, case ID, investigator, file name, hostname, username, IP address (internal AND",
    "public), email, domain, file path, URL and configured secret was replaced before this zip was",
    "written. The same real value has the same placeholder in every file (for example ANON_HOST_3),",
    "so one host can be followed across logs. The list that maps placeholders back to real values was",
    "never written anywhere — it existed only while this zip was built.",
    p.withheldCases > 0
      ? `Lines of ${p.withheldCases} case(s) whose names could not be loaded were withheld, not sent.`
      : "",
    "",
    "Read every file before you send it. A redactor can miss a value it has never seen.",
    "",
    "Replaced values:",
    counts || "  none",
    "",
  ]
    .filter((line, i, all) => !(line === "" && all[i - 1] === ""))
    .join("\n");
}

export function assembleSupportBundle(p: SupportBundleParts): Buffer {
  const text = (path: string, body: string): ZipEntry => ({ path, data: Buffer.from(body, "utf8") });
  const entries: ZipEntry[] = [
    text("README.txt", buildSupportReadme(p)),
    text("diagnostics.txt", p.diagnosticsText),
    text("support.json", p.supportJson),
    text("redaction-summary.json", JSON.stringify(p.summary, null, 2)),
  ];
  if (!p.sessionLog.omitted) entries.push(text("logs/session.log", p.sessionLog.text));
  if (!p.debugLog.omitted) entries.push(text("logs/debug.log", p.debugLog.text));
  if (p.caseLog && !p.caseLog.omitted) entries.push(text("logs/case.log", p.caseLog.text));
  p.imports.forEach((r, i) =>
    entries.push(text(`imports/failure-${i + 1}.json`, JSON.stringify(r, null, 2))),
  );
  return createZip(entries);
}
