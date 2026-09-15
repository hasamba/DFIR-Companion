// KAPE's own acquisition provenance (#932 item 1): what `_copylog.csv` /
// `_skiplog.csv` state about ONE collection run — every file the tool actually copied, or
// deliberately did not, with the tool's own hash/size/timestamp for each. A sibling to
// kapeImport.ts (#931 item 8's own "many small files" convention), never an addition to it: that
// file's own `PROFILES` shape assumes one row describes artifact CONTENT (a ShimCache entry, a
// Prefetch run); an acquisition-log row describes ACQUISITION of a file, a different concept.
//
// What this module never says: that a file being copied means it was later PARSED, or that its
// parser's output was ever IMPORTED into this case — "copied" is not "examined". It is never
// wired into refutationGate.ts's own refutation-downgrade logic; a real, SCOPED (host / volume /
// run / interval) version of that integration is #1101, filed separately after this design's own
// first draft tried to do it unsafely (Codex design review, RECOMMENDATION-932.1.md). A skipped
// file's own reason (Excluded / Deduped) is disclosed as a fact, never treated as proof anything
// was examined. Verified against KAPE's own documentation
// (github.com/EricZimmerman/KapeDocs, Pages/4.-Log-files.md) — not invented.

import { createHash } from "node:crypto";
import { parseCsv } from "./csvImport.js";
import {
  aggregateEvents,
  getCI,
  normalizeTime,
  str,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { AcquisitionFact, AcquisitionLogKind } from "./canonicalAcquisition.js";

type Row = Record<string, unknown>;

export const ACQUISITION_FACTS_MAX = 256;
const NAME_MAX = 260; // a Windows MAX_PATH-scale bound; a path longer than this is still shown, just clipped
const BASIS =
  "each file's own SHA-1, recorded at the source by the acquisition tool; not a container or disk-image hash, and this log does not verify the destination copy against it" as const;

export interface KapeAcquisitionOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface KapeAcquisitionResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  artifact: string;
  format: string;
}

const show = (v: string, max = NAME_MAX): string => (v.length > max ? `${v.slice(0, max - 1)}…` : v);

const COPYLOG_HEADERS = [
  "copiedtimestamp",
  "sourcefile",
  "destinationfile",
  "filesize",
  "sourcefilesha1",
  "deferredcopy",
  "createdonutc",
  "modifiedonutc",
  "lastaccessedonutc",
  "copyduration",
];
const SKIPLOG_HEADERS = ["sourcefile", "sourcefilesha1", "reason"];
const SKIP_REASONS = new Set(["excluded", "deduped"]);

/** All of KAPE's own documented copylog columns are present (#932 item 1, Codex design review
 * finding #9 — a loose 2-3 column signature risked misclaiming an unrelated CSV). */
export function isKapeCopyLog(headers: readonly string[]): boolean {
  const h = new Set(headers.map((x) => x.trim().toLowerCase()));
  return COPYLOG_HEADERS.every((c) => h.has(c));
}

/** All three documented skiplog columns are present AND a sample of `Reason` values are drawn
 * from KAPE's own closed vocabulary — an unrelated 3-column CSV sharing generic names is never
 * misclaimed (#932 item 1, Codex design review finding #9). */
export function isKapeSkipLog(headers: readonly string[], rows: readonly string[][]): boolean {
  const h = new Set(headers.map((x) => x.trim().toLowerCase()));
  if (!SKIPLOG_HEADERS.every((c) => h.has(c))) return false;
  const reasonIdx = headers.findIndex((x) => x.trim().toLowerCase() === "reason");
  if (reasonIdx < 0) return false;
  const sample = rows.slice(0, 20).map((r) => (r[reasonIdx] ?? "").trim().toLowerCase());
  return sample.length > 0 && sample.every((v) => SKIP_REASONS.has(v));
}

function bool(v: unknown): boolean | undefined {
  const s = str(v).trim().toLowerCase();
  if (s === "true") return true;
  if (s === "false") return false;
  return undefined;
}

function num(v: unknown): number | undefined {
  const s = str(v).trim();
  if (!s) return undefined;
  const n = Number(s);
  return Number.isFinite(n) ? n : undefined;
}

interface Scanned {
  facts: AcquisitionFact[];
  notCited: number;
  malformedRows: number;
  first: string;
  last: string;
}

function scanCopyLog(rows: readonly Row[]): Scanned {
  const facts: AcquisitionFact[] = [];
  let notCited = 0;
  let malformedRows = 0;
  let first = "";
  let last = "";
  for (const r of rows) {
    const sourceFile = str(getCI(r, "SourceFile")).trim();
    if (!sourceFile) {
      malformedRows += 1;
      continue;
    }
    const t = str(getCI(r, "CopiedTimestamp")).trim();
    if (t) {
      const n = normalizeTime(t);
      if (!first || n < first) first = n;
      if (!last || n > last) last = n;
    }
    if (facts.length < ACQUISITION_FACTS_MAX) {
      facts.push({
        sourceFile: show(sourceFile),
        sha1: str(getCI(r, "SourceFileSha1")).trim() || undefined,
        fileSize: num(getCI(r, "FileSize")),
        deferredCopy: bool(getCI(r, "DeferredCopy")),
      });
    } else notCited += 1;
  }
  return { facts, notCited, malformedRows, first, last };
}

function scanSkipLog(rows: readonly Row[]): Scanned {
  const facts: AcquisitionFact[] = [];
  let notCited = 0;
  let malformedRows = 0;
  for (const r of rows) {
    const sourceFile = str(getCI(r, "SourceFile")).trim();
    if (!sourceFile) {
      malformedRows += 1;
      continue;
    }
    if (facts.length < ACQUISITION_FACTS_MAX) {
      facts.push({
        sourceFile: show(sourceFile),
        sha1: str(getCI(r, "SourceFileSha1")).trim() || undefined,
        reason: str(getCI(r, "Reason")).trim() || undefined,
      });
    } else notCited += 1;
  }
  return { facts, notCited, malformedRows, first: "", last: "" };
}

function toRows(headers: string[], rawRows: string[][]): Row[] {
  return rawRows.map((cols) => {
    const row: Row = {};
    headers.forEach((h, i) => {
      row[h.trim()] = cols[i] ?? "";
    });
    return row;
  });
}

function summarize(
  logKind: AcquisitionLogKind,
  scanned: Scanned,
  uploadId: string,
): { event: MappedEvent; iocs: SiemIoc[] } {
  const { facts, notCited, malformedRows } = scanned;
  const deferred = facts.filter((f) => f.deferredCopy).length;
  const byReason = new Map<string, number>();
  for (const f of facts) if (f.reason) byReason.set(f.reason, (byReason.get(f.reason) ?? 0) + 1);

  const head =
    logKind === "copied"
      ? `KAPE acquisition: ${facts.length + notCited} file(s) copied`
      : `KAPE acquisition: ${facts.length + notCited} file(s) skipped`;
  const parts = [
    logKind === "copied" && deferred
      ? `${deferred} via a deferred (raw-disk) read — the source was locked`
      : "",
    logKind === "skipped" ? [...byReason.entries()].map(([r, n]) => `${n} ${r}`).join(", ") : "",
    scanned.first && scanned.last ? `collected ${scanned.first} – ${scanned.last}` : "",
    malformedRows ? `${malformedRows} row(s) in this log named no source file — not counted` : "",
    notCited ? `${notCited} further file(s) not individually cited` : "",
  ].filter(Boolean);
  const description = `${head}${parts.length ? ` — ${parts.join("; ")}` : ""}`.slice(0, 600);

  const observed = scanned.first || new Date(0).toISOString();
  const event: MappedEvent = {
    timestamp: normalizeTime(observed) || "",
    description,
    severity: "Info",
    mitre: [],
    aggKey: `kape-acquisition|${logKind}|${uploadId}`,
    sources: ["KAPE"],
    artifactName: logKind === "copied" ? "KAPE.Acquisition.CopyLog" : "KAPE.Acquisition.SkipLog",
    canonical: createCanonicalEvent({
      event: { category: "file", type: "acquisition", action: logKind, outcome: "success" },
      time: { observed, normalized: normalizeTime(observed) || "" },
      evidence: { rawRecords: [{ source: "kape-acquisition", locator: uploadId }] },
      producer: {
        importer: "kape-acquisition",
        parserVersion: "1",
        mappingVersion: "kape-acquisition-v1",
      },
      acquisitionCoverage: {
        tool: "kape",
        logKind,
        facts,
        notCited,
        malformedRows,
        ...(logKind === "copied" && scanned.first
          ? { coverage: { first: scanned.first, last: scanned.last } }
          : {}),
        basis: BASIS,
      },
    }),
  };
  return { event, iocs: [] };
}

/** A KAPE `_copylog.csv` or `_skiplog.csv`, or null when neither log's own header matches. No
 * external upload id is threaded in (kapeImport.ts's own `KapeImportOptions` carries none) — the
 * locator is a content hash of the CSV text itself, deterministic and unique enough for the same
 * purpose. */
export function parseKapeAcquisitionLog(
  text: string,
  opts: KapeAcquisitionOptions = {},
): KapeAcquisitionResult | null {
  const { headers, rows: rawRows } = parseCsv(text);
  if (!headers.length) return null;
  const isCopy = isKapeCopyLog(headers);
  const isSkip = !isCopy && isKapeSkipLog(headers, rawRows);
  if (!isCopy && !isSkip) return null;

  const uploadId = createHash("sha256").update(text).digest("hex").slice(0, 16);
  const rows = toRows(headers, rawRows);
  const scanned = isCopy ? scanCopyLog(rows) : scanSkipLog(rows);
  const { event } = summarize(isCopy ? "copied" : "skipped", scanned, uploadId);
  const mapped: MappedEvent[] = [event];
  const { events, groups } = aggregateEvents(mapped, {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? 1,
  });
  const artifact = isCopy ? "KapeAcquisitionCopyLog" : "KapeAcquisitionSkipLog";
  return {
    events,
    iocs: [],
    total: rawRows.length,
    kept: events.length,
    dropped: 0,
    groups,
    artifact,
    format: artifact,
  };
}
