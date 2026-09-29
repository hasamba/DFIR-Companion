import { createHash } from "node:crypto";
import { normalizeReportMeta, reportMetaSchema } from "./reportMeta.js";

// The report-level half of a version / release diff (#1779). The evidence diff compares findings,
// IOCs and the forensic timeline only, so two versions that differ only in the rendered report text
// or in the analyst-authored Case Details (report-meta) used to read "no differences". This module
// names that change: whether the report text differs, and which Case Details fields changed.
//
// Pure: no I/O. Both sides go through normalizeReportMeta, so an older record that predates a meta
// field compares that field at its default value instead of reporting a phantom change.

export interface ReportTextSide {
  contentHash?: string;
  markdown: string;
  meta: unknown;
}

export interface ReportTextDiff {
  /** The rendered report text differs (content hash, or the markdown when a hash is missing). */
  textChanged: boolean;
  /** Top-level report-meta keys whose value differs, in reportMetaSchema key order. */
  caseDetailsChanged: string[];
}

const META_KEYS = Object.keys(reportMetaSchema.shape);

function textDiffers(from: ReportTextSide, to: ReportTextSide): boolean {
  if (from.contentHash && to.contentHash) return from.contentHash !== to.contentHash;
  return from.markdown !== to.markdown;
}

export function diffReportText(from: ReportTextSide, to: ReportTextSide): ReportTextDiff {
  const a: Record<string, unknown> = normalizeReportMeta(from.meta);
  const b: Record<string, unknown> = normalizeReportMeta(to.meta);
  return {
    textChanged: textDiffers(from, to),
    caseDetailsChanged: META_KEYS.filter((key) => JSON.stringify(a[key]) !== JSON.stringify(b[key])),
  };
}

/** sha256 of the normalized report-meta — lets the version store dedupe on meta as well as text. */
export function reportMetaHash(meta: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(normalizeReportMeta(meta)))
    .digest("hex");
}
