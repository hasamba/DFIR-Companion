import { filePath, sameLocation, hashVeto, type FilePath } from "./downloadExecution.js";
import type { TimelineEventShape } from "./downloadCorroborationShared.js";
import { resolveHost, type HostAliasIndex } from "./hostAlias.js";
import {
  attestedDigest,
  type StaticReportAttestation,
  type StaticReportTool,
} from "./staticReportAttestationStore.js";

// The read-time join an analyst attestation makes sound (#1316): which victim-host rows name the
// same location (olevba's own documentPath, on the attested host, through the attested volume
// mapping) or the same content (the attested digest) as a static-analysis report. Never persisted,
// never a merge-time mutation, never a severity change on either side (933.20 / #993 read-time
// convention). Every row states its own basis; the attestation itself is a claim the system did
// not and cannot verify, and the response says so.

export const STATIC_REPORT_ATTESTATION_CAVEAT =
  "an attestation is an analyst's claim, never a verification; the system did not and cannot confirm the report was produced from this host";

export const STATIC_REPORT_MATCH_ROWS_MAX = 50;

// Report rows carry no time and no host; a process-creation row names a document only in its
// command line, which this join does not read.
export const PATH_JOIN_CONTRACT =
  "path rows read a victim row's own top-level path only (a process-creation row naming the document in its command line is not read), so an empty result never means the file was never opened or executed; the staged copy must keep the victim's relative path below the mount for a match to be possible";

interface FingerprintBlock {
  reportFingerprint: string;
  documentPath?: string;
  sampleHash?: { sha256?: string; md5?: string; hashUnavailable?: boolean };
}

export interface StaticReportEventShape extends TimelineEventShape {
  canonical?: TimelineEventShape["canonical"] & {
    olevbaFinding?: FingerprintBlock;
    olevbaStompingLead?: FingerprintBlock;
    olevbaCompoundLead?: FingerprintBlock;
    capaMatch?: FingerprintBlock;
    capaCompositeLead?: FingerprintBlock;
    decodedString?: FingerprintBlock;
    mobileRequestedPermission?: FingerprintBlock;
  };
}

const BLOCKS: ReadonlyArray<[keyof NonNullable<StaticReportEventShape["canonical"]>, StaticReportTool]> = [
  ["olevbaFinding", "olevba"],
  ["olevbaStompingLead", "olevba"],
  ["olevbaCompoundLead", "olevba"],
  ["capaMatch", "capa"],
  ["capaCompositeLead", "capa"],
  ["decodedString", "floss"],
  ["mobileRequestedPermission", "mobsf"],
];

function reportBlock(e: StaticReportEventShape): { block: FingerprintBlock; tool: StaticReportTool } | null {
  for (const [key, tool] of BLOCKS) {
    const block = e.canonical?.[key] as FingerprintBlock | undefined;
    if (block?.reportFingerprint) return { block, tool };
  }
  return null;
}

export interface ReportEvents<T> {
  tool: StaticReportTool;
  events: T[];
  toolReportedSha256: string | undefined;
  toolReportedMd5: string | undefined;
}

/** Every event a fingerprint is stamped on, the tool that stamped it, and the sample hash the
 * tool itself reported (capa/FLOSS metadata; olevba never has one). Null when no event carries it. */
export function reportEventsByFingerprint<T extends StaticReportEventShape>(
  events: readonly T[],
  fingerprint: string,
): ReportEvents<T> | null {
  const fp = fingerprint.toLowerCase();
  let tool: StaticReportTool | undefined;
  let toolReportedSha256: string | undefined;
  let toolReportedMd5: string | undefined;
  const matched: T[] = [];
  for (const e of events) {
    const found = reportBlock(e);
    if (!found || found.block.reportFingerprint.toLowerCase() !== fp) continue;
    tool ??= found.tool;
    const hash = found.block.sampleHash;
    if (hash && !hash.hashUnavailable) {
      toolReportedSha256 ??= hash.sha256?.toLowerCase();
      toolReportedMd5 ??= hash.md5?.toLowerCase();
    }
    matched.push(e);
  }
  return tool ? { tool, events: matched, toolReportedSha256, toolReportedMd5 } : null;
}

// Analyst-side rows, by PROVENANCE (design review M-4/L-3): the report tools themselves, PE-sieve,
// and the raw CLI YARA importer (`sources` ["YARA"] alone — yaraImport.ts's own header says it is
// an analyst-workstation scan). A SO-CRATES row carries ["SO-CRATES","YARA"] and a Velociraptor
// YARA row no "YARA" at all — both are victim-side hunts and must NOT be excluded.
// Spellings pinned by tests against the real importers' own output (olevbaResultImport.ts
// "olevba", capaResultImport.ts "capa", flossResultImport.ts "FLOSS", pesieveImport.ts "PE-sieve",
// yaraImport.ts YARA_SOURCE "YARA").
const ANALYST_SOURCES = new Set(["olevba", "capa", "FLOSS", "PE-sieve", "YARA", "mobsf"]);
const VICTIM_SIDE_SOURCES = new Set(["SO-CRATES", "Velociraptor"]);
export function isAnalystSideRow(e: StaticReportEventShape): boolean {
  if (reportBlock(e)) return true;
  const sources = e.sources ?? [];
  if (sources.some((s) => VICTIM_SIDE_SOURCES.has(s))) return false;
  return sources.some((s) => ANALYST_SOURCES.has(s));
}

export interface StaticReportMatchRow {
  eventId: string;
  timestamp: string;
  host: string;
  hostIsAttestedSubject: boolean;
  identity: "path-only" | "analyst-attested-digest" | "tool-reported-digest";
  victimPath?: string;
  victimSha256?: string;
  volumeNote?: string;
  digestConflict?: boolean;
  digestAgrees?: boolean;
  basis: string;
}

export interface StaticReportMatchKind {
  rows: StaticReportMatchRow[];
  truncated: number;
  excludedAnalystSide: number;
  basis?: string;
  skipped?: string;
}

export interface StaticReportMatches {
  attestationId: string;
  attestationRevoked: boolean;
  caveat: string;
  contract: string;
  path: StaticReportMatchKind;
  hash: StaticReportMatchKind;
  diagnostics: {
    reportPresent: boolean;
    subjectHostCanonical: string;
    subjectHostKnown: boolean;
    documentOutsideAttestedMount: boolean;
    volumelessDocumentPaths: number;
    volumeMismatchWithoutMapping: number;
    volumeMismatchDespiteMapping: number;
    unattributedHostRows: number;
    md5OnlyVictimRows: number;
    pathJoinSkipped?: string;
  };
}

function byTime(a: StaticReportMatchRow, b: StaticReportMatchRow): number {
  return a.timestamp < b.timestamp
    ? -1
    : a.timestamp > b.timestamp
      ? 1
      : a.eventId < b.eventId
        ? -1
        : a.eventId > b.eventId
          ? 1
          : 0;
}

function bound(rows: StaticReportMatchRow[]): { rows: StaticReportMatchRow[]; truncated: number } {
  const sorted = [...rows].sort(byTime);
  return {
    rows: sorted.slice(0, STATIC_REPORT_MATCH_ROWS_MAX),
    truncated: Math.max(0, sorted.length - STATIC_REPORT_MATCH_ROWS_MAX),
  };
}

/** The staged path with the attested victim volume in place of the mount it was read from — the
 * substitution IS the comparison (review H-1), and it is earned only when the staged path really
 * sits under the attested mount (H-2). */
function effectiveStagedPath(
  staged: FilePath,
  volume: StaticReportAttestation["evidenceVolume"],
): { effective: FilePath; outsideMount: boolean } {
  if (!volume) return { effective: staged, outsideMount: false };
  const underMount =
    staged.volumeKind === volume.mountPoint.volumeKind && staged.volume === volume.mountPoint.volume;
  if (!underMount) return { effective: staged, outsideMount: true };
  if (!volume.originalVolume) return { effective: staged, outsideMount: false };
  return { effective: { ...volume.originalVolume, relative: staged.relative }, outsideMount: false };
}

export function staticReportMatches<T extends StaticReportEventShape>(input: {
  attestation: StaticReportAttestation;
  events: readonly T[];
  aliasIndex: HostAliasIndex;
}): StaticReportMatches {
  const { attestation: att, events, aliasIndex } = input;
  const revoked = Boolean(att.revokedAt);
  const prefix = revoked ? "ATTESTATION REVOKED — " : "";
  const subject = resolveHost(aliasIndex, att.subjectHost);
  const hostOf = (e: T): string | undefined => (e.asset ? resolveHost(aliasIndex, e.asset) : undefined);
  // Known through a VICTIM row only — an analyst-workstation row naming the subject host proves
  // nothing about the victim (review #14).
  const subjectHostKnown = events.some((e) => !isAnalystSideRow(e) && hostOf(e) === subject);
  const report = reportEventsByFingerprint(events, att.reportFingerprint);

  const diagnostics: StaticReportMatches["diagnostics"] = {
    reportPresent: report !== null,
    subjectHostCanonical: subject,
    subjectHostKnown,
    documentOutsideAttestedMount: false,
    volumelessDocumentPaths: 0,
    volumeMismatchWithoutMapping: 0,
    volumeMismatchDespiteMapping: 0,
    unattributedHostRows: 0,
    md5OnlyVictimRows: 0,
  };

  const attestedWhen = `attested by ${att.attestedBy} at ${att.attestedAt}`;
  // The digest this attestation binds to the host: the analyst's own, else the one the tool's own
  // sample metadata reported (capa/FLOSS) — the same value the store's one-host-per-document rule
  // already binds (review #1). Which one it was is stated on every hash row.
  const digest = attestedDigest(att);
  const digestProvenance = att.documentSha256
    ? "digest supplied by the analyst's attestation of the staged copy"
    : "digest read from the tool's own sample metadata, not hashed by the analyst";

  // ── path kind ──
  const pathRows: StaticReportMatchRow[] = [];
  let pathExcluded = 0;
  const mismatchNoMapping = new Set<string>();
  const mismatchDespiteMapping = new Set<string>();
  const documentPaths = new Set<string>();
  for (const e of report?.events ?? []) {
    const p = reportBlock(e)?.block.documentPath;
    if (p) documentPaths.add(p);
  }
  const staged = [...documentPaths].map((p) => filePath(p)).filter((p): p is FilePath => p !== null);
  diagnostics.volumelessDocumentPaths = staged.filter((s) => s.volumeKind === "none").length;
  const placeable = staged.filter((s) => s.volumeKind !== "none");
  if (report?.tool !== "olevba") {
    diagnostics.pathJoinSkipped = report
      ? `${report.tool} reports carry no document path`
      : "report not present in this case";
  } else if (staged.length === 0) {
    diagnostics.pathJoinSkipped = "the report names no document path";
  } else if (placeable.length === 0) {
    diagnostics.pathJoinSkipped =
      "document path names no volume — a staged path without a drive, GUID or device cannot be placed on the victim";
  } else {
    for (const s of placeable) {
      const { effective, outsideMount } = effectiveStagedPath(s, att.evidenceVolume);
      if (outsideMount) {
        // The staged copy is not under the attested mount, so the attested mapping says nothing
        // about it — a raw comparison would produce rows indistinguishable from a mapping-earned
        // match (review #2). Skipped and said, never compared as written.
        diagnostics.documentOutsideAttestedMount = true;
        diagnostics.pathJoinSkipped =
          "the staged document is not under the attested mount point — the attested volume mapping cannot place it, so no path rows were computed";
        continue;
      }
      for (const e of events) {
        if (!e.path) continue;
        const victim = filePath(e.path);
        if (!victim) continue;
        const loc = sameLocation(effective, victim);
        if (!loc.same) {
          if (
            victim.relative === effective.relative &&
            victim.volumeKind === effective.volumeKind &&
            !isAnalystSideRow(e) &&
            hostOf(e) === subject
          ) {
            (att.evidenceVolume?.originalVolume ? mismatchDespiteMapping : mismatchNoMapping).add(e.id ?? "");
          }
          continue;
        }
        if (isAnalystSideRow(e)) {
          pathExcluded += 1;
          continue;
        }
        const host = hostOf(e);
        if (!host) {
          diagnostics.unattributedHostRows += 1;
          continue;
        }
        if (host !== subject) continue;
        const victimSha = e.sha256?.toLowerCase();
        const conflict = Boolean(digest) && hashVeto({ sha256: digest }, e);
        const agrees = Boolean(digest) && victimSha === digest;
        pathRows.push({
          eventId: e.id ?? "",
          timestamp: e.timestamp ?? "",
          host,
          hostIsAttestedSubject: true,
          identity: "path-only",
          victimPath: e.path,
          ...(e.sha256 ? { victimSha256: e.sha256 } : {}),
          ...(loc.volumeNote ? { volumeNote: loc.volumeNote } : {}),
          ...(conflict ? { digestConflict: true } : {}),
          ...(agrees ? { digestAgrees: true } : {}),
          basis: conflict
            ? `${prefix}same path on the attested subject host, but the victim row's own digest DISAGREES with the attested document — a different file at this path; host identity ${attestedWhen}`
            : agrees
              ? `${prefix}same path on the attested subject host, and the victim row's own digest AGREES with the attested document (${digestProvenance}); host identity ${attestedWhen}`
              : `${prefix}same path on the attested subject host; host identity ${attestedWhen}, not hash-verified — a different file could occupy this path at a different time`,
        });
      }
    }
  }
  diagnostics.volumeMismatchWithoutMapping = mismatchNoMapping.size;
  diagnostics.volumeMismatchDespiteMapping = mismatchDespiteMapping.size;

  // ── hash kind ──
  const hashRows: StaticReportMatchRow[] = [];
  let hashExcluded = 0;
  let hashBasis: string | undefined;
  let hashSkipped: string | undefined;
  for (const e of events) {
    if (!e.sha256 && e.md5 && !isAnalystSideRow(e)) diagnostics.md5OnlyVictimRows += 1;
  }
  if (!digest) {
    hashSkipped =
      "no digest available — the analyst did not hash the staged copy and the tool's own sample metadata reported none";
  } else {
    const crossCheck =
      att.digestCrossCheck === "tool-sha256"
        ? "corroborated by the tool's own sha256 of the sample"
        : att.digestCrossCheck === "tool-md5"
          ? "corroborated at md5 strength only (the tool reported only an md5, the analyst supplied a matching one)"
          : att.digestCrossCheck === "md5-only-unchecked"
            ? "not cross-checked (the tool reported only an md5 and the analyst supplied none)"
            : att.documentSha256
              ? "not cross-checked (the tool reported no digest)"
              : "the tool's own value, nothing independent to check it against";
    hashBasis = `${digestProvenance}, ${crossCheck}; sha256 equality only — an md5-only victim row can never match`;
    for (const e of events) {
      if (!e.sha256 || e.sha256.toLowerCase() !== digest) continue;
      if (isAnalystSideRow(e)) {
        hashExcluded += 1;
        continue;
      }
      const host = hostOf(e);
      if (!host) diagnostics.unattributedHostRows += 1;
      hashRows.push({
        eventId: e.id ?? "",
        timestamp: e.timestamp ?? "",
        host: host ?? "",
        hostIsAttestedSubject: host === subject,
        identity: att.documentSha256 ? "analyst-attested-digest" : "tool-reported-digest",
        victimSha256: e.sha256,
        ...(e.path ? { victimPath: e.path } : {}),
        basis: `${prefix}${hashBasis}; ${attestedWhen}`,
      });
    }
  }

  const p = bound(pathRows);
  const h = bound(hashRows);
  return {
    attestationId: att.id,
    attestationRevoked: revoked,
    caveat: STATIC_REPORT_ATTESTATION_CAVEAT,
    contract: PATH_JOIN_CONTRACT,
    path: { ...p, excludedAnalystSide: pathExcluded },
    hash: {
      ...h,
      excludedAnalystSide: hashExcluded,
      ...(hashBasis ? { basis: hashBasis } : {}),
      ...(hashSkipped ? { skipped: hashSkipped } : {}),
    },
    diagnostics,
  };
}
