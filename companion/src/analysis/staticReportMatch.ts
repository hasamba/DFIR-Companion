import { filePath, sameLocation, hashVeto, type FilePath } from "./downloadExecution.js";
import type { TimelineEventShape } from "./downloadCorroborationShared.js";
import { resolveHost, type HostAliasIndex } from "./hostAlias.js";
import type { StaticReportAttestation, StaticReportTool } from "./staticReportAttestationStore.js";

// The read-time join an analyst attestation makes sound (#1316): which victim-host rows name the
// same location (olevba's own documentPath, on the attested host, through the attested volume
// mapping) or the same content (the attested digest) as a static-analysis report. Never persisted,
// never a merge-time mutation, never a severity change on either side (933.20 / #993 read-time
// convention). Every row states its own basis; the attestation itself is a claim the system did
// not and cannot verify, and the response says so.

export const STATIC_REPORT_ATTESTATION_CAVEAT =
  "an attestation is an analyst's claim, never a verification; the system did not and cannot confirm the report was produced from this host";

export const STATIC_REPORT_MATCH_ROWS_MAX = 50;

// Reports rows carry no time and no host; a process-creation row names a document only in its
// command line, which this join does not read (top-level `path` only) — so an empty result never
// means "never executed".
export const PATH_JOIN_CONTRACT =
  "path rows read a victim row's own top-level path only; the staged copy must keep the victim's relative path below the mount for a match to be possible";

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
  };
}

const BLOCKS: ReadonlyArray<[keyof NonNullable<StaticReportEventShape["canonical"]>, StaticReportTool]> = [
  ["olevbaFinding", "olevba"],
  ["olevbaStompingLead", "olevba"],
  ["olevbaCompoundLead", "olevba"],
  ["capaMatch", "capa"],
  ["capaCompositeLead", "capa"],
  ["decodedString", "floss"],
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
const ANALYST_SOURCES = new Set(["olevba", "capa", "FLOSS", "PE-sieve"]);
function isAnalystSide(e: StaticReportEventShape): boolean {
  if (reportBlock(e)) return true;
  const sources = e.sources ?? [];
  if (sources.some((s) => ANALYST_SOURCES.has(s))) return true;
  return sources.includes("YARA") && !sources.includes("SO-CRATES") && !sources.includes("Velociraptor");
}

export interface StaticReportMatchRow {
  eventId: string;
  timestamp: string;
  host: string;
  hostIsAttestedSubject: boolean;
  identity: "path-only" | "analyst-attested-digest";
  victimPath?: string;
  victimSha256?: string;
  volumeNote?: string;
  digestConflict?: boolean;
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
    volumeMismatchWithoutMapping: number;
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
  if (!volume?.originalVolume) return { effective: staged, outsideMount: false };
  const underMount =
    staged.volumeKind === volume.mountPoint.volumeKind && staged.volume === volume.mountPoint.volume;
  if (!underMount) return { effective: staged, outsideMount: true };
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
  const subjectHostKnown = events.some((e) => hostOf(e) === subject);
  const report = reportEventsByFingerprint(events, att.reportFingerprint);

  const diagnostics: StaticReportMatches["diagnostics"] = {
    reportPresent: report !== null,
    subjectHostCanonical: subject,
    subjectHostKnown,
    documentOutsideAttestedMount: false,
    volumeMismatchWithoutMapping: 0,
    unattributedHostRows: 0,
    md5OnlyVictimRows: 0,
  };

  const attestedWhen = `attested by ${att.attestedBy} at ${att.attestedAt}`;
  const digest = att.documentSha256;

  // ── path kind ──
  const pathRows: StaticReportMatchRow[] = [];
  let pathExcluded = 0;
  const documentPaths = new Set<string>();
  for (const e of report?.events ?? []) {
    const p = reportBlock(e)?.block.documentPath;
    if (p) documentPaths.add(p);
  }
  const staged = [...documentPaths].map((p) => filePath(p)).filter((p): p is FilePath => p !== null);
  if (report?.tool !== "olevba") {
    diagnostics.pathJoinSkipped = report
      ? `${report.tool} reports carry no document path`
      : "report not present in this case";
  } else if (staged.length === 0 || staged.every((s) => s.volumeKind === "none")) {
    diagnostics.pathJoinSkipped =
      "document path names no volume — a staged path without a drive, GUID or device cannot be placed on the victim";
  } else {
    for (const s of staged) {
      if (s.volumeKind === "none") continue;
      const { effective, outsideMount } = effectiveStagedPath(s, att.evidenceVolume);
      if (outsideMount) diagnostics.documentOutsideAttestedMount = true;
      for (const e of events) {
        if (!e.path) continue;
        const victim = filePath(e.path);
        if (!victim) continue;
        const loc = sameLocation(effective, victim);
        if (!loc.same) {
          if (
            victim.relative === effective.relative &&
            !att.evidenceVolume?.originalVolume &&
            victim.volumeKind === effective.volumeKind
          )
            diagnostics.volumeMismatchWithoutMapping += 1;
          continue;
        }
        if (isAnalystSide(e)) {
          pathExcluded += 1;
          continue;
        }
        const host = hostOf(e);
        if (!host) {
          diagnostics.unattributedHostRows += 1;
          continue;
        }
        if (host !== subject) continue;
        const conflict = Boolean(digest) && hashVeto({ sha256: digest }, e);
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
          basis: conflict
            ? `${prefix}same path on the attested subject host, but the victim row's own digest DISAGREES with the attested document — a different file at this path; host identity ${attestedWhen}`
            : `${prefix}same path on the attested subject host; host identity ${attestedWhen}, not hash-verified — a different file could occupy this path at a different time`,
        });
      }
    }
  }

  // ── hash kind ──
  const hashRows: StaticReportMatchRow[] = [];
  let hashExcluded = 0;
  let hashBasis: string | undefined;
  let hashSkipped: string | undefined;
  if (!digest) {
    hashSkipped = "no digest attested — the analyst did not hash the staged copy and the tool reported none";
  } else {
    const crossCheck =
      att.digestCrossCheck === "tool-sha256"
        ? "corroborated by the tool's own sha256 of the sample"
        : att.digestCrossCheck === "md5-only-unchecked"
          ? "not cross-checked (the tool reported only an md5)"
          : "not cross-checked (the tool reported no digest)";
    hashBasis = `digest supplied by the analyst's attestation of the staged copy, ${crossCheck}; sha256 equality only — an md5-only victim row can never match`;
    for (const e of events) {
      if (!e.sha256) {
        if (e.md5) diagnostics.md5OnlyVictimRows += 1;
        continue;
      }
      if (e.sha256.toLowerCase() !== digest) continue;
      if (isAnalystSide(e)) {
        hashExcluded += 1;
        continue;
      }
      const host = hostOf(e) ?? "";
      hashRows.push({
        eventId: e.id ?? "",
        timestamp: e.timestamp ?? "",
        host,
        hostIsAttestedSubject: host === subject,
        identity: "analyst-attested-digest",
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
