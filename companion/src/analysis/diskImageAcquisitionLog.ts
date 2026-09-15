// A full-disk-imaging tool's OWN acquisition/verification log (#1102, surfaced by 932.1's design
// review): FTK Imager's `<image>.<ext>.txt` sidecar, or dc3dd's own `log=`/`hlog=` output. A
// sibling to kapeAcquisitionLog.ts's own "many small files" convention, never an addition to it —
// that module's own block states a per-FILE hash; this one states a single hash across the WHOLE
// acquired evidence stream, a different concept entirely (canonicalDiskImage.ts's own `basis`).
//
// What this module never says: that a verified hash means the image is complete (both tools can
// hash-verify an image that still substituted zeros for unreadable sectors — readErrorsDetected is
// a SEPARATE, independent fact), or that a checksum line this parser does not recognize is either a
// match or a mismatch. Any checksum-result text other than an exact, anchored "... : verified" is
// reported as `"unrecognized"` with the raw text preserved verbatim — never inferred. No real
// failed-verification log text was found for either tool this session (see
// RECOMMENDATION-1102.md), so `"mismatch"` is deliberately not a value this module can produce.
//
// Verified against real documentation, not invented — see canonicalDiskImage.ts's own header for
// sources. Not attempted: bad-sector RANGE parsing beyond the one confirmed "N through M" shape,
// dc3dd's `mlog=` machine-readable format, plain `dd`, and EnCase E01/Ex01 metadata.

import { createHash } from "node:crypto";
import {
  aggregateEvents,
  normalizeTime,
  type MappedEvent,
  type SiemEvent,
  type SiemIoc,
} from "./siemImport.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { HashMeasurement, VerificationStatus } from "./canonicalDiskImage.js";

export interface DiskImageLogOptions {
  aggregate?: boolean;
  maxEvents?: number;
}

export interface DiskImageLogResult {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  artifact: string;
  format: string;
}

const BASIS =
  "a hash of the whole acquired evidence stream, as computed by the imaging tool itself; never a per-file content hash, and never directly comparable to one" as const;

type HashAlgo = "md5" | "sha1" | "sha256" | "sha512";

const READ_ERROR_MARKERS = ["attention: this image is incomplete!", "could not be read"];
const READ_ERROR_RANGE = /(\d+)\s+through\s+(\d+)/i;

function detectReadErrors(text: string): { detected: boolean; range?: string } {
  const lower = text.toLowerCase();
  const detected = READ_ERROR_MARKERS.some((m) => lower.includes(m));
  if (!detected) return { detected: false };
  const m = text.match(READ_ERROR_RANGE);
  return m ? { detected, range: `${m[1]} through ${m[2]}` } : { detected };
}

function uploadId(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

function severityFor(status: VerificationStatus, readErrorsDetected: boolean): "Info" | "Medium" | "High" {
  if (readErrorsDetected) return "High";
  if (status === "unrecognized") return "Medium";
  return "Info";
}

function describe(
  tool: "FTK Imager" | "dc3dd",
  hashes: HashMeasurement[],
  status: VerificationStatus,
  sectorCount: number | undefined,
  readErrors: { detected: boolean; range?: string },
  id: string,
): string {
  const byAlgo = new Map<string, HashMeasurement[]>();
  for (const h of hashes) byAlgo.set(h.algorithm, [...(byAlgo.get(h.algorithm) ?? []), h]);
  const hashParts: string[] = [];
  for (const [algo, group] of byAlgo) {
    const verificationHash = group.find((h) => h.phase === "verification");
    if (verificationHash) hashParts.push(`${algo.toUpperCase()} ${status}`);
  }
  const parts = [
    `Disk image acquisition (${tool})`,
    hashParts.length ? hashParts.join(", ") : status === "not-performed" ? "no output verification" : status,
    sectorCount !== undefined ? `${sectorCount} sectors` : "",
    readErrors.detected
      ? `ATTENTION: image incomplete${readErrors.range ? `, sectors ${readErrors.range} could not be read` : ""}`
      : "",
    `log ${id.slice(0, 8)}`,
  ].filter(Boolean);
  return parts.join(" — ").slice(0, 600);
}

function buildEvent(input: {
  tool: "ftk-imager" | "dc3dd";
  toolLabel: "FTK Imager" | "dc3dd";
  id: string;
  hashes: HashMeasurement[];
  verificationStatus: VerificationStatus;
  unrecognizedVerificationText?: string;
  sectorCount?: number;
  sectorSize?: number;
  remainderBytes?: number;
  sourcePath?: string;
  outputPath?: string;
  acquisitionStarted?: string;
  acquisitionFinished?: string;
  readErrors: { detected: boolean; range?: string };
}): MappedEvent {
  const observed = input.acquisitionStarted || new Date().toISOString();
  const severity = severityFor(input.verificationStatus, input.readErrors.detected);
  return {
    timestamp: normalizeTime(observed) || "",
    description: describe(
      input.toolLabel,
      input.hashes,
      input.verificationStatus,
      input.sectorCount,
      input.readErrors,
      input.id,
    ),
    severity,
    mitre: [],
    aggKey: `disk-image-acquisition|${input.tool}|${input.id}`,
    sources: [input.toolLabel],
    artifactName: input.tool === "ftk-imager" ? "DiskImage.FtkImager" : "DiskImage.Dc3dd",
    canonical: createCanonicalEvent({
      event: { category: "file", type: "acquisition", action: "image", outcome: input.verificationStatus },
      time: { observed, normalized: normalizeTime(observed) || "" },
      evidence: { rawRecords: [{ source: "disk-image-acquisition", locator: input.id }] },
      producer: {
        importer: "disk-image-acquisition",
        parserVersion: "1",
        mappingVersion: "disk-image-acquisition-v1",
      },
      diskImageAcquisition: {
        tool: input.tool,
        ...(input.sourcePath ? { sourcePath: input.sourcePath } : {}),
        ...(input.outputPath ? { outputPath: input.outputPath } : {}),
        ...(input.sectorCount !== undefined ? { sectorCount: input.sectorCount } : {}),
        ...(input.sectorSize !== undefined ? { sectorSize: input.sectorSize } : {}),
        ...(input.remainderBytes !== undefined ? { remainderBytes: input.remainderBytes } : {}),
        hashes: input.hashes,
        verificationStatus: input.verificationStatus,
        ...(input.unrecognizedVerificationText
          ? { unrecognizedVerificationText: input.unrecognizedVerificationText }
          : {}),
        readErrorsDetected: input.readErrors.detected,
        ...(input.readErrors.range ? { readErrorRange: input.readErrors.range } : {}),
        ...(input.acquisitionStarted ? { acquisitionStarted: input.acquisitionStarted } : {}),
        ...(input.acquisitionFinished ? { acquisitionFinished: input.acquisitionFinished } : {}),
        basis: BASIS,
      },
    }),
  };
}

function finish(event: MappedEvent, artifact: string, opts: DiskImageLogOptions): DiskImageLogResult {
  const { events, groups } = aggregateEvents([event], {
    aggregate: opts.aggregate,
    minSeverity: "Info",
    maxEvents: opts.maxEvents ?? 1,
  });
  return { events, iocs: [], total: 1, kept: events.length, dropped: 0, groups, artifact, format: artifact };
}

// ───────────────────────────── FTK Imager ─────────────────────────────

/** FTK Imager's own acquisition/verification log names both its case-header block and its
 * verification-results block by these two fixed section labels (#1102 design round, matching
 * KAPE's own "require every documented column" discipline against an accidental partial match). */
export function isFtkImagerLog(text: string): boolean {
  return /case information:/i.test(text) && /image verification results:/i.test(text);
}

function ftkChecksumLines(
  block: string,
): { algo: HashAlgo; digest: string; verified: boolean; raw: string }[] {
  const out: { algo: HashAlgo; digest: string; verified: boolean; raw: string }[] = [];
  const re = /(md5|sha1|sha256|sha512)\s+checksum:\s*([0-9a-f]+)\s*(:\s*(\S.*))?$/gim;
  let m: RegExpExecArray | null;
  while ((m = re.exec(block))) {
    const algo = m[1].toLowerCase() as HashAlgo;
    const digest = m[2].toLowerCase();
    const tail = (m[4] ?? "").trim();
    out.push({ algo, digest, verified: /^verified$/i.test(tail), raw: m[0].trim() });
  }
  return out;
}

export function parseFtkImagerLog(text: string, opts: DiskImageLogOptions = {}): DiskImageLogResult | null {
  if (!isFtkImagerLog(text)) return null;
  const verifyIdx = text.search(/image verification results:/i);
  const acquisitionBlock = text.slice(0, verifyIdx);
  const verificationBlock = text.slice(verifyIdx);

  const acquisitionLines = ftkChecksumLines(acquisitionBlock);
  const verificationLines = ftkChecksumLines(verificationBlock);

  const hashes: HashMeasurement[] = [];
  let status: VerificationStatus = "not-performed";
  let unrecognizedText: string | undefined;
  for (const a of acquisitionLines) {
    hashes.push({ algorithm: a.algo, digest: a.digest, phase: "acquisition" });
  }
  for (const v of verificationLines) {
    hashes.push({ algorithm: v.algo, digest: v.digest, phase: "verification" });
    const acq = acquisitionLines.find((a) => a.algo === v.algo);
    const matches = v.verified && !!acq && acq.digest === v.digest;
    if (matches) {
      if (status !== "unrecognized") status = "verified";
    } else {
      status = "unrecognized";
      unrecognizedText = unrecognizedText ? `${unrecognizedText}; ${v.raw}` : v.raw;
    }
  }

  const sectorCountMatch = text.match(/sector count:\s*(\d+)/i);
  const startedMatch = text.match(/acquisition started:\s*(.+)/i);
  const finishedMatch = text.match(/acquisition finished:\s*(.+)/i);
  const readErrors = detectReadErrors(text);
  const id = uploadId(text);

  const event = buildEvent({
    tool: "ftk-imager",
    toolLabel: "FTK Imager",
    id,
    hashes,
    verificationStatus: status,
    unrecognizedVerificationText: unrecognizedText,
    sectorCount: sectorCountMatch ? Number(sectorCountMatch[1]) : undefined,
    acquisitionStarted: startedMatch ? startedMatch[1].trim() : undefined,
    acquisitionFinished: finishedMatch ? finishedMatch[1].trim() : undefined,
    readErrors,
  });
  return finish(event, "DiskImageFtkImagerLog", opts);
}

// ───────────────────────────── dc3dd ─────────────────────────────

/** dc3dd's own real captured output names both an input-results and an output-results block by
 * these two fixed labels (confirmed via its man page + a real captured run — RECOMMENDATION-1102.md). */
export function isDc3ddLog(text: string): boolean {
  return /input results for file/i.test(text) && /output results for file/i.test(text);
}

interface Dc3ddBlock {
  path?: string;
  sectorCount?: number;
  remainderBytes?: number;
  hash?: { algo: HashAlgo; digest: string };
}

function parseDc3ddBlock(block: string): Dc3ddBlock {
  const pathMatch = block.match(/results for file `([^']*)'/i);
  const countMatch = block.match(/(\d+)\s+sectors\s*\+\s*(\d+)\s+bytes\s+(in|out)/i);
  const hashMatch = block.match(/([0-9a-f]{32,128})\s*\((md5|sha1|sha256|sha512)\)/i);
  return {
    path: pathMatch ? pathMatch[1] : undefined,
    sectorCount: countMatch ? Number(countMatch[1]) : undefined,
    remainderBytes: countMatch ? Number(countMatch[2]) : undefined,
    hash: hashMatch
      ? { algo: hashMatch[2].toLowerCase() as HashAlgo, digest: hashMatch[1].toLowerCase() }
      : undefined,
  };
}

export function parseDc3ddLog(text: string, opts: DiskImageLogOptions = {}): DiskImageLogResult | null {
  if (!isDc3ddLog(text)) return null;
  const outIdx = text.search(/output results for file/i);
  const inputBlock = text.slice(0, outIdx);
  const outputBlock = text.slice(outIdx);

  const input = parseDc3ddBlock(inputBlock);
  const output = parseDc3ddBlock(outputBlock);

  const hashes: HashMeasurement[] = [];
  if (input.hash)
    hashes.push({ algorithm: input.hash.algo, digest: input.hash.digest, phase: "acquisition" });
  if (output.hash)
    hashes.push({ algorithm: output.hash.algo, digest: output.hash.digest, phase: "verification" });

  let status: VerificationStatus;
  let unrecognizedText: string | undefined;
  if (!output.hash) {
    status = "not-performed";
  } else if (input.hash && input.hash.algo === output.hash.algo && input.hash.digest === output.hash.digest) {
    status = "verified";
  } else {
    status = "unrecognized";
    unrecognizedText = `output hash ${output.hash.digest} (${output.hash.algo})`;
  }

  const sectorSizeMatch = text.match(/sector size:\s*(\d+)\s*bytes/i);
  const readErrors = detectReadErrors(text);
  const id = uploadId(text);

  const event = buildEvent({
    tool: "dc3dd",
    toolLabel: "dc3dd",
    id,
    hashes,
    verificationStatus: status,
    unrecognizedVerificationText: unrecognizedText,
    sectorCount: input.sectorCount,
    sectorSize: sectorSizeMatch ? Number(sectorSizeMatch[1]) : undefined,
    remainderBytes: input.remainderBytes,
    sourcePath: input.path,
    outputPath: output.path,
    readErrors,
  });
  return finish(event, "DiskImageDc3ddLog", opts);
}

/** Either tool's own log, or null when neither signature matches. */
export function parseDiskImageLog(text: string, opts: DiskImageLogOptions = {}): DiskImageLogResult | null {
  return parseFtkImagerLog(text, opts) ?? parseDc3ddLog(text, opts);
}

export function isDiskImageLog(text: string): boolean {
  return isFtkImagerLog(text) || isDc3ddLog(text);
}
