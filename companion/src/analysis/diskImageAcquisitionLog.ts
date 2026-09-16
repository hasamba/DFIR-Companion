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

/** A real hex digest for the named algorithm has exactly this many characters — never trusted as
 * opaque text (Codex code review finding H4: an arbitrary-length "hex" match let a truncated or
 * corrupted digest line verify). */
const DIGEST_LENGTH: Record<HashAlgo, number> = { md5: 32, sha1: 40, sha256: 64, sha512: 128 };
function validDigestLength(algo: HashAlgo, digest: string): boolean {
  return digest.length === DIGEST_LENGTH[algo];
}

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

interface FtkChecksumLine {
  algo: HashAlgo;
  digest: string;
  verified: boolean;
  validLength: boolean;
  raw: string;
}

function ftkChecksumLines(block: string): FtkChecksumLine[] {
  const out: FtkChecksumLine[] = [];
  const re = /(md5|sha1|sha256|sha512)\s+checksum:\s*([0-9a-f]+)\s*(:\s*(\S.*))?$/gim;
  let m: RegExpExecArray | null;
  while ((m = re.exec(block))) {
    const algo = m[1].toLowerCase() as HashAlgo;
    const digest = m[2].toLowerCase();
    const tail = (m[4] ?? "").trim();
    out.push({
      algo,
      digest,
      verified: /^verified$/i.test(tail),
      validLength: validDigestLength(algo, digest),
      raw: m[0].trim(),
    });
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
  for (const a of acquisitionLines)
    hashes.push({ algorithm: a.algo, digest: a.digest, phase: "acquisition" });
  for (const v of verificationLines)
    hashes.push({ algorithm: v.algo, digest: v.digest, phase: "verification" });

  // Every acquisition-phase algorithm must have its OWN matching, exact-length, exact-"verified"
  // verification counterpart — a single matching algorithm out of several never verifies the
  // whole log (Codex code review finding H4: a partial/truncated verification section, or one
  // with zero parseable lines despite the section header being present, previously verified).
  let status: VerificationStatus;
  const unrecognizedParts: string[] = [];
  if (acquisitionLines.length === 0) {
    status = "not-performed";
  } else {
    for (const a of acquisitionLines) {
      const v = verificationLines.find((x) => x.algo === a.algo);
      const ok = !!v && v.verified && v.digest === a.digest && a.validLength && v.validLength;
      if (!ok)
        unrecognizedParts.push(
          v ? v.raw : `${a.algo.toUpperCase()} checksum: no matching verification result`,
        );
    }
    status = unrecognizedParts.length === 0 ? "verified" : "unrecognized";
  }
  const unrecognizedText = unrecognizedParts.length ? unrecognizedParts.join("; ") : undefined;

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

/** dc3dd names its own result blocks "input results for <file|device> `<path>'" and (one or more
 * of, per its own real man page — "to write to multiple outputs specify more than one of of=,
 * hof=, ofs=, hofs=, or fhod=, in any combination") "output results for <file|device> `<path>'" —
 * "device" for a block special file, "file" for a regular one (a real captured `/dev/sdb` run
 * confirmed "device" verbatim; Codex code review finding H1: the original signature required the
 * literal word "file" and never matched a physical-device acquisition at all). */
export function isDc3ddLog(text: string): boolean {
  return (
    /input results for (?:files?|devices?)/i.test(text) &&
    /output results for (?:files?|devices?)/i.test(text)
  );
}

interface Dc3ddHashLine {
  algo: HashAlgo;
  digest: string;
  validLength: boolean;
}

function dc3ddHashLines(block: string): Dc3ddHashLine[] {
  const out: Dc3ddHashLine[] = [];
  const re = /([0-9a-f]+)\s*\((md5|sha1|sha256|sha512)\)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(block))) {
    const algo = m[2].toLowerCase() as HashAlgo;
    const digest = m[1].toLowerCase();
    out.push({ algo, digest, validLength: validDigestLength(algo, digest) });
  }
  return out;
}

// A real device run reports "<N> sectors in" with no "+ M bytes" remainder clause at all — the
// clause is only ever present for a REGULAR FILE input where the read stops mid-sector at EOF, so
// both shapes are real and neither implies the other (confirmed against two independent real
// captured logs — RECOMMENDATION-1102.md's own dc3dd citation, and a real /dev/sdb run).
function dc3ddSectors(block: string): { sectorCount?: number; remainderBytes?: number } {
  const withRemainder = block.match(/(\d+)\s+sectors\s*\+\s*(\d+)\s+bytes\s+(?:in|out)/i);
  if (withRemainder)
    return { sectorCount: Number(withRemainder[1]), remainderBytes: Number(withRemainder[2]) };
  const plain = block.match(/(\d+)\s+sectors\s+(?:in|out)/i);
  return plain ? { sectorCount: Number(plain[1]) } : {};
}

// dc3dd's own real, verbatim summary line for sectors it could not read from a device and
// zero-filled instead (confirmed via a real captured `/dev/sdb` run — RECOMMENDATION-1102.md;
// Codex code review finding H3: this was previously never checked at all, so a hash that still
// matched despite substituted sectors reported a clean "verified"/Info result).
function dc3ddBadSectors(text: string): number | undefined {
  const m = text.match(/(\d+)\s+bad sectors replaced by zeros/i);
  return m ? Number(m[1]) : undefined;
}

interface Dc3ddBlock {
  kind: "input" | "output";
  path?: string;
  sectorCount?: number;
  remainderBytes?: number;
  hashes: Dc3ddHashLine[];
}

function splitDc3ddBlocks(text: string): Dc3ddBlock[] {
  const headerRe = /(input|output) results for (?:files?|devices?) `([^']*)'/gi;
  const marks: { index: number; kind: "input" | "output"; path: string }[] = [];
  let m: RegExpExecArray | null;
  while ((m = headerRe.exec(text))) {
    marks.push({ index: m.index, kind: m[1].toLowerCase() as "input" | "output", path: m[2] });
  }
  return marks.map((mark, i) => {
    const end = i + 1 < marks.length ? marks[i + 1].index : text.length;
    const chunk = text.slice(mark.index, end);
    return { kind: mark.kind, path: mark.path, hashes: dc3ddHashLines(chunk), ...dc3ddSectors(chunk) };
  });
}

export function parseDc3ddLog(text: string, opts: DiskImageLogOptions = {}): DiskImageLogResult | null {
  if (!isDc3ddLog(text)) return null;
  const blocks = splitDc3ddBlocks(text);
  const inputBlock = blocks.find((b) => b.kind === "input");
  const outputBlocks = blocks.filter((b) => b.kind === "output");

  const hashes: HashMeasurement[] = [];
  const inputByAlgo = new Map<HashAlgo, Dc3ddHashLine>();
  for (const h of inputBlock?.hashes ?? []) {
    inputByAlgo.set(h.algo, h);
    hashes.push({ algorithm: h.algo, digest: h.digest, phase: "acquisition" });
  }
  for (const b of outputBlocks) {
    for (const h of b.hashes) hashes.push({ algorithm: h.algo, digest: h.digest, phase: "verification" });
  }

  // Multiple outputs verify only when EVERY one of them, for every algorithm it reports, matches
  // the corresponding input digest (Codex code review finding H2: comparing only the first output
  // hash let one verified destination hide a mismatched second one — dc3dd genuinely supports
  // writing to several outputs in one run, per its own man page).
  const hashedOutputs = outputBlocks.filter((b) => b.hashes.length > 0);
  let status: VerificationStatus;
  const unrecognizedParts: string[] = [];
  if (hashedOutputs.length === 0) {
    status = "not-performed";
  } else {
    for (const b of hashedOutputs) {
      for (const h of b.hashes) {
        const input = inputByAlgo.get(h.algo);
        const ok = !!input && input.digest === h.digest && input.validLength && h.validLength;
        if (!ok) unrecognizedParts.push(`output ${h.digest} (${h.algo}) at ${b.path ?? "unknown path"}`);
      }
    }
    status = unrecognizedParts.length === 0 ? "verified" : "unrecognized";
  }
  const unrecognizedText = unrecognizedParts.length ? unrecognizedParts.join("; ") : undefined;

  const sectorSizeMatch = text.match(/sector size:\s*(\d+)\s*bytes/i);
  const badSectors = dc3ddBadSectors(text);
  const readErrors = detectReadErrors(text);
  if (badSectors !== undefined && badSectors > 0) readErrors.detected = true;
  const id = uploadId(text);

  const event = buildEvent({
    tool: "dc3dd",
    toolLabel: "dc3dd",
    id,
    hashes,
    verificationStatus: status,
    unrecognizedVerificationText: unrecognizedText,
    sectorCount: inputBlock?.sectorCount,
    sectorSize: sectorSizeMatch ? Number(sectorSizeMatch[1]) : undefined,
    remainderBytes: inputBlock?.remainderBytes,
    sourcePath: inputBlock?.path,
    outputPath: outputBlocks[0]?.path,
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
