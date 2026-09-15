// The envelope block one full-disk-imaging tool's OWN acquisition/verification log states about
// itself (#1102, surfaced by 932.1's design review). A sibling to canonicalAcquisition.ts's own
// per-FILE acquisitionCoverage block — never a variant of it: that block's own `basis` sentence
// says its hash is "not a container or disk-image hash"; this one is exactly that opposite case, a
// single hash across the WHOLE acquired evidence stream. Kept in its own file for the same reason
// (canonicalEvent.ts's own size bound).
//
// Verified against real documentation, not invented: FTK Imager's own acquisition/verification log
// format (cross-confirmed via a SANS Institute walkthrough, an independent forensic-examiner blog
// quoting a real log verbatim, and a real forum thread showing an incomplete acquisition's exact
// "ATTENTION: This image is incomplete!" / "could not be read: N through M" wording) and dc3dd's
// own real man page plus a real captured multi-line output example (kali.org's own tool page).

import { z } from "zod";

export const diskImageTools = ["ftk-imager", "dc3dd"] as const;
export type DiskImageTool = (typeof diskImageTools)[number];

export const diskImageHashAlgorithms = ["md5", "sha1", "sha256", "sha512"] as const;
export type DiskImageHashAlgorithm = (typeof diskImageHashAlgorithms)[number];

/** No real failed-verification log text was found for either tool this session, for either tool —
 * a mismatch's own checksum line falls into "unrecognized" rather than being silently trusted as a
 * match or invented as a "mismatch" value with no real wording behind it. */
export const verificationStatuses = ["verified", "unrecognized", "not-performed"] as const;
export type VerificationStatus = (typeof verificationStatuses)[number];

export const hashMeasurementSchema = z.object({
  algorithm: z.enum(diskImageHashAlgorithms),
  digest: z.string().regex(/^[0-9a-f]+$/i),
  /** WHEN this was computed — acquisition (from the source) vs verification (re-hashing the
   * finished image) — never conflated; the two can legitimately differ in a genuine mismatch. */
  phase: z.enum(["acquisition", "verification"]),
});
export type HashMeasurement = z.infer<typeof hashMeasurementSchema>;

export const diskImageAcquisitionSchema = z.object({
  tool: z.enum(diskImageTools),
  sourcePath: z.string().optional(),
  outputPath: z.string().optional(),
  sectorCount: z.number().int().nonnegative().optional(),
  sectorSize: z.number().int().positive().optional(),
  remainderBytes: z.number().int().nonnegative().optional(),
  hashes: z.array(hashMeasurementSchema),
  verificationStatus: z.enum(verificationStatuses),
  /** Present only when verificationStatus is "unrecognized" — the raw checksum-result text,
   * verbatim, so an analyst (or a future, properly-verified parser) can see exactly what the tool
   * said without this importer ever guessing at its meaning. */
  unrecognizedVerificationText: z.string().optional(),
  readErrorsDetected: z.boolean(),
  /** Verbatim "N through M", when the one confirmed shape matches — never invented when absent. */
  readErrorRange: z.string().optional(),
  acquisitionStarted: z.string().optional(),
  acquisitionFinished: z.string().optional(),
  /** Always this exact sentence: the hash this block carries is a hash of the WHOLE acquired
   * evidence stream — never a per-file content hash (canonicalAcquisition.ts's own block), and
   * never directly comparable to one (932.1's own "compare like-for-like byte scopes" guardrail). */
  basis: z.literal(
    "a hash of the whole acquired evidence stream, as computed by the imaging tool itself; " +
      "never a per-file content hash, and never directly comparable to one",
  ),
});
export type DiskImageAcquisition = z.infer<typeof diskImageAcquisitionSchema>;
