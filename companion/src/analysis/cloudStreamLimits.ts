// The named limits of the streaming cloud import (#2303). Every number here is disclosed: the import
// note and the Cloud Coverage panel name each budget that was reached, and the manual
// (mkdocs-docs/reference/importing.md → "Large cloud exports") lists them all.
//
// WHY THESE VALUES. Measured against the #2300 baseline (synthetic MES UAL and CloudTrail exports,
// 1.5% of rows graded High/Medium): a realistic 1M-row UAL export carries ~15,000 High/Medium rows,
// a 1.2M-record CloudTrail set ~18,000. The budgets keep all of those individually, and stop a
// pathological export (1M failed sign-ins against 1M distinct accounts) from putting a million rows
// into the forensic timeline the AI reads. Info telemetry goes to the super-timeline, which is a
// per-case store capped by DFIR_SUPERTIMELINE_MAX (100,000 by default).

/** A cloud upload at least this large — or any gzip upload — is imported by streaming from disk. */
export const CLOUD_STREAM_MIN_BYTES = 32 * 1024 * 1024;

/** Records read, deduplicated, graded and written per batch. */
export const CLOUD_STREAM_BATCH_RECORDS = 5_000;

/**
 * Zip-bomb guard: decompressed bytes may be at most this many times the compressed bytes read so
 * far. CloudTrail and UAL JSON compress 8–20×; a crafted bomb is 1,000× and more.
 */
export const GZIP_MAX_RATIO = 100;
/** The ratio is only enforced past this much output, so a tiny, highly compressible file passes. */
export const GZIP_RATIO_SLACK_BYTES = 64 * 1024 * 1024;
/** Absolute ceiling on decompressed bytes from one upload, whatever the ratio. */
export const GZIP_MAX_OUTPUT_BYTES = 20 * 1024 * 1024 * 1024;

/** One JSON record (array element or line) larger than this is skipped and counted, never held. */
export const JSON_RECORD_MAX_CHARS = 16 * 1024 * 1024;
/** One CSV record larger than this is force-split (parseCsvRecordsFromLines' own guard). */
export const CSV_RECORD_MAX_CHARS = 8 * 1024 * 1024;

/** Medium rows kept individually per (rule, actor) before that pair's rows are aggregated. */
export const MEDIUM_INDIVIDUAL_PER_RULE_ACTOR = 25;
/** Medium rows kept individually per import, across all rules and actors. */
export const MEDIUM_INDIVIDUAL_MAX = 10_000;

/** Distinct aggregated groups (Medium overflow, Low, Info) one import may create at full detail. */
export const AGGREGATE_GROUPS_MAX = 5_000;
/** Coarser groups (by rule, or rule and source address) once the detailed groups are used up. */
export const COARSE_GROUPS_MAX = 1_000;

/**
 * Info and Low rows written to the super-timeline individually per import, further bounded by the
 * room the case's super-timeline has left, so one import never evicts the rows earlier imports put
 * there. Rows past this budget are represented by aggregated rows.
 */
export const SUPER_ROWS_PER_IMPORT_MAX = 50_000;

/**
 * Whole-export summaries (credential lineages, compute lifecycles, privilege paths, mailbox chains,
 * service-account joins) are built over at most this many records — the first ones in the file.
 */
export const SUMMARY_RECORDS_MAX = 25_000;

/** IOCs one import keeps (the whole-file importers' own default). */
export const STREAM_IOCS_MAX = 5_000;

/**
 * Decoded text a Sigma re-grade reads from one stored import file (#2353). The re-grade parses the
 * file again with the whole-file importer, which needs the text as one string, so this is that
 * path's ceiling — the same 256 MB as DFIR_MAX_BODY_MB's default — not the streamed import's
 * GZIP_MAX_OUTPUT_BYTES. A stored file past it is skipped and counted, never read whole.
 */
export const REGRADE_TEXT_MAX_BYTES = 256 * 1024 * 1024;
