// The memory run envelope (#933 item 12, second half — #1016): what makes an empty Volatility
// export a completed search, and what makes it an aborted one. Nothing in an export says which;
// only a run envelope written by the invoking script — the command, the exit status, stderr as
// its own field, the digests — can. The envelope travels WITH the stdout it describes (a bundle
// of runs, each embedding its export); a standalone envelope binds to nothing, because two
// images' empty exports are byte-identical and a digest alone names no run.
//
// What one row rests on, and what it never says:
//   - the envelope is uploader-supplied and unsigned: every verdict is the envelope's STATEMENT,
//     worded as such; provenance is not established (an attestation scheme is out of scope);
//   - the verdict is read from the exit status and the COMPLETE stderr field (scanned before
//     anything is shortened); a stderr past the bound makes the verdict indeterminate, never
//     "completed"; an exit 0 wins over a traceback on stderr (an optional import can fail loudly
//     while the plugin succeeds);
//   - the stdout digest is computed over the bytes (`stdoutBase64`) or the UTF-8 text (`stdout`)
//     the envelope embeds, and a stated digest that disagrees unbinds the run; the export's own
//     rows still import as an export;
//   - a dump-type qualification comes only from a `windows.crashinfo` run of the SAME image
//     (mandatory `imageSha256`) in the same bundle;
//   - an empty result never speaks for pages the dump does not hold, and never for "clean".

import { createHash } from "node:crypto";
import { z } from "zod";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { MemoryRunBlock, MemoryRunVerdict } from "./canonicalMemoryRun.js";
import { readImageFacts } from "./memoryImageFacts.js";
import { extractTables } from "./memoryTables.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { isObject, normalizeTime, type MappedEvent, type SiemEvent, type SiemIoc } from "./siemImport.js";

export const RUN_ENVELOPE_TYPE = "dfir.volatility-run";
export const RUN_ENVELOPE_VERSION = 1;
export const RUNS_PER_BUNDLE_MAX = 256;
/** stderr read in full up to this many characters; past it the verdict is indeterminate. */
export const STDERR_MAX = 1_048_576;
/** Embedded stdout read up to this many characters (decoded); past it the run is not read. */
export const STDOUT_MAX = 64 * 1_048_576;
const STDERR_LINES_MAX = 50;
const LINE_MAX = 200;
const DESCRIPTION_MAX = 900;
/** The user-space plugins an empty result of which a bitmap dump cannot clear. */
const USER_SPACE_PLUGINS = /(?:^|\.)(malfind|cmdline|dlllist|ldrmodules|handles|envars|vadinfo|yarascan)\b/i;
const VALIDATION_RE =
  /^(?:Unsatisfied requirement\b|Unable to validate the plugin requirements\b|A symbol table requirement was not fulfilled\b)/;
const PAGE_ERROR_RE = /^Volatility was unable to read a requested page\b/;
const TRACEBACK_RE = /^Traceback \(most recent call last\)/;
const VOL2_RE = /(?:^|[\s/\\])vol(?:atility)?\.py\b|--profile[= ]|(?:^|\s)-{1,2}profile\b/;
const HEX64 = /^(?:sha256:)?([0-9a-f]{64})$/i;
const BASIS =
  "an uploader-supplied, unsigned run envelope; its statements are read, not verified; an empty result speaks only for the pages the dump holds";

const show = (v: string, max = LINE_MAX): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
const short = (digest: string): string => digest.replace(/^sha256:/, "").slice(0, 12);
const sha256 = (data: string | Buffer): string => `sha256:${createHash("sha256").update(data).digest("hex")}`;
const normDigest = (v: string): string => {
  const m = HEX64.exec(v.trim());
  return m ? `sha256:${m[1].toLowerCase()}` : "";
};

// ───────────────────────────── the format ─────────────────────────────

const runSchema = z.object({
  type: z.literal(RUN_ENVELOPE_TYPE).optional(),
  envelopeVersion: z.number().int().positive().optional(),
  command: z.string().min(1),
  plugin: z.string().min(1),
  renderer: z.string().optional(),
  volatilityVersion: z.string().optional(),
  symbols: z.string().optional(),
  exitStatus: z.number().int(),
  stdout: z.string().optional(),
  stdoutBase64: z.string().optional(),
  stdoutSha256: z.string().optional(),
  stderr: z.string().default(""),
  imageSha256: z.string().min(1),
  startedAt: z.string().optional(),
  endedAt: z.string().optional(),
});
export type RunEnvelope = z.infer<typeof runSchema>;

const bundleSchema = z.object({
  type: z.literal(RUN_ENVELOPE_TYPE).optional(),
  envelopeVersion: z.number().int().positive().optional(),
  runs: z.array(z.unknown()),
});

/** Detection: the discriminator on the run or the bundle, and an integer exit status on a run. */
export function isRunEnvelopeUpload(root: unknown): boolean {
  if (!isObject(root) || Array.isArray(root)) return false;
  if (root.type !== RUN_ENVELOPE_TYPE) {
    const runs = root.runs;
    return (
      Array.isArray(runs) && runs.length > 0 && runs.every((r) => isObject(r) && r.type === RUN_ENVELOPE_TYPE)
    );
  }
  return Array.isArray(root.runs) || typeof root.exitStatus === "number";
}

// ───────────────────────────── the verdict ─────────────────────────────

interface ExportRead {
  /** True when the embedded stdout was read as a Volatility export (a table, a header, or `[]`). */
  readable: boolean;
  rows: number;
  volatility2: boolean;
}

/** The stderr lines that decide a verdict, scanned over the WHOLE field. */
function stderrMarkers(stderr: string): {
  validation: string;
  pageError: string;
  traceback: boolean;
  lines: string[];
} {
  let validation = "";
  let pageError = "";
  let traceback = false;
  const lines: string[] = [];
  for (const raw of stderr.split(/\r\n|\r|\n/)) {
    const line = raw.trim();
    if (!line) continue;
    if (!validation && VALIDATION_RE.test(line)) validation = line;
    if (!pageError && PAGE_ERROR_RE.test(line)) pageError = line;
    if (TRACEBACK_RE.test(line)) traceback = true;
    if (
      lines.length < STDERR_LINES_MAX &&
      (VALIDATION_RE.test(line) || PAGE_ERROR_RE.test(line) || TRACEBACK_RE.test(line))
    )
      lines.push(show(line));
  }
  return { validation, pageError, traceback, lines };
}

/** The verdict from the envelope's statements alone — exit status, the whole stderr, the export as read. */
export function runVerdict(
  env: RunEnvelope,
  read: ExportRead | null,
  stderrOverBound: boolean,
  dumpQualification: string | undefined,
): MemoryRunVerdict {
  const plugin = show(env.plugin, 60);
  const qualified = (words: string): string => (dumpQualification ? `${words}; ${dumpQualification}` : words);
  if (!read)
    return {
      kind: "unbound",
      words: "no export embedded; applied to nothing — embed the run's stdout in the envelope",
    };
  if (stderrOverBound)
    return {
      kind: "indeterminate",
      words: `indeterminate: stderr exceeds the bound the importer reads (${STDERR_MAX} characters); completion not established`,
      rows: read.rows,
    };
  if (VOL2_RE.test(env.command) || read.volatility2)
    return {
      kind: "volatility-2",
      words: `a Volatility 2 run (profile-based); the export is not read; the envelope names the run: ${show(env.command, 120)}`,
    };
  const m = stderrMarkers(env.stderr);
  if (env.exitStatus !== 0 && !m.validation)
    return {
      kind: "did-not-complete-exit",
      words: `did not complete: exit status ${env.exitStatus}; the absence of rows is not evidence`,
      rows: read.rows,
    };
  if (m.validation)
    return {
      kind: "did-not-complete-validation",
      words: `did not complete: symbol/translation validation failed: ${show(m.validation)}; the absence of rows is not evidence`,
      rows: read.rows,
      requirement: show(m.validation),
    };
  if (m.pageError)
    return {
      kind: "did-not-complete-page-error",
      words: `did not complete after ${read.rows} row${read.rows === 1 ? "" : "s"}; later candidates may never have been searched (${show(m.pageError, 120)})`,
      rows: read.rows,
    };
  if (!read.readable)
    return {
      kind: "indeterminate",
      words:
        "indeterminate: the embedded stdout is not a readable Volatility export; completion not established",
      rows: 0,
    };
  const traceback = m.traceback ? "; stderr carries a traceback (unverified; the run exited 0)" : "";
  if (read.rows === 0)
    return {
      kind: "completed-no-rows",
      words: qualified(
        `${plugin} completed with no rows over the pages this image holds and the structures the plugin reads; not evidence about pages the dump does not hold${traceback}`,
      ),
      rows: 0,
      ...(m.traceback ? { tracebackOnSuccess: true } : {}),
      ...(dumpQualification ? { dumpQualification } : {}),
    };
  return {
    kind: "completed-with-rows",
    words: `${plugin} completed with ${read.rows} row${read.rows === 1 ? "" : "s"}${traceback}`,
    rows: read.rows,
    ...(m.traceback ? { tracebackOnSuccess: true } : {}),
  };
}

// ───────────────────────────── the pass ─────────────────────────────

export interface RunParse {
  events: SiemEvent[];
  iocs: SiemIoc[];
  total: number;
  kept: number;
  dropped: number;
  groups: number;
  tables: number;
  format: string;
  tool: string;
}
export type ExportParser = (text: string, filename: string | undefined) => RunParse;

interface RunRead {
  env: RunEnvelope;
  index: number;
  stdout: string | null;
  digest: string;
  encoding: MemoryRunBlock["stdoutEncoding"];
  stated: string;
  bound: boolean;
  stderrOverBound: boolean;
  parsed: RunParse | null;
  read: ExportRead | null;
  imageDump: string;
  problem: string;
}

/** Decode one run's embedded stdout; the digest is over bytes when the collector supplied them. */
function readStdout(env: RunEnvelope): {
  stdout: string | null;
  digest: string;
  encoding: MemoryRunBlock["stdoutEncoding"];
} {
  if (env.stdoutBase64 !== undefined) {
    const bytes = Buffer.from(env.stdoutBase64, "base64");
    return { stdout: bytes.toString("utf8"), digest: sha256(bytes), encoding: "bytes" };
  }
  if (env.stdout !== undefined)
    return { stdout: env.stdout, digest: sha256(Buffer.from(env.stdout, "utf8")), encoding: "text-utf8" };
  return { stdout: null, digest: "", encoding: "none" };
}

function readRun(
  raw: unknown,
  index: number,
  parseExport: ExportParser,
): RunRead | { index: number; problem: string } {
  const parsed = runSchema.safeParse(raw);
  if (!parsed.success)
    return {
      index,
      problem: `run ${index}: not a run envelope (${show(parsed.error.issues[0]?.message ?? "invalid", 80)})`,
    };
  const env = parsed.data;
  const { stdout, digest, encoding } = readStdout(env);
  const stated = env.stdoutSha256 ? normDigest(env.stdoutSha256) : "";
  const stderrOverBound = env.stderr.length > STDERR_MAX;
  const imageDigest = normDigest(env.imageSha256);
  let problem = "";
  if (!imageDigest) problem = "imageSha256 is not a sha256 digest";
  else if (env.stdoutSha256 && !stated) problem = "stdoutSha256 is not a sha256 digest";
  else if (stated && digest && stated !== digest)
    problem = `the digest of the embedded stdout (${short(digest)}, over ${encoding === "bytes" ? "the bytes" : "the text, UTF-8"}) differs from the stated stdoutSha256 (${short(stated)}) — line endings, a BOM or the encoding may differ`;
  else if (stdout !== null && stdout.length > STDOUT_MAX)
    problem = "the embedded stdout exceeds the bound the importer reads";
  const bound = !problem && stdout !== null;
  const exportParse = bound && stdout !== null ? parseExport(stdout, `${env.plugin}.json`) : null;
  const trimmed = stdout?.trim() ?? "";
  const read: ExportRead | null =
    bound && exportParse
      ? {
          readable: exportParse.format !== "empty" || trimmed === "[]" || /^\{\s*\}$/.test(trimmed),
          rows: exportParse.total,
          volatility2: exportParse.format === "volatility2-text",
        }
      : null;
  const imageDump =
    bound && stdout !== null && /crashinfo/i.test(env.plugin)
      ? (readImageFacts(extractTables(stdout, undefined).tables)?.dumpType ?? "")
      : "";
  return {
    env,
    index,
    stdout,
    digest,
    encoding,
    stated,
    bound,
    stderrOverBound,
    parsed: exportParse,
    read,
    imageDump,
    problem,
  };
}

/**
 * Read a run-envelope upload: every run's embedded export imports as the export it is (through
 * `parseExport`), and one run row per envelope states the verdict. Returns the runs' export
 * parses too, so the caller can merge their rows and counts.
 */
export function parseRunEnvelopes(
  root: unknown,
  parseExport: ExportParser,
): { runRows: MappedEvent[]; exports: RunParse[]; note: string } {
  const bundle = bundleSchema.safeParse(root);
  const rawRuns: unknown[] = bundle.success ? bundle.data.runs : [root];
  const version =
    (isObject(root) && typeof root.envelopeVersion === "number" ? root.envelopeVersion : 0) ||
    RUN_ENVELOPE_VERSION;
  const reads = rawRuns.slice(0, RUNS_PER_BUNDLE_MAX).map((r, i) => readRun(r, i, parseExport));
  const beyond = Math.max(0, rawRuns.length - RUNS_PER_BUNDLE_MAX);
  // The dump type per image, from a crashinfo run of the SAME image in this bundle.
  const dumpByImage = new Map<string, string>();
  for (const r of reads)
    if ("env" in r && r.imageDump) dumpByImage.set(normDigest(r.env.imageSha256), r.imageDump);
  const runRows: MappedEvent[] = [];
  const exports: RunParse[] = [];
  const problems: string[] = [];
  for (const r of reads) {
    if (!("env" in r)) {
      problems.push(r.problem);
      continue;
    }
    const image = normDigest(r.env.imageSha256);
    const dump = dumpByImage.get(image);
    const qualification =
      dump && /bitmap/i.test(dump) && USER_SPACE_PLUGINS.test(r.env.plugin)
        ? "over a dump that may not hold user-space pages; an empty result does not clear user-space behaviour"
        : dump
          ? undefined
          : r.bound && USER_SPACE_PLUGINS.test(r.env.plugin)
            ? "dump type not established for this run"
            : undefined;
    const verdict = r.bound
      ? runVerdict(r.env, r.read, r.stderrOverBound, r.read?.rows === 0 ? qualification : undefined)
      : ({
          kind: "unbound",
          words:
            r.problem || "no export embedded; applied to nothing — embed the run's stdout in the envelope",
        } satisfies MemoryRunVerdict);
    if (r.parsed) exports.push(r.parsed);
    runRows.push(runRow(r, version, image, verdict));
  }
  const note = [
    ...(beyond ? [`${beyond} further run(s) beyond the ${RUNS_PER_BUNDLE_MAX} read`] : []),
    ...problems.slice(0, 8),
  ].join("; ");
  return { runRows, exports, note };
}

// ───────────────────────────── the row ─────────────────────────────

function runRow(r: RunRead, version: number, image: string, verdict: MemoryRunVerdict): MappedEvent {
  const env = r.env;
  const severity: Severity =
    verdict.kind === "completed-no-rows" ||
    verdict.kind === "completed-with-rows" ||
    verdict.kind === "unbound"
      ? "Low"
      : "Medium";
  const markers = stderrMarkers(env.stderr.slice(0, STDERR_MAX)).lines;
  const facts = [
    `exit ${env.exitStatus}`,
    ...(verdict.rows !== undefined
      ? [`${verdict.rows} row${verdict.rows === 1 ? "" : "s"} in the embedded export`]
      : []),
    env.volatilityVersion ? `Volatility ${show(env.volatilityVersion, 30)}` : "Volatility version not stated",
    env.symbols ? `symbols ${show(env.symbols, 80)}` : "",
    `stdout ${r.digest ? short(r.digest) : "not embedded"}${r.encoding === "text-utf8" ? " (digest over the embedded text, UTF-8)" : ""}`,
    `image ${short(image)}`,
    env.startedAt ? `started ${show(env.startedAt, 30)}` : "",
    markers.length ? `stderr: ${markers.slice(0, 2).join(" | ")}` : "stderr: no diagnostic line",
  ].filter(Boolean);
  const head = `Memory run envelope (uploader-supplied, unsigned) states: ${show(env.plugin, 60)} — ${verdict.words}`;
  const tail = `[${facts.join("; ")}; command: ${show(env.command, 120)}]`;
  const body = `${head} ${tail}`;
  const description = body.length > DESCRIPTION_MAX ? `${body.slice(0, DESCRIPTION_MAX - 2)}…]` : body;
  // The identity is the whole material envelope: two runs with the same words are two rows.
  const identity = createHash("sha256")
    .update(
      JSON.stringify([
        RUN_ENVELOPE_TYPE,
        env.command,
        env.plugin,
        env.exitStatus,
        r.digest,
        image,
        sha256(Buffer.from(env.stderr, "utf8")),
        env.startedAt ?? "",
        env.endedAt ?? "",
      ]),
    )
    .digest("hex")
    .slice(0, 32);
  const observed = env.startedAt ? normalizeTime(env.startedAt) : "";
  const block: MemoryRunBlock = {
    envelopeVersion: version,
    plugin: env.plugin,
    command: env.command,
    exitStatus: env.exitStatus,
    stdoutSha256: r.digest,
    stdoutEncoding: r.encoding,
    ...(r.stated ? { statedStdoutSha256: r.stated } : {}),
    imageSha256: image,
    ...(env.volatilityVersion ? { volatilityVersion: env.volatilityVersion } : {}),
    ...(env.symbols ? { symbols: env.symbols } : {}),
    ...(env.renderer ? { renderer: env.renderer } : {}),
    ...(env.startedAt ? { startedAt: env.startedAt } : {}),
    ...(env.endedAt ? { endedAt: env.endedAt } : {}),
    bound: r.bound,
    verdict,
    stderrLines: markers,
    basis: BASIS,
  };
  return {
    timestamp: observed,
    description: `${description}${observed ? "" : " [undated: the envelope states no start time]"}`,
    severity,
    mitre: [],
    aggKey: boundedAggKey(`mem|run|${identity}`),
    sources: ["Volatility"],
    canonical: createCanonicalEvent({
      event: {
        category: "memory",
        type: "run-envelope",
        action: env.plugin,
        outcome: env.exitStatus === 0 ? "success" : "failure",
      },
      time: { observed: env.startedAt ?? "", normalized: observed },
      evidence: { rawRecords: [{ source: "volatility-run-envelope", locator: `run:${r.index}` }] },
      producer: {
        importer: "memory",
        parserVersion: "1",
        mappingVersion: "memory-run-envelope-v1",
        ruleVersions: ["memory-run-v1"],
      },
      memoryRun: block,
    }),
  };
}
