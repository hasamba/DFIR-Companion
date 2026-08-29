import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import type { ToolConfig } from "./toolConfig.js";
import { cleanToolOutput, type ToolRunner } from "./toolRunner.js";

/**
 * What a parser run must be able to prove afterwards (#688).
 *
 * A tool's output is evidence, and evidence is only as trustworthy as the account of how it was
 * produced. The Companion already hashed the OUTPUT (every stored artifact gets a custody record),
 * but the run itself left no trace: which build of Hayabusa, which Sigma rule set, which arguments,
 * and what the tool complained about on stderr. Six months later "Chainsaw found nothing" is not a
 * defensible statement without them — a rule set that failed to load produces exactly that result.
 *
 * Everything here is BEST EFFORT except the ruleset hash for a fail-closed tool: a version probe
 * that fails records an empty version rather than failing the analyst's run.
 */

/** A rule set reduced to one deterministic identity. */
export interface RulesetIdentity {
  /** The configured path, verbatim. */
  path: string;
  /** SHA-256 over the file, or over the directory's sorted "relative path + file hash" listing. */
  sha256: string;
  /** How many files went into the hash (1 for a single-file rule set). */
  files: number;
  /** Total bytes hashed. */
  bytes: number;
}

/** The full account of one tool run, recorded alongside the output it produced. */
export interface ToolRunProvenance {
  toolId: string;
  binary: string;
  /** First line of the binary's own version output; "" when the probe failed. */
  version: string;
  /** The exact argv the Companion spawned — placeholders already substituted. */
  argv: string[];
  exitCode: number;
  /** Bounded tail of the tool's stderr, cleaned of ANSI and progress redraws. */
  stderr: string;
  /** SHA-256 of the output text the importer was handed. */
  outputSha256: string;
  ruleset: RulesetIdentity | null;
}

// A rule set is a git checkout of a few thousand small YAML files. These caps exist so a mistyped
// path pointing at a home directory (or a checkout with its .git intact) cannot turn one tool run
// into an unbounded disk walk. Exceeding either means "this is not a rule set" — the identity comes
// back null, which for a fail-closed tool stops the run.
const MAX_RULESET_FILES = 50_000;
const MAX_RULESET_BYTES = 256 * 1024 * 1024;

// Path segments never part of a rule set: version-control internals (huge, and their contents change
// with no rule change) and the usual editor/OS clutter.
function isSkippedSegment(name: string): boolean {
  return name.startsWith(".");
}

async function hashOneFile(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path, { highWaterMark: 1 << 20 })) {
    hash.update(chunk as Buffer);
  }
  return hash.digest("hex");
}

/**
 * Reduce a rules file or rules DIRECTORY to one identity, or null when the path does not exist, is
 * empty, or is too large to be a rule set.
 *
 * A directory is hashed over its sorted list of "relative path + file sha256" lines rather than over
 * concatenated bytes, so the result is stable regardless of the order the filesystem lists entries
 * in, and it changes when a rule is added, removed, edited OR renamed. Two analysts on the same
 * Sigma commit get the same hash on Windows and on Linux (the separator is normalized to "/").
 */
export async function hashRuleset(path: string): Promise<RulesetIdentity | null> {
  const target = path.trim();
  if (!target) return null;
  let info;
  try {
    info = await stat(target);
  } catch {
    return null; // missing / unreadable — for a fail-closed tool this is the whole point
  }

  if (info.isFile()) {
    if (info.size > MAX_RULESET_BYTES) return null;
    try {
      return { path: target, sha256: await hashOneFile(target), files: 1, bytes: info.size };
    } catch {
      return null;
    }
  }
  if (!info.isDirectory()) return null;

  const lines: string[] = [];
  let bytes = 0;
  const walk = async (dir: string, rel: string): Promise<boolean> => {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return false;
    }
    for (const entry of entries) {
      if (isSkippedSegment(entry.name)) continue;
      const abs = join(dir, entry.name);
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (!(await walk(abs, relPath))) return false;
        continue;
      }
      if (!entry.isFile()) continue; // sockets, devices, dangling links: not rules
      if (lines.length >= MAX_RULESET_FILES) return false;
      try {
        bytes += (await stat(abs)).size;
        if (bytes > MAX_RULESET_BYTES) return false;
        lines.push(`${relPath} ${await hashOneFile(abs)}`);
      } catch {
        return false; // a rule we cannot read makes the whole set unidentifiable
      }
    }
    return true;
  };

  if (!(await walk(target, ""))) return null;
  if (lines.length === 0) return null; // an empty directory is not a rule set
  lines.sort();
  const sha256 = createHash("sha256").update(lines.join("\n"), "utf8").digest("hex");
  return { path: target, sha256, files: lines.length, bytes };
}

// A version probe must never cost more than a moment or hold more than a few lines.
const VERSION_TIMEOUT_MS = 15_000;
const VERSION_MAX_BYTES = 64 * 1024;

/**
 * The tool's own version string, or "" when it cannot be obtained. Never throws: a binary that has
 * no version flag, prints its banner to stderr, or refuses to launch must not fail the analyst's run
 * — it just leaves the version blank in the record.
 */
export async function probeToolVersion(cfg: ToolConfig, runner: ToolRunner): Promise<string> {
  if (!cfg.binary) return "";
  try {
    const res = await runner(cfg.binary, cfg.versionArgs ?? ["--version"], {
      timeoutMs: VERSION_TIMEOUT_MS,
      maxOutputBytes: VERSION_MAX_BYTES,
    });
    // Several tools print the banner to stderr, so read both. cleanToolOutput keeps the TAIL, and a
    // version banner leads — so take the first line of the cleaned whole.
    const cleaned = cleanToolOutput(`${res.stdout}\n${res.stderr}`, 40);
    return (cleaned.split("\n").find((l) => l.trim().length > 0) ?? "").trim().slice(0, 200);
  } catch {
    return "";
  }
}

// How much stderr the custody line carries. Enough to show what the tool complained about, short
// enough that a chatty tool cannot bloat the tamper-evident log.
const STDERR_TAIL_CHARS = 400;

/**
 * The one-line account of a run, written into the custody record's `source` field.
 *
 * Custody records are a flat, appendable, human-readable log — so this is a single readable line
 * rather than nested JSON, and every part is bounded.
 */
export function describeToolRun(p: ToolRunProvenance): string {
  const parts = [
    `tool ${p.toolId}${p.version ? ` ${p.version}` : ""}`,
    `binary ${p.binary}`,
    `exit ${p.exitCode}`,
    `argv ${JSON.stringify(p.argv).slice(0, 1200)}`,
    p.ruleset
      ? `ruleset ${p.ruleset.path} sha256:${p.ruleset.sha256} (${p.ruleset.files} file(s), ${p.ruleset.bytes} bytes)`
      : "ruleset none",
    `output sha256:${p.outputSha256}`,
  ];
  const stderr = p.stderr.trim();
  if (stderr) parts.push(`stderr ${JSON.stringify(stderr.slice(-STDERR_TAIL_CHARS))}`);
  return parts.join(" | ");
}

/** SHA-256 of the text the importer was handed, matching how saveImport hashes what it stores. */
export function hashOutputText(text: string): string {
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}
