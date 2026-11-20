// AI Agent Forensics (#2722): did the file change between hashing and preservation? Each hit carries
// the file's hash taken after the YARA scan; the preserved copy's hash comes from the artifact's own
// upload() (project files) or, for files the AICodingAgents triage collection kept, from the hunt's
// upload manifest.
//
// WHAT "same" DOES NOT PROVE: YARA, hash() and upload() each read the file separately, and the bytes
// YARA matched are never hashed. A file replaced after the match but before the hash gives two equal
// hashes of the replacement. So "same" means only "unchanged between hashing and preservation", and
// every surface that shows the check also shows AI_AGENT_HASH_CAVEAT (Codex review of #2722).
//
// The answer fails toward "not recorded": "not preserved" is said only when the artifact itself said
// the file was not kept. A manifest that could not be read in full, a row with no client id, or a path
// the manifest does not show all read "not recorded" — the path join is best-effort, and an upload may
// not have landed yet, so the absence of a manifest entry proves nothing.

import type { AiAgentHitRow } from "./aiAgentRows.js";
import type { UploadManifestEntry } from "./aiAgentRunStore.js";

export type AiAgentHashCheck = "same" | "differs" | "not preserved" | "not recorded";

/** Said beside the check on every surface: the panel, report.md, report.csv and the manual. */
export const AI_AGENT_HASH_CAVEAT =
  "The file is hashed after the YARA scan, in a separate read: the bytes YARA read are not separately " +
  "hashed, so a match between the file hash and the preserved copy shows only that the file did not " +
  "change between hashing and preservation. That the preserved copy holds the matched bytes is not proven.";

const LABELS: Partial<Record<AiAgentHashCheck, string>> = {
  same: "same: unchanged between hashing and preservation",
  differs: "differs: changed between hashing and preservation",
};

/** The check as the exports word it; "not preserved" and "not recorded" read as they are. */
export function hashCheckLabel(check: AiAgentHashCheck): string {
  return LABELS[check] ?? check;
}

export interface AiAgentHashResult {
  preservedSha256: string;
  hashCheck: AiAgentHashCheck;
}

const HEX64 = /^[0-9a-f]{64}$/;
const NOT_PRESERVED = "match observed; file not preserved";
const NOT_RECORDED: AiAgentHashResult = { preservedSha256: "", hashCheck: "not recorded" };

/** A client path or an upload's server path, compared case-insensitively with forward slashes. */
function normalizePath(p: string): string {
  let s = p;
  try {
    s = decodeURIComponent(p);
  } catch {
    // A path with a stray "%" stays as it is.
  }
  return s
    .replace(/\\/g, "/")
    .replace(/\/{2,}/g, "/")
    .toLowerCase();
}

function compare(scan: string, preserved: string): AiAgentHashResult {
  if (!HEX64.test(scan) || !HEX64.test(preserved))
    return { preservedSha256: preserved, hashCheck: "not recorded" };
  return { preservedSha256: preserved, hashCheck: scan === preserved ? "same" : "differs" };
}

/** The manifest entries for this client whose server path ends with the hit's client path. */
function manifestMatches(
  manifest: readonly UploadManifestEntry[],
  clientId: string,
  filePath: string,
): UploadManifestEntry[] {
  const key = normalizePath(filePath).replace(/^\/+/, "");
  if (!key) return [];
  return manifest.filter((m) => {
    if (m.clientId !== clientId) return false;
    const path = normalizePath(m.path);
    return path === key || path.endsWith(`/${key}`);
  });
}

/**
 * The preserved hash and the check for one hit. `manifest` is the hunt's complete upload manifest, or
 * null when it could not be read in full; `clientId` is the endpoint the row came from.
 */
export function aiAgentHashCheck(
  row: AiAgentHitRow,
  clientId: string,
  manifest: readonly UploadManifestEntry[] | null | undefined,
): AiAgentHashResult {
  const scan = row.FileSha256 ?? "";
  if (row.PreservedSha256) return compare(scan, row.PreservedSha256);
  if ((row.Preserved ?? "").startsWith(NOT_PRESERVED))
    return { preservedSha256: "", hashCheck: "not preserved" };
  if (!manifest || !clientId || !row.FilePath) return NOT_RECORDED;
  const hashes = [
    ...new Set(
      manifestMatches(manifest, clientId, row.FilePath)
        .map((m) => String(m.sha256 ?? "").toLowerCase())
        .filter((h) => HEX64.test(h)),
    ),
  ];
  if (!hashes.length) return NOT_RECORDED;
  return compare(scan, hashes.includes(scan) ? scan : hashes[0]);
}
