// Command-line identity for a process CREATION, used to correlate the SAME creation reported by
// different tools that assign different pids and share no file hash (correlate.ts step 4, #68).
//
// The signature is deliberately TIME-INDEPENDENT: it captures WHICH command shape ran, under which
// parent, on which host — not when. correlate.ts applies the ±window separately (exactly like the
// host+pid step), so two tools reporting the same creation seconds apart merge, while a genuine
// re-run of the same command later stays distinct (window + the same-tool corroboration guard).
// Bucketing time INTO the signature would instead split two events that straddle a bucket boundary.

import { createHash } from "node:crypto";
import type { ForensicEvent } from "./stateTypes.js";

// Pulls a command line out of free text an importer left unstructured. Matches "CommandLine=…",
// "cmd=…", "cmdline: …" etc., stopping at a field separator (" | " or Hayabusa's " ¦ ") or end of
// the segment. Best-effort: only used as a fallback when the structured `commandLine` field is unset.
const CMDLINE_RE = /(?:command_?line|cmdline|cmd)\s*[=:]\s*(.+?)(?:\s+[|¦]\s+|$)/i;

// Normalize a command line for cross-tool matching: collapse whitespace, reduce the leading image to
// its basename (tools disagree on the same binary's full path — "C:\Windows\System32\cmd.exe" vs
// "cmd.exe"), and lowercase. Arguments are LEFT INTACT: they are exactly what distinguishes one
// invocation from another, so stripping them would collapse distinct commands (the same failure the
// step-1 image-hash comment in correlate.ts warns about for shared interpreters).
export function normalizeCommandLine(raw: string): string {
  const collapsed = raw.replace(/\s+/g, " ").trim();
  if (!collapsed) return "";
  let image: string;
  let rest: string;
  if (collapsed[0] === '"') {
    const end = collapsed.indexOf('"', 1);
    if (end === -1) { image = collapsed.slice(1); rest = ""; }
    else { image = collapsed.slice(1, end); rest = collapsed.slice(end + 1).trim(); }
  } else {
    const sp = collapsed.indexOf(" ");
    if (sp === -1) { image = collapsed; rest = ""; }
    else { image = collapsed.slice(0, sp); rest = collapsed.slice(sp + 1).trim(); }
  }
  const base = image.split(/[\\/]/).pop() || image;
  return (rest ? `${base} ${rest}` : base).toLowerCase();
}

// Best-effort command line for an event: the structured field first, else scraped from text.
export function eventCommandLine(e: ForensicEvent): string {
  if (e.commandLine && e.commandLine.trim()) return normalizeCommandLine(e.commandLine);
  for (const src of [e.description, e.message ?? ""]) {
    const m = CMDLINE_RE.exec(src);
    if (m) return normalizeCommandLine(m[1]);
  }
  return "";
}

// A stable signature for a process creation, or undefined when no command line can be determined
// (so non-process rows and creations with no captured command never get a bogus key).
export function computeChainSignature(e: ForensicEvent): string | undefined {
  const cmd = eventCommandLine(e);
  if (!cmd) return undefined;
  const host = (e.asset ?? "").split(".")[0].trim().toLowerCase();
  const proc = (e.processName ?? "").trim().toLowerCase();
  const parent = (e.parentName ?? "").trim().toLowerCase();
  const key = `${host}|${proc}|${parent}|${cmd}`;
  return createHash("sha1").update(key).digest("hex").slice(0, 16);
}
