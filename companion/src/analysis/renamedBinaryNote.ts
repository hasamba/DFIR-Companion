// The renamed-binary fact, owned in one place (#1502).
//
// binaryRenameImport.ts appends `[renamed binary: <onDisk> is really <original>]` to a row whose
// version resource names a different file than the one on disk. Until #1502 that fact reached the
// model only as prose at the end of a long line, and the model graded `mimikatz.exe privilege::debug
// sekurlsa::logonpasswords` Critical/92 with "is really Cmd.Exe" sitting right beside it. Prose at
// the end of a line is not a flag. This module turns the note into one: a structured tag on the
// prompt row (renderDecoyTag) and a deterministic cap on a finding built on nothing else
// (decoyOnlyEvidence → findingGrounding.ts).
//
// It lives at the timeline tier so both the importer (ingest tier) and the readers (findings, ai)
// import the marker and the parser from here — one owner, no second regex kept in sync by a test.
// The marker string itself is also registered in derivedNote.ts DERIVED_NOTE_NAMES, which is what
// keeps correlation from clipping it off a long row.

import type { ForensicEvent } from "./stateTypes.js";

export const RENAMED_BINARY_MARKER = "[renamed binary:";
const NOTE_RE = /\[renamed binary:\s*(.+?)\s+is really\s+(.+?)\]/u;

// The binaries a decoy can be. A file that identifies as one of these carries no capability of its
// own: whatever the command line says, a shell ran it, not the named tool. mshta/wscript/rundll32
// are NOT here — they execute payloads, so a rename onto them proves nothing about absence.
const PLAIN_SHELLS = new Set(["cmd.exe", "powershell.exe", "pwsh.exe"]);

const leaf = (p: string): string =>
  p
    .replace(/[/\\]+$/u, "")
    .split(/[/\\]/u)
    .pop() ?? p;

/** `{ onDisk, original }` from the importer's note; null when the row carries none. */
export function parseRenamedBinaryNote(
  description: string | undefined,
): { onDisk: string; original: string } | null {
  const m = NOTE_RE.exec(description ?? "");
  if (!m) return null;
  return { onDisk: m[1].trim(), original: m[2].trim() };
}

/**
 * The on-disk file name when this row is a DECOY: named like a tool, really a plain shell.
 * `svchost.exe is really mimikatz.exe` is the opposite case — the tool DID run — and returns null,
 * as does a name that matches its resource and an original that can execute payloads itself.
 */
export function decoyShellOf(e: Pick<ForensicEvent, "description">): string | null {
  const note = parseRenamedBinaryNote(e.description);
  if (!note) return null;
  const onDisk = leaf(note.onDisk).toLowerCase();
  const original = leaf(note.original).toLowerCase();
  if (onDisk === original || !PLAIN_SHELLS.has(original)) return null;
  return leaf(note.onDisk);
}

/**
 * The structured tag for a renamed binary. Says exactly what the evidence proves — the file
 * identifies as a shell — and never claims execution is absent: the file may have been swapped
 * after it ran, or another copy may exist. That wording came out of the plan review for #1502.
 */
export function renderDecoyTag(e: Pick<ForensicEvent, "description">): string {
  const note = parseRenamedBinaryNote(e.description);
  if (!note) return "";
  const pair = `${note.onDisk} is really ${note.original}`.replace(/[<>\u0000-\u001f]/gu, "");
  if (!decoyShellOf(e)) return `<renamed-binary:${pair}>`;
  const shell = leaf(note.original).toLowerCase();
  return `<renamed-binary:${pair} — the file identifies as ${shell}, so this row does not substantiate execution of the named tool>`;
}

// A file-presence artifact ABOUT the decoy file: no process identity, no network fields, and a path
// whose leaf is the decoy's name or its prefetch (`MIMIKATZ.EXE-A84515FA.pf`). MFT, Amcache and
// Prefetch rows for the dropped file are this. A row with a process identity is behavioral evidence
// in its own right — Sysmon EID 10 on lsass, an EDR verdict — and is never folded in by name.
function isFileTraceOf(e: ForensicEvent, decoyLeaves: ReadonlySet<string>): boolean {
  if (e.processName || e.commandLine || e.pid !== undefined) return false;
  if (e.srcIp || e.dstIp || e.port !== undefined) return false;
  if (!e.path) return false;
  const name = leaf(e.path).toLowerCase();
  if (decoyLeaves.has(name)) return true;
  const prefetch = /^(.+?)-[0-9a-f]{8}\.pf$/iu.exec(name);
  return !!prefetch && decoyLeaves.has(prefetch[1]);
}

/** One decoy: the name on disk and the shell it identifies as. */
export interface DecoyBinary {
  onDisk: string;
  original: string;
}

/**
 * The decoy file names a finding rests on, when it rests on NOTHING else: every supporting event is
 * either a decoy-shell row or a file trace of one of those decoys. Any other event — behavioral,
 * network, or simply unrelated — returns [] and the finding keeps its grading. The gate lowers only
 * when it is certain; a wrongly cited row is the content-mismatch class, not this one.
 */
export function decoyOnlyEvidence(supporting: readonly ForensicEvent[]): DecoyBinary[] {
  const decoys = new Map<string, DecoyBinary>(); // lowercased on-disk leaf → the pair
  for (const e of supporting) {
    const onDisk = decoyShellOf(e);
    const note = onDisk ? parseRenamedBinaryNote(e.description) : null;
    if (onDisk && note) decoys.set(onDisk.toLowerCase(), { onDisk, original: leaf(note.original) });
  }
  if (decoys.size === 0) return [];
  const leaves = new Set(decoys.keys());
  for (const e of supporting) {
    if (decoyShellOf(e)) continue;
    if (!isFileTraceOf(e, leaves)) return [];
  }
  return [...decoys.values()];
}
