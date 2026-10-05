// The command line as its own structured tag on a synthesis row (#1951).
//
// Every model-facing row goes through promptDescription(): 240 characters, head + " … " + tail.
// A Chainsaw Sysmon EID 1 row is often ~480 characters — rule name, Image=, CommandLine=,
// ParentImage=, ParentCommandLine=, host — and the cut lands inside CommandLine=. On INC-2026-027
// the model read `… powershell.exe - CommandLi … @ host` and wrote that the command line was
// truncated, although the full value sat in the row's `commandLine` field.
//
// So the stored `commandLine` gets its own seat: `<cmd:…>`, capped at CMD_TAG_MAX with head and
// tail kept. It is emitted ONLY when the description render does not already show the arguments,
// so a short row costs zero extra tokens and renders as before. The leading image path is dropped
// when it repeats the row's image — `<proc:…>` already names it.
//
// PURE — no I/O. Not a prompt constant: the eval change gate hashes only prompts/*.ts.

import type { ForensicEvent } from "./stateTypes.js";
import { headAndTail, promptDescription } from "./ai/promptDescription.js";

/** Cap for the tag value; head and tail are kept past it. */
export const CMD_TAG_MAX = 300;

/** One line, no angle brackets (the tag delimiters), no control characters. */
function clean(v: string): string {
  return v
    .replace(/\s+/gu, " ")
    .replace(/[<>\u0000-\u001f\u007f]/gu, "")
    .replace(/\s+/gu, " ")
    .trim();
}

/** The file name at the end of a Windows or POSIX path. */
function baseName(p: string): string {
  const cut = Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/"));
  return cut >= 0 ? p.slice(cut + 1) : p;
}

/** The image names this row already carries, lowercased. */
function knownImages(e: ForensicEvent): Set<string> {
  const names = new Set<string>();
  for (const v of [e.processName, e.path ? baseName(e.path) : undefined]) {
    const n = (v ?? "").trim().toLowerCase();
    if (n) names.add(n);
  }
  return names;
}

/** The command line without a leading image path that repeats the row's image; else unchanged. */
function stripRepeatedImage(cmd: string, e: ForensicEvent): string {
  const lower = cmd.toLowerCase();
  const fullPath = (e.path ?? "").trim().toLowerCase();
  // A bare image path with spaces (C:\Program Files\…) cannot be split on whitespace.
  if (fullPath) {
    for (const lead of [`"${fullPath}"`, fullPath]) {
      if (lower.startsWith(lead) && /^(\s|$)/u.test(cmd.slice(lead.length))) {
        return cmd.slice(lead.length).trim();
      }
    }
  }
  const m = /^(?:"([^"]*)"|(\S+))(?=\s|$)/u.exec(cmd);
  if (!m) return cmd;
  const first = (m[1] ?? m[2] ?? "").toLowerCase();
  const names = knownImages(e);
  const base = baseName(first);
  if (names.has(base) || names.has(`${base}.exe`)) return cmd.slice(m[0].length).trim();
  return cmd;
}

/**
 * `<cmd:ARGS>` for a row whose stored command line the 240-character description render hides;
 * "" when the row has no command line, only an image, or the render already shows the arguments.
 */
export function renderCommandLineTag(e: ForensicEvent): string {
  if (!e.commandLine) return "";
  const args = clean(stripRepeatedImage(clean(e.commandLine), e));
  if (!args) return "";
  if (clean(promptDescription(e.description)).includes(args)) return "";
  return `<cmd:${headAndTail(args, CMD_TAG_MAX)}>`;
}
