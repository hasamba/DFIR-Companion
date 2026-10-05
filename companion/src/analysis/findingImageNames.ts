// Program-name grounding (#1954). A High/Critical finding that names a program (`a.exe`) which no
// cited row carries is telling a process chain its own evidence does not show. A lab run produced
// exactly that: the finding said one binary ran the echoed commands, the cited rows showed another,
// and the second-opinion referee missed it. findingGrounding.ts floors such a finding through the
// same `contentMismatch` flag as an IP mismatch. This module only extracts and compares names.
//
// Deliberately narrow: only names ending in `.exe`, compared by lowercased leaf. A name that follows
// a negation or a hedge in the same clause ("unlike svchost.exe", "tools such as procdump.exe") is
// context, not a claim, and is skipped. A renamed-binary note (#1502) lives in the row description,
// which is part of the evidence text, so both of its names count as present with no special case.

import type { Finding, ForensicEvent } from "./stateTypes.js";

// A path-or-name token ending in `.exe`. The look-behind starts the token after a separator or a
// space, so `C:\Tools\a.exe` yields the leaf `a.exe`; the look-ahead rejects `payload.exe.bak`.
const EXE_LEAF_RE =
  /(?<![A-Za-z0-9_$~.-])([A-Za-z0-9_$~-][A-Za-z0-9_$~.-]*\.exe)(?![A-Za-z0-9_]|\.[A-Za-z0-9_])/gi;

// Words that make the next name context instead of a claim. `e_g_` is "e.g." after normalizing.
const CONTEXT_WORDS_RE =
  /\b(?:not|never|no|unlike|instead\s+of|rather\s+than|other\s+than|except|such\s+as|e_g_|for\s+example|for\s+instance|typically|commonly|often)\b/i;
// A clause break ends the look-back window. A dot counts only at a sentence end, not inside a name.
const CLAUSE_BREAK_RE = /[,;:]|\.(?=\s|$)/g;
const LOOK_BACK_CHARS = 60;

/** The distinct lowercased `.exe` leaf names a text carries, in first-seen order. */
export function exeLeavesIn(text: string): string[] {
  return [...new Set([...text.matchAll(EXE_LEAF_RE)].map((m) => m[1].toLowerCase()))];
}

// "e.g." and "i.e." would read as sentence ends; swap them for word tokens of the same length.
function normalizeAbbrev(text: string): string {
  return text.replace(/\be\.g\./gi, "e_g_").replace(/\bi\.e\./gi, "i_e_");
}

function isContextMention(text: string, index: number): boolean {
  const window = text.slice(Math.max(0, index - LOOK_BACK_CHARS), index);
  const breaks = [...window.matchAll(CLAUSE_BREAK_RE)];
  const clause = breaks.length ? window.slice(breaks[breaks.length - 1].index + 1) : window;
  return CONTEXT_WORDS_RE.test(clause);
}

function claimedLeaves(text: string): string[] {
  const norm = normalizeAbbrev(text);
  const out: string[] = [];
  for (const m of norm.matchAll(EXE_LEAF_RE)) {
    if (!isContextMention(norm, m.index)) out.push(m[1].toLowerCase());
  }
  return out;
}

function evidenceText(e: ForensicEvent): string {
  return [e.description, e.message, e.processName, e.parentName, e.commandLine, e.path]
    .filter((s): s is string => !!s)
    .join(" ");
}

/** `.exe` names the finding claims that no cited row carries; empty when all are backed. */
export function claimedImagesNotInEvidence(f: Finding, supporting: readonly ForensicEvent[]): string[] {
  const claimed = new Set([...claimedLeaves(f.title), ...claimedLeaves(f.description)]);
  if (!claimed.size) return [];
  const present = new Set(exeLeavesIn(supporting.map(evidenceText).join(" ")));
  return [...claimed].filter((n) => !present.has(n));
}

/** The one program image the cited rows show, when they show exactly one; else undefined. */
export function soleCitedImage(supporting: readonly ForensicEvent[]): string | undefined {
  const images = new Set(supporting.flatMap((e) => exeLeavesIn(e.processName ?? "")));
  return images.size === 1 ? [...images][0] : undefined;
}
