// Shell-escape normalization for COMMAND MATCHING ONLY (#908 item 1).
//
// The detection rules in tradecraftRules.ts and reconTechniques.ts match literal substrings —
// `certutil`, `-enc`, `vssadmin delete`. Every one of them is defeated by escaping the binary or
// the flag, which costs an attacker nothing:
//
//   c^e^r^t^u^t^i^l -urlcache -f http://…        cmd.exe caret escapes
//   p`o`w`ershell -e`n`c <base64>                 PowerShell backtick escapes
//   "cert"+"util" / 'IE'+'X'                      string concatenation
//   pow""ershell                                  empty quote pair splitting a token
//
// Base64 decoding (deobfuscate.ts) does not help here: the payload is not encoded, it is spelled
// differently. This module spells it back.
//
// THREE RULES KEEP THIS SAFE.
//
//  1. The result is for MATCHING, never for display or evidence. Callers build a throwaway blob,
//     match against it, and keep showing the original command. Nothing normalized is persisted.
//  2. Callers match the ORIGINAL FIRST and the normalized text second, so normalization can only
//     ADD a match, never remove one. A rule that fires today still fires after this change.
//  3. Normalization is bounded and single-pass: one left-to-right scan with quote-state tracking,
//     a capped concatenation loop, and an input ceiling. No recursion, no backtracking, no eval.
//
// SHELL-AWARE, because the naive version is wrong. Backtick-n is a NEWLINE inside double quotes
// and a literal "n" outside them — `-e`n`c` is `-enc`, while "a`nb" is two lines. A rule that
// picked one meaning would either miss the evasion or invent a token nobody typed. Single quotes
// are literal in PowerShell, so nothing inside them is touched at all, and a caret inside double
// quotes is literal to cmd.exe.
//
// `tricks` reports which forms were seen. That is itself evidence — a command line that had to be
// spelled sideways to run is a Defense Evasion signal (T1027) independent of what it then did.

export type ObfuscationTrick = "caret" | "backtick" | "concat" | "empty-quote";

export interface NormalizedCommand {
  text: string; // the de-escaped text, for matching only
  changed: boolean; // true when normalization altered anything
  tricks: ObfuscationTrick[]; // which escaping forms were found, in detection order
  truncated: boolean; // input exceeded MAX_INPUT and was returned unchanged
}

// A command line longer than this is not a command line — it is a pasted blob, a log line that
// swallowed a field, or a payload. Scanning it buys nothing and costs time on every imported row.
export const MAX_INPUT = 8192;

// How many concatenation joins to resolve. `"a"+"b"+"c"` collapses in one pass; the loop exists
// for nested residue, and the cap exists so a crafted input cannot spin here.
const MAX_CONCAT_PASSES = 8;

// PowerShell escape sequences that produce WHITESPACE rather than their letter. Only meaningful
// inside a double-quoted string; outside, a backtick escapes the literal character.
const WHITESPACE_ESCAPES = new Set(["n", "t", "r", "a", "b", "f", "v", "0"]);

// `"po"+"wer"+"shell"` → the joined content with the quotes dropped. Each part is quoted, the
// parts are joined by `+`, and the quote characters may differ between parts. The inner class
// excludes both quote characters so a part can never swallow the delimiter of the next one.
const CONCAT_RE = /(["'])([^"']*)\1(?:\s*\+\s*(["'])([^"']*)\3)+/g;

// An empty quote pair wedged between two word characters — `pow""ershell`. Anchored on word
// characters on BOTH sides so a genuine empty argument (`-Name ""`, surrounded by spaces) is left
// exactly as written.
const EMPTY_QUOTE_RE = /(\w)(?:""|'')(?=\w)/g;

/**
 * De-escape a command line for matching. Returns the original unchanged when nothing was escaped,
 * so a caller can skip the second match entirely on the common case.
 */
export function normalizeCommand(raw: string): NormalizedCommand {
  const src = typeof raw === "string" ? raw : "";
  if (src.length > MAX_INPUT) {
    return { text: src, changed: false, tricks: [], truncated: true };
  }
  const found = new Set<ObfuscationTrick>();

  // ── Pass 1: caret and backtick escapes, tracking quote state ────────────────────────────────
  let out = "";
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];

    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      out += ch;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      out += ch;
      continue;
    }
    // PowerShell single quotes are literal end to end. Nothing inside them escapes anything.
    if (inSingle) {
      out += ch;
      continue;
    }

    const next = i + 1 < src.length ? src[i + 1] : "";

    // cmd.exe caret. Literal inside double quotes, and a trailing caret is a line continuation
    // rather than an escape — neither is evasion, so neither is a trick.
    if (ch === "^" && !inDouble) {
      if (!next) {
        out += ch;
        continue;
      }
      out += next; // `^^` yields a literal caret, `^x` yields x
      i++;
      found.add("caret");
      continue;
    }

    // PowerShell backtick.
    if (ch === "`") {
      if (!next) {
        out += ch;
        continue;
      }
      if (inDouble && WHITESPACE_ESCAPES.has(next)) {
        out += " "; // `n / `t inside a string really is whitespace
      } else {
        out += next; // outside a string (or an unknown escape) it is the literal character
      }
      i++;
      found.add("backtick");
      continue;
    }

    out += ch;
  }

  // ── Pass 2: quoted concatenation ────────────────────────────────────────────────────────────
  for (let pass = 0; pass < MAX_CONCAT_PASSES; pass++) {
    const joined = out.replace(CONCAT_RE, (m) => {
      // Re-read the parts from the whole match so an arbitrary number of terms collapses at once.
      const parts = m.match(/(["'])([^"']*)\1/g) ?? [];
      return parts.map((p) => p.slice(1, -1)).join("");
    });
    if (joined === out) break;
    out = joined;
    found.add("concat");
  }

  // ── Pass 3: empty quote pairs ───────────────────────────────────────────────────────────────
  const unpadded = out.replace(EMPTY_QUOTE_RE, "$1");
  if (unpadded !== out) {
    out = unpadded;
    found.add("empty-quote");
  }

  return {
    text: out,
    changed: out !== src,
    tricks: [...found],
    truncated: false,
  };
}

/**
 * The blob a matcher should test: the original, plus the de-escaped form when it differs.
 *
 * Joined with a newline so no rule can match ACROSS the seam and claim a hit that exists in
 * neither reading. Callers pass this to an existing regex unchanged — matching the original text
 * is still tried first, character for character, so this can only widen what fires.
 */
export function matchableCommand(raw: string): string {
  const n = normalizeCommand(raw);
  return n.changed ? `${raw}\n${n.text}` : raw;
}
