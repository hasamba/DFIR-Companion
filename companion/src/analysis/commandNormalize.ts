// Shell-escape normalization for COMMAND MATCHING ONLY (#908 item 1).
//
// The detection rules match literal substrings — `certutil`, `-enc`, `vssadmin delete`. Every one
// of them is defeated by escaping the binary or the flag, which costs an attacker nothing:
//
//   c^e^r^t^u^t^i^l -urlcache -f http://…        cmd.exe caret escapes
//   p`o`w`ershell -e`n`c <base64>                 PowerShell backtick escapes
//   "cert"+"util" / 'IE'+'X'                      string concatenation
//   pow""ershell  /  c"er"tutil                   quote pairs splitting a token
//   seku^<CRLF>rlsa                               caret/backtick line continuation
//
// Base64 decoding (deobfuscate.ts) does not help: the payload is not encoded, it is spelt
// differently. This module spells it back.
//
// ─────────────────────────── WHY THIS IS SO DEFENSIVE ───────────────────────────
//
// A false NEGATIVE here means one evasive command is graded like ordinary telemetry. A false
// POSITIVE means the tool asserts "credential dumping" about a string nobody malicious ever typed
// — in a report that goes into a real investigation. The second failure is far worse, so every
// rule below is written to avoid inventing a token, and the review that shaped this module found
// five separate ways an earlier version did exactly that:
//
//   • `de^lete harmless vssadmin` graded STRONG. The first version matched against the original
//     and the normalized copy JOINED BY A NEWLINE, and `vssadmin\s+delete` matched ACROSS the
//     seam — `\s` matches `\n` — producing a hit present in neither reading. There is no separator
//     that is safe here, so the copies are now matched SEPARATELY and never concatenated.
//   • `Write-Output "se""kurlsa"` graded STRONG. Inside a double-quoted PowerShell string `""` is
//     a LITERAL QUOTE, not a token split, so the value is `se"kurlsa` and nothing matches.
//   • `Write-Output "vssadmin`adelete"` graded STRONG. `` `a `` is BEL, not whitespace; mapping it
//     to a space spliced two words into `vssadmin delete`.
//   • `Write-Output '"IE"+"X"'` graded WEAK. Single quotes are literal in PowerShell, so that is
//     one string containing plus signs, not a concatenation to resolve.
//   • `powershell.exe Write-Output se^kurlsa` graded STRONG. `^` is not a PowerShell escape at all.
//
// The lesson in all five: escaping only means something inside the shell that defines it, and
// inside the quoting context that defines it. So this is a real scan with quote state, not a pile
// of replace() calls.
//
// ─────────────────────────── THE THREE INVARIANTS ───────────────────────────
//
//  1. MATCHING ONLY. Callers build throwaway candidate strings and keep showing the original
//     command. Nothing normalized is displayed, persisted, or written to evidence.
//  2. SEPARATE CANDIDATES. `commandCandidates` returns the original AND the de-escaped copy as
//     distinct strings. A caller tests each in turn, so a match must exist wholly inside one
//     reading. Normalization can only ADD a match, never remove one, and never fabricate one from
//     two halves.
//  3. BOUNDED. One left-to-right pass, a capped concat loop, an 8 KB ceiling. No recursion, no
//     backtracking-prone patterns, no eval.

export type ObfuscationTrick = "caret" | "backtick" | "continuation" | "concat" | "quote-split";

/** Which shell's escape syntax applies. Derived from the process image when one is recorded. */
export type ShellKind = "cmd" | "powershell" | "unknown";

export interface NormalizedCommand {
  text: string; // the de-escaped text, for matching only
  changed: boolean; // true when normalization altered anything
  tricks: ObfuscationTrick[]; // which escaping forms were found
  truncated: boolean; // input exceeded MAX_INPUT and was returned unchanged
}

// A command line longer than this is not a command line — it is a pasted blob or a payload.
export const MAX_INPUT = 8192;

// How many concatenation joins to resolve. `"a"+"b"+"c"` collapses in one pass; the cap exists so
// a crafted input cannot spin here.
const MAX_CONCAT_PASSES = 8;

// With no process image we cannot know which shell ran, and a LONE escape character is far more
// likely to be literal text than evasion — `se^kurlsa` in a filename, a backtick in a bash command
// substitution. Real obfuscation sprays them: `c^e^r^t^u^t^i^l` carries seven. So when the shell is
// unknown, an escape form must appear at least this many times before it is honoured at all.
const UNKNOWN_SHELL_MIN_ESCAPES = 2;

// Sentinels standing in for the CONTENT of a single-quoted literal while concatenation and
// quote-splitting run. Unicode private-use characters: they carry no shell meaning, cannot appear
// in a real command line, and — unlike a bare number — cannot collide with digits already in the
// text (`calc 2 + 2` would have been mangled by a numeric placeholder).
const PH_OPEN = "\uE000";
const PH_CLOSE = "\uE001";
const PH_RE = /\uE000(\d+)\uE001/g;

// PowerShell escapes, inside a double-quoted string only. Each maps to the character it actually
// produces — NOT to a space. `a` is BEL and `0` is NUL; treating them as whitespace is what let
// "vssadmin`adelete" masquerade as "vssadmin delete".
const PS_ESCAPES: Record<string, string> = {
  n: "\n",
  t: "\t",
  r: "\r",
  a: "\x07",
  b: "\b",
  f: "\f",
  v: "\v",
  e: "\x1b",
  "0": "\0",
};

// `"po"+"wer"+"shell"` → the joined content, quotes dropped. Applied only OUTSIDE single-quoted
// literals (see the mask in normalizeCommand).
const CONCAT_RE = /(["'])([^"']*)\1(?:\s*\+\s*(["'])([^"']*)\3)+/g;

// A quote pair wedged between two word characters — `pow""ershell`, `c"er"tutil`. Anchored on word
// characters on BOTH sides, and the quoted part may not contain whitespace, so a genuine quoted
// path (`"C:\Program Files"`, preceded by a space) is never touched.
const QUOTE_SPLIT_RE = /(\w)(["'])([^"'\s]*)\2(?=\w)/g;

/** The shell whose escape syntax a process image implies. */
export function shellFromImage(image: string): ShellKind {
  const base = String(image ?? "")
    .toLowerCase()
    .replace(/^.*[\\/]/, "");
  if (/^(?:powershell|pwsh|powershell_ise)(?:\.exe)?$/.test(base)) return "powershell";
  if (/^cmd(?:\.exe)?$/.test(base)) return "cmd";
  return "unknown";
}

function countChar(s: string, ch: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) if (s[i] === ch) n++;
  return n;
}

/**
 * De-escape a command line for matching. `shell` selects which escape syntax applies; with
 * "unknown" both are considered, but only when an escape character appears often enough to be
 * deliberate.
 */
export function normalizeCommand(raw: string, shell: ShellKind = "unknown"): NormalizedCommand {
  const src = typeof raw === "string" ? raw : "";
  if (src.length > MAX_INPUT) {
    return { text: src, changed: false, tricks: [], truncated: true };
  }

  // Which escape characters this text is allowed to honour.
  const caretOk =
    shell === "cmd" || (shell === "unknown" && countChar(src, "^") >= UNKNOWN_SHELL_MIN_ESCAPES);
  const backtickOk =
    shell === "powershell" || (shell === "unknown" && countChar(src, "`") >= UNKNOWN_SHELL_MIN_ESCAPES);

  const found = new Set<ObfuscationTrick>();

  // ── Pass 1: escapes, quote-aware. Emits the text plus a mask marking the characters that came
  // from inside a SINGLE-quoted literal, which passes 2 and 3 must not touch. ─────────────────
  const chars: string[] = [];
  const literal: boolean[] = [];
  let inSingle = false;
  let inDouble = false;

  const emit = (s: string, isLiteral: boolean): void => {
    for (const c of s) {
      chars.push(c);
      literal.push(isLiteral);
    }
  };

  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    const next = i + 1 < src.length ? src[i + 1] : "";

    if (ch === "'" && !inDouble) {
      // The quote is a DELIMITER, never content. Marking the closing one as literal swallowed it
      // into the placeholder, leaving `'<ph>` with no closing quote for the concat pattern to see,
      // so `'IE'+'X'` stopped resolving.
      emit(ch, false);
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle) {
      // Inside a double-quoted string, `""` is an escaped literal quote — NOT a token split.
      if (inDouble && next === '"') {
        emit('"', false);
        i++;
        continue;
      }
      inDouble = !inDouble;
      emit(ch, false);
      continue;
    }
    // PowerShell single quotes are literal end to end: no escape inside them means anything.
    if (inSingle) {
      emit(ch, true);
      continue;
    }

    // Line continuation: an escape character immediately before a line break joins the lines.
    if ((ch === "^" && caretOk && !inDouble) || (ch === "`" && backtickOk)) {
      if (next === "\r" || next === "\n") {
        let j = i + 1;
        if (src[j] === "\r" && src[j + 1] === "\n") j += 2;
        else j += 1;
        i = j - 1;
        found.add("continuation");
        continue;
      }
    }

    // cmd.exe caret. Literal inside double quotes; a trailing caret escapes nothing.
    if (ch === "^" && caretOk && !inDouble) {
      if (!next) {
        emit(ch, false);
        continue;
      }
      emit(next, false); // `^^` yields one literal caret, `^x` yields x
      i++;
      found.add("caret");
      continue;
    }

    // PowerShell backtick.
    if (ch === "`" && backtickOk) {
      if (!next) {
        emit(ch, false);
        continue;
      }
      // The control-character escapes mean something only inside a double-quoted string.
      emit(inDouble && PS_ESCAPES[next] !== undefined ? PS_ESCAPES[next] : next, false);
      i++;
      found.add("backtick");
      continue;
    }

    emit(ch, false);
  }

  // ── Passes 2 and 3: concatenation and quote-splitting. ──────────────────────────────────────
  //
  // A `+` or a quote character INSIDE a single-quoted literal is inert — `'"IE"+"X"'` is one
  // string, not a concatenation. But `'IE'+'X'` genuinely IS one, and the `+` there is at the top
  // level. So the distinction is not "is this region quoted" but "is this operator inside a
  // literal", and the way to say that to a regex is to make each literal's CONTENT opaque:
  // substitute a placeholder that contains no quote, plus, or whitespace, rewrite, then restore.
  const parts: string[] = [];
  let masked = "";
  let m = 0;
  while (m < chars.length) {
    if (!literal[m]) {
      masked += chars[m];
      m++;
      continue;
    }
    let end = m;
    while (end < chars.length && literal[end]) end++;
    masked += `${PH_OPEN}${parts.length}${PH_CLOSE}`;
    parts.push(chars.slice(m, end).join(""));
    m = end;
  }

  const rewritten = rewriteUnquoted(masked, found);
  const text = rewritten.replace(PH_RE, (_a, idx: string) => parts[Number(idx)] ?? "");
  return { text, changed: text !== src, tricks: [...found], truncated: false };
}

// Concatenation and quote-splitting, applied to a stretch of text known not to be inside a
// single-quoted literal.
function rewriteUnquoted(run: string, found: Set<ObfuscationTrick>): string {
  let s = run;
  for (let pass = 0; pass < MAX_CONCAT_PASSES; pass++) {
    const joined = s.replace(CONCAT_RE, (m) => {
      const parts = m.match(/(["'])([^"']*)\1/g) ?? [];
      return parts.map((p) => p.slice(1, -1)).join("");
    });
    if (joined === s) break;
    s = joined;
    found.add("concat");
  }
  const spliced = s.replace(QUOTE_SPLIT_RE, "$1$3");
  if (spliced !== s) {
    s = spliced;
    found.add("quote-split");
  }
  return s;
}

/**
 * The strings a matcher should test: the original, plus the de-escaped copy when it differs.
 *
 * Returned SEPARATELY and never joined. Concatenating them — under any separator — lets a rule
 * match the tail of one and the head of the other and report a hit that exists in neither. That
 * is not hypothetical: `\s` matches a newline, and `de^lete harmless vssadmin` graded "strong"
 * credential-dumping under the joined version of this function.
 */
export function commandCandidates(image: string, cmd: string): string[] {
  const raw = `${image} ${cmd}`;
  const n = normalizeCommand(raw, shellFromImage(image));
  return n.changed ? [raw, n.text] : [raw];
}

/** True when `re` matches the original command or its de-escaped reading. */
export function matchesCommand(re: RegExp, image: string, cmd: string): boolean {
  return commandCandidates(image, cmd).some((c) => re.test(c));
}
