// #2569 — token-shaped literals that are already in the text an anonymizer masks.
//
// Case text is adversary-controlled. A planted "ANON_HOST_1" must never collide with a token the
// anonymizer mints, or restore() turns the planted string into a real victim value and the AI
// reads two different things as one entity. Every literal found is either:
//   - escaped to "ANON-LITERAL_…" when that exact token was already minted by an earlier apply()
//     call (the same spelling supportLogRedact uses), so it can never read as ours (restore()
//     puts the literal back, #3001); or
//   - returned for the caller to reserve, so assign() skips that number from now on.
// The text is otherwise unchanged.

/** The spelling a literal takes when it equals a token this anonymizer already minted. */
export const ANON_LITERAL_PREFIX = "ANON-LITERAL_";

export interface TokenLiteralScan {
  /** The input with every already-minted literal escaped. */
  readonly text: string;
  /** Upper-case literals that were NOT minted yet — the caller reserves these numbers. */
  readonly literals: readonly string[];
}

/**
 * Scan `text` for token-shaped literals. `tokenSource` is the token regex source (matched
 * case-insensitively); `isMinted` receives the literal in upper case.
 */
export function scanTokenLiterals(
  text: string,
  tokenSource: string,
  isMinted: (upperToken: string) => boolean,
  escapes?: LiteralEscapes,
): TokenLiteralScan {
  const literals: string[] = [];
  escapes?.seen(text);
  const out = text.replace(new RegExp(tokenSource, "gi"), (m) => {
    const upper = m.toUpperCase();
    if (!isMinted(upper)) return (literals.push(upper), m);
    const escaped = ANON_LITERAL_PREFIX + m.slice("ANON_".length);
    escapes?.record(escaped, m);
    return escaped;
  });
  return { text: out, literals };
}

// #3001 — restore() undoes the escapes above, so a planted literal comes back as itself. Only the
// exact spellings this anonymizer produced, each mapped to its original literal (case kept: the
// escape drops the "anon_" prefix's case). Never undone: a spelling that was already in an input
// (it may be a real string), or one two different literals escaped to (ambiguous). Both stay marked.
// Restore is then NOT idempotent: restored text holds the literal while its token is minted, so a
// second restore would turn it into the real value (#2569). Callers restore once.
export interface LiteralEscapes {
  /** Every escaped spelling already in an apply() input: never undone. */
  seen(input: string): void;
  /** `escaped` is the spelling `original` took on the way out. */
  record(escaped: string, original: string): void;
  /** `text` with tokens replaced by `real(token)` and this anonymizer's escapes undone, in one pass. */
  restore(text: string, readers: TokenReaders, real: (upperToken: string) => string | undefined): string;
}

/** The per-anonymizer escape log. `tokenSource` starts with "ANON_", as the token regex does. */
export function literalEscapes(tokenSource: string): LiteralEscapes {
  if (!tokenSource.startsWith("ANON_")) throw new Error("token source must start with ANON_");
  const source = ANON_LITERAL_PREFIX + tokenSource.slice("ANON_".length);
  const undo = new Map<string, string | null>(); // escaped spelling -> original; null: never undone
  const unescape = (s: string) => s.replace(new RegExp(source, "gi"), (m) => undo.get(m) ?? m);
  return {
    seen: (input) => {
      for (const m of input.match(new RegExp(source, "gi")) ?? []) undo.set(m, null);
    },
    record: (escaped, original) => {
      const was = undo.get(escaped);
      undo.set(escaped, was === undefined || was === original ? original : null);
    },
    restore: (text, readers, real) => {
      if (undo.size === 0) return readers.replace(text, real);
      // A later pass can swallow an escape into a value (an email around it): undo it there too.
      const tokens = (s: string) =>
        readers.replace(s, (tok) => {
          const value = real(tok);
          return value === undefined ? undefined : unescape(value);
        });
      // Split on escaped spellings first, so an undone literal is never read again as a token.
      let out = "";
      let at = 0;
      for (const m of text.matchAll(new RegExp(source, "gi"))) {
        out += tokens(text.slice(at, m.index)) + (undo.get(m[0]) ?? m[0]);
        at = m.index + m[0].length;
      }
      return out + tokens(text.slice(at));
    },
  };
}

// #2992 — a token glued to a digit read back as another token: "ANON_IP_1" + "0" is "ANON_IP_10".
// A minted token right before a digit is followed by this delimiter; restore() consumes exactly one
// after a token it minted. Inserted when the next text is delimiters then a digit, so one already
// in the input after a token survives the round trip (byte stuffing). Visible, rare after a value.
export const TOKEN_DELIMITER = "\u00B7";
const DELIMITER_THEN_DIGIT = `${TOKEN_DELIMITER}*[0-9]`;
const DELIMITED = new RegExp(`${TOKEN_DELIMITER}(?=${DELIMITER_THEN_DIGIT})`, "y");
const NEEDS_DELIMITER = new RegExp(DELIMITER_THEN_DIGIT, "y");
// After a site's match: a digit, or an IPv6 placeholder whose plain return may start with one.
const MAY_GLUE = /[0-9\uE000]/;
const LAST_TOKEN = /ANON_([A-Z]+)_(\d+)$/;
const LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/** 1 when text[at] is a delimiter this module would have inserted (followed by delimiters + digit). */
export function delimiterAt(text: string, at: number): number {
  DELIMITED.lastIndex = at;
  return DELIMITED.test(text) ? 1 : 0;
}

/** `tokenSource` plus the optional delimiter it consumes — the reader form of a minted token. */
function delimitedTokenSource(tokenSource: string): string {
  return `(?:${tokenSource})(?:${TOKEN_DELIMITER}(?=${DELIMITER_THEN_DIGIT}))?`;
}

export interface TokenReaders {
  /** Every token (with the delimiter it owns) replaced by `fn(upper token)`; undefined keeps it. */
  replace(text: string, fn: (upperToken: string) => string | undefined): string;
  /** True when the whole string is one token, with its delimiter and the digits after it. */
  isToken(s: string): boolean;
}

/** The readers of minted tokens: each consumes the delimiter a token owns. Fresh regexes per call. */
export function tokenReaders(tokenSource: string): TokenReaders {
  const source = delimitedTokenSource(tokenSource);
  return {
    replace: (text, fn) =>
      text.replace(new RegExp(source, "gi"), (m) => fn(m.replace(TOKEN_DELIMITER, "").toUpperCase()) ?? m),
    isToken: (s) => new RegExp(`^${source}[0-9]*$`, "i").test(s.trim()),
  };
}

/** A character absent from `text`, so the input can never forge it. "" when none is free. */
function absentChar(text: string): string {
  for (let c = 0xe002; c <= 0xf8ff; c++) {
    const ch = String.fromCharCode(c);
    if (!text.includes(ch)) return ch;
  }
  return "";
}

export interface TokenEnds {
  /** A new apply() call on `text`, with the anonymizer's token -> value map. */
  start(text: string, toReal: ReadonlyMap<string, string>): void;
  /** A site's splice of text[at, end) as `result` (`value` when nothing was minted). */
  ended(result: string, value: string, at: number, end: number, text: string): string;
  /** The final text; a value a later pass swallowed an alias into gets the token's real text. */
  finish(text: string, toReal: Map<string, string>): string;
}

/**
 * The per-anonymizer state for the sites that can splice a token before a digit. Such a token is
 * spliced as an ALIAS of the same shape (same length, letters for letters, the same number), so every
 * later pass reads exactly the text it read before; any mark between the token and the digit would
 * give those passes a boundary they never had. finish() puts the token back with the delimiter.
 * One mark, before an address returned as it is that starts with a digit right after a token, is
 * safe: an address opens with at most four hex digits and a colon, so no later pass starts there,
 * and none starts inside a token's number.
 */
export function tokenEnds(tokenSource: string, categories: readonly string[]): TokenEnds {
  let mark = "";
  let aliases = new Map<string, string>(); // alias -> token
  let input = "";
  let known: ReadonlyMap<string, string> = new Map();
  let before = 0; // toReal entries older than this call: never rewritten
  const taken = new Set(categories);
  // An alias spelling found nowhere: not in the text, this call's input, or any stored value.
  const free = (code: string, text: string) =>
    !taken.has(code) && ![text, input, ...known.values()].some((t) => t.includes(`ANON_${code}_`));
  function alias(token: string, letters: number, text: string): string | null {
    for (let k = aliases.size; k < aliases.size + 4096; k++) {
      let code = "";
      for (let n = k, i = 0; i < letters; i++, n = Math.floor(n / 26)) code = LETTERS[n % 26] + code;
      const a = token.replace(LAST_TOKEN, `ANON_${code}_$2`);
      if (aliases.has(a) || !free(code, text)) continue;
      aliases.set(a, token);
      return a;
    }
    return null;
  }
  return {
    start: (text, toReal) => {
      mark = absentChar(text);
      aliases = new Map();
      input = text;
      known = toReal;
      before = toReal.size;
    },
    ended: (result, value, at, end, text) => {
      const after = /^[0-9]/.test(result) && LAST_TOKEN.test(text.slice(Math.max(0, at - 64), at));
      const head = after ? mark : "";
      const last = result !== value && MAY_GLUE.test(text[end] ?? "") ? LAST_TOKEN.exec(result) : null;
      const token = last ? last[0] : "";
      const swapped = last ? alias(token, last[1].length, text) : null;
      return head + (swapped ? result.slice(0, -token.length) + swapped : result);
    },
    finish: (text, toReal) => {
      const names = [...aliases.keys()].sort((a, b) => b.length - a.length);
      const source = [...names, tokenSource].join("|");
      const out = text.replace(
        new RegExp(`(${source})${mark && `${mark}?`}`, "gi"),
        (m, tok: string, at: number, w: string) => {
          const token = aliases.get(tok) ?? (toReal.has(tok.toUpperCase()) ? tok : null);
          if (token === null) return m;
          NEEDS_DELIMITER.lastIndex = at + m.length;
          return NEEDS_DELIMITER.test(w) ? token + TOKEN_DELIMITER : token;
        },
      );
      for (const [tok, value] of [...toReal].slice(before))
        for (const [a, t] of aliases)
          if (value.includes(a)) toReal.set(tok, value.replaceAll(a, toReal.get(t) ?? t)); // #2991
      return mark ? out.replaceAll(mark, "") : out;
    },
  };
}

/**
 * #2991 — put back the real text of every token `lookup` knows in `value`. A later pass (account,
 * email, host, …) can match text that already holds a token an earlier pass minted; the new token
 * must stand for the original text, or restore() hands back a token. Exact case only: a literal in
 * the input never equals a minted token (escaped or reserved above). Own regex, no shared state.
 */
export function expandMintedTokens(
  value: string,
  tokenSource: string,
  lookup: (token: string) => string | undefined,
): string {
  if (!value.includes("ANON_")) return value;
  return value.replace(new RegExp(tokenSource, "g"), (m) => lookup(m) ?? m);
}

/**
 * #3058 — the spelling of an expanded value as the call's input wrote it. A token stands for one
 * spelling of a case-folded value, so a value built around it (`LAB\<user>-<token>`) expanded to
 * the saved spelling, not the text it replaced, and restore() changed the case. `spell` keeps the
 * expansion when the input holds it verbatim, else takes the one spelling of it the input holds;
 * with none, or more than one, the expansion stays. Set the input with `start` once per call.
 * `expand` is expandMintedTokens, then `spell`.
 */
export interface InputSpelling {
  start: (input: string) => string;
  spell: (raw: string, real: string) => string;
  expand: (raw: string, lookup: (token: string) => string | undefined) => string;
}
export function createInputSpelling(tokenSource: string): InputSpelling {
  let input = "";
  let lower: string | null = null;
  const seen = new Map<string, string>(); // per call: one value is spelled once
  function start(text: string): string {
    input = text;
    lower = null;
    seen.clear();
    return text;
  }
  function spell(raw: string, real: string): string {
    if (raw === real || real.length === 0) return real;
    const known = seen.get(real);
    if (known !== undefined) return known;
    const out = spelled(real);
    seen.set(real, out);
    return out;
  }
  function spelled(real: string): string {
    if (input.includes(real)) return real;
    lower ??= input.toLowerCase();
    const want = real.toLowerCase();
    if (lower.length !== input.length || want.length !== real.length) return real; // folding moved offsets
    const found = new Set<string>();
    for (let at = lower.indexOf(want); at >= 0 && found.size < 2; at = lower.indexOf(want, at + 1))
      found.add(input.slice(at, at + want.length));
    return found.size === 1 ? [...found][0] : real;
  }
  const expand = (raw: string, lookup: (token: string) => string | undefined): string =>
    spell(raw, expandMintedTokens(raw, tokenSource, lookup));
  return { start, spell, expand };
}
