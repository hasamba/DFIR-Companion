// ReDoS safety check for USER-AUTHORED regex patterns (the declarative importer's `match` rules,
// which arrive over POST /importers and are persisted to disk).
//
// A substring heuristic can't do this job: `(a+)+` and `((a+))+` are the same danger, and a pattern
// that spots one misses the other. So parse the source into a small AST and decide on STRUCTURE —
// equivalent shapes then get treated equivalently no matter how they're spelled.
//
// Catastrophic backtracking needs an AMBIGUOUS LOOP: a repetition whose body can match the same
// input more than one way, so a failing suffix forces the engine to retry every possible split.
// Three forms are rejected:
//   * a repetition whose body holds another variable-length repetition — star height >= 2
//     ((a+)+, ((a*))+, (a{1,3})+, (a?){20})
//   * a repetition over alternatives that can begin with the same character ((a|a)+, (\w|\d)+);
//     branches that can't collide, like (foo|bar)+, stay allowed
//   * two adjacent repetitions competing for the same characters (.*.*, \w*\d*)
// Bounded repeats are only judged once the count is big enough for the path explosion to matter, so
// ordinary shapes like (\d{1,3}\.){3} pass while (a?){20}a{20} does not.
//
// Deliberately conservative — some safe patterns are refused. That trade is intentional: a refusal
// surfaces as a validation error the analyst can read and rewrite, while a miss hangs the server on
// every subsequent detect() call.

export interface RegexSafetyResult {
  ok: boolean;
  /** Human-readable rejection reason, suitable for a validation error. Absent when ok. */
  reason?: string;
}

// A pattern this long is not a filename/field discriminator; it's an attack or a mistake.
const MAX_PATTERN_LEN = 512;
// A bounded repeat only multiplies backtracking paths once the count is non-trivial. 8 keeps
// everyday shapes like (\d{1,3}\.){3} and still catches (a?){20}.
const SAFE_BOUNDED_REPEAT = 8;

// ── Character sets ────────────────────────────────────────────────────────────────────────────
// Only ever asked "can these two overlap?", so an approximation is fine as long as it errs toward
// "yes" — `any` and negated sets are treated as overlapping everything.
type CharSet =
  { any: true } | { any: false; negated: boolean; chars: Set<string>; ranges: [number, number][] };

const ANY: CharSet = { any: true };
const EMPTY: CharSet = { any: false, negated: false, chars: new Set(), ranges: [] };

function literal(c: string): CharSet {
  return { any: false, negated: false, chars: new Set([c]), ranges: [] };
}

// \d \w \s (and their negations) as explicit sets; negated forms widen to `any` (conservative).
function shorthand(c: string): CharSet | null {
  switch (c) {
    case "d":
      return { any: false, negated: false, chars: new Set(), ranges: [[48, 57]] };
    case "w":
      return {
        any: false,
        negated: false,
        chars: new Set(["_"]),
        ranges: [
          [48, 57],
          [65, 90],
          [97, 122],
        ],
      };
    case "s":
      return { any: false, negated: false, chars: new Set([" ", "\t", "\n", "\r", "\f", "\v"]), ranges: [] };
    case "D":
    case "W":
    case "S":
      return ANY;
    default:
      return null;
  }
}

function inSet(s: Extract<CharSet, { any: false }>, ch: string): boolean {
  if (s.chars.has(ch)) return true;
  const cp = ch.codePointAt(0) ?? -1;
  return s.ranges.some(([lo, hi]) => cp >= lo && cp <= hi);
}

/**
 * The set as the `i` flag sees it: every letter stands for both of its cases.
 *
 * Without this, `^(a|A)+b$` reads as two alternatives that cannot start with the same character —
 * true of the SOURCE, false of the regex that actually runs. Under `i` the two branches are the
 * same branch twice, which is textbook exponential backtracking. Measured at 26 characters of
 * input: 0ms without the flag, 4831ms with it.
 *
 * ASCII letters only. A missed non-ASCII fold means a missed rejection rather than a wrong one,
 * which is the safe direction for a checker whose other approximations already err toward "these
 * overlap".
 */
function foldCase(s: CharSet): CharSet {
  if (s.any || s.negated) return s; // already overlaps everything
  const chars = new Set<string>();
  for (const c of s.chars) {
    chars.add(c.toLowerCase());
    chars.add(c.toUpperCase());
  }
  const ranges: [number, number][] = [...s.ranges];
  for (const [lo, hi] of s.ranges) {
    const lower: [number, number] = [Math.max(lo, 0x61), Math.min(hi, 0x7a)]; // a-z
    if (lower[0] <= lower[1]) ranges.push([lower[0] - 32, lower[1] - 32]);
    const upper: [number, number] = [Math.max(lo, 0x41), Math.min(hi, 0x5a)]; // A-Z
    if (upper[0] <= upper[1]) ranges.push([upper[0] + 32, upper[1] + 32]);
  }
  return { any: false, negated: false, chars, ranges };
}

function overlaps(a: CharSet, b: CharSet, ignoreCase: boolean): boolean {
  if (a.any || b.any) return true;
  if (a.negated || b.negated) return true; // complement arithmetic isn't worth it
  // foldCase returns the same object for any/negated sets, both already handled above, so these
  // two are always the narrow shape inSet() needs.
  const x = ignoreCase ? foldCase(a) : a;
  const y = ignoreCase ? foldCase(b) : b;
  if (x.any || y.any || x.negated || y.negated) return true;
  for (const c of x.chars) if (inSet(y, c)) return true;
  for (const c of y.chars) if (inSet(x, c)) return true;
  return x.ranges.some(([lo, hi]) => y.ranges.some(([lo2, hi2]) => lo <= hi2 && lo2 <= hi));
}

function union(sets: CharSet[]): CharSet {
  if (sets.some((s) => s.any || s.negated)) return ANY;
  const chars = new Set<string>();
  const ranges: [number, number][] = [];
  for (const s of sets) {
    if (s.any) continue;
    for (const c of s.chars) chars.add(c);
    ranges.push(...s.ranges);
  }
  return { any: false, negated: false, chars, ranges };
}

// ── AST ───────────────────────────────────────────────────────────────────────────────────────
type Atom =
  | { k: "char"; set: CharSet }
  | { k: "group"; alts: Term[][]; assertion: boolean }
  | { k: "backref" }
  | { k: "zero" }; // ^ $ \b \B — no width

interface Term {
  atom: Atom;
  min: number;
  max: number;
} // max === Infinity for * + {n,}

// A hand-rolled parser rather than a library: this runs on untrusted input at request time, needs
// no dependency, and only has to be accurate enough to locate quantifiers, groups and first-sets.
class Parser {
  private i = 0;
  constructor(private readonly s: string) {}

  parse(): Term[][] {
    const alts = this.alternation();
    if (this.i < this.s.length) throw new Error(`unexpected "${this.s[this.i]}"`);
    return alts;
  }

  private alternation(): Term[][] {
    const alts: Term[][] = [this.sequence()];
    while (this.s[this.i] === "|") {
      this.i++;
      alts.push(this.sequence());
    }
    return alts;
  }

  private sequence(): Term[] {
    const terms: Term[] = [];
    while (this.i < this.s.length && this.s[this.i] !== "|" && this.s[this.i] !== ")")
      terms.push(this.term());
    return terms;
  }

  private term(): Term {
    const atom = this.atom();
    const { min, max } = this.quantifier();
    return { atom, min, max };
  }

  private quantifier(): { min: number; max: number } {
    const c = this.s[this.i];
    let min = 1;
    let max = 1;
    if (c === "*") {
      this.i++;
      min = 0;
      max = Infinity;
    } else if (c === "+") {
      this.i++;
      min = 1;
      max = Infinity;
    } else if (c === "?") {
      this.i++;
      min = 0;
      max = 1;
    } else if (c === "{") {
      const m = /^\{(\d+)(,(\d*))?\}/.exec(this.s.slice(this.i));
      if (!m) return { min, max }; // a literal "{" — legal in JS regex
      this.i += m[0].length;
      min = Number(m[1]);
      max = m[2] === undefined ? min : m[3] ? Number(m[3]) : Infinity;
    } else return { min, max };
    if (this.s[this.i] === "?") this.i++; // lazy — still backtracks catastrophically
    return { min, max };
  }

  private atom(): Atom {
    const c = this.s[this.i];
    if (c === "(") return this.group();
    if (c === "[") return { k: "char", set: this.charClass() };
    if (c === ".") {
      this.i++;
      return { k: "char", set: ANY };
    }
    if (c === "^" || c === "$") {
      this.i++;
      return { k: "zero" };
    }
    if (c === "\\") return this.escape();
    if (c === "*" || c === "+" || c === "?") throw new Error("nothing to repeat");
    this.i++;
    return { k: "char", set: literal(c) };
  }

  private group(): Atom {
    this.i++; // "("
    let assertion = false;
    if (this.s[this.i] === "?") {
      const rest = this.s.slice(this.i);
      if (/^\?[:=!]/.test(rest)) {
        assertion = rest[1] !== ":";
        this.i += 2;
      } else if (/^\?<[=!]/.test(rest)) {
        assertion = true;
        this.i += 3;
      } else {
        const m = /^\?<[A-Za-z_$][\w$]*>/.exec(rest); // named capture
        if (!m) throw new Error("unsupported group");
        this.i += m[0].length;
      }
    }
    const alts = this.alternation();
    if (this.s[this.i] !== ")") throw new Error("unbalanced (");
    this.i++;
    return { k: "group", alts, assertion };
  }

  private charClass(): CharSet {
    this.i++; // "["
    const negated = this.s[this.i] === "^";
    if (negated) this.i++;
    const chars = new Set<string>();
    const ranges: [number, number][] = [];
    let widened = false;
    let first = true;
    while (this.i < this.s.length && (this.s[this.i] !== "]" || first)) {
      first = false;
      const lo = this.classMember();
      if (lo === null) {
        widened = true;
        continue;
      } // a shorthand class inside [] — widen
      if (this.s[this.i] === "-" && this.s[this.i + 1] !== undefined && this.s[this.i + 1] !== "]") {
        this.i++;
        const hi = this.classMember();
        if (hi === null) {
          widened = true;
          continue;
        }
        ranges.push([lo.codePointAt(0) ?? 0, hi.codePointAt(0) ?? 0]);
      } else chars.add(lo);
    }
    if (this.s[this.i] !== "]") throw new Error("unbalanced [");
    this.i++;
    if (widened) return ANY;
    return { any: false, negated, chars, ranges };
  }

  // One literal char inside a class; null when it's a \d/\w/\s shorthand (no single code point).
  private classMember(): string | null {
    if (this.s[this.i] !== "\\") return this.s[this.i++] ?? "";
    this.i++;
    const c = this.s[this.i];
    if (c === undefined) throw new Error("trailing backslash");
    this.i++;
    if (shorthand(c)) return null;
    return this.escapedChar(c);
  }

  private escape(): Atom {
    this.i++; // "\"
    const c = this.s[this.i];
    if (c === undefined) throw new Error("trailing backslash");
    this.i++;
    if (c === "b" || c === "B") return { k: "zero" };
    if (/[1-9]/.test(c) || c === "k") {
      while (/[\d<>\w]/.test(this.s[this.i] ?? "")) this.i++;
      return { k: "backref" };
    }
    const sh = shorthand(c);
    if (sh) return { k: "char", set: sh };
    if (c === "p" || c === "P") {
      while (this.i < this.s.length && this.s[this.i++] !== "}");
      return { k: "char", set: ANY };
    }
    return { k: "char", set: literal(this.escapedChar(c)) };
  }

  // Decode the escapes that denote a single code point; consumes any trailing hex digits.
  private escapedChar(c: string): string {
    switch (c) {
      case "n":
        return "\n";
      case "t":
        return "\t";
      case "r":
        return "\r";
      case "f":
        return "\f";
      case "v":
        return "\v";
      case "0":
        return "\0";
      case "c": {
        this.i++;
        return "\0";
      } // control escape — exact value irrelevant
      case "x": {
        const h = this.s.slice(this.i, this.i + 2);
        this.i += 2;
        return String.fromCharCode(parseInt(h, 16) || 0);
      }
      case "u": {
        if (this.s[this.i] === "{") {
          const end = this.s.indexOf("}", this.i);
          if (end < 0) throw new Error("bad \\u{}");
          const cp = parseInt(this.s.slice(this.i + 1, end), 16) || 0;
          this.i = end + 1;
          return String.fromCodePoint(cp);
        }
        const h = this.s.slice(this.i, this.i + 4);
        this.i += 4;
        return String.fromCharCode(parseInt(h, 16) || 0);
      }
      default:
        return c; // \. \+ \\ … — the literal character
    }
  }
}

// ── Analysis ──────────────────────────────────────────────────────────────────────────────────

// Characters a sequence can begin with. Zero-width atoms and skippable (min === 0) terms are
// stepped over, since the next term can then be the one that actually consumes.
function firstSet(seq: Term[]): CharSet {
  const parts: CharSet[] = [];
  for (const t of seq) {
    if (t.atom.k === "zero") continue;
    if (t.atom.k === "group" && t.atom.assertion) continue;
    parts.push(atomSet(t.atom));
    if (t.min > 0) break; // consumes at least once — stop widening
  }
  return union(parts);
}

function atomSet(atom: Atom): CharSet {
  switch (atom.k) {
    case "char":
      return atom.set;
    case "group":
      return union(atom.alts.map(firstSet));
    case "backref":
      return ANY;
    case "zero":
      return EMPTY;
  }
}

// Why this atom is ambiguous as a loop body — i.e. why it can match one string in several ways.
// null when it looks unambiguous.
function ambiguity(atom: Atom, ignoreCase: boolean): string | null {
  if (atom.k === "backref") return "a repetition whose body contains a backreference";
  if (atom.k !== "group") return null; // a bare char/class body is unambiguous

  for (const seq of atom.alts) {
    for (const t of seq) {
      if (t.min !== t.max) return "a repetition whose body contains another variable-length repetition";
      const nested = ambiguity(t.atom, ignoreCase);
      if (nested) return nested;
    }
  }
  if (atom.alts.length > 1) {
    const firsts = atom.alts.map(firstSet);
    for (let i = 0; i < firsts.length; i++) {
      for (let j = i + 1; j < firsts.length; j++) {
        if (overlaps(firsts[i], firsts[j], ignoreCase))
          return "a repetition over alternatives that can start with the same character";
      }
    }
  }
  return null;
}

const isLoop = (t: Term): boolean => t.max > SAFE_BOUNDED_REPEAT;

function scan(alts: Term[][], ignoreCase: boolean): string | null {
  for (const seq of alts) {
    let prevLoop: Term | null = null;
    for (const t of seq) {
      if (isLoop(t)) {
        const why = ambiguity(t.atom, ignoreCase);
        if (why) return why;
        // Two loops side by side split the same run of characters — .*.* and \w*\d* are quadratic.
        if (prevLoop && overlaps(atomSet(prevLoop.atom), atomSet(t.atom), ignoreCase)) {
          return "two adjacent repetitions that match the same characters";
        }
      }
      if (t.atom.k === "zero") continue; // an anchor doesn't separate two loops
      prevLoop = isLoop(t) ? t : null;
      if (t.atom.k === "group") {
        const nested = scan(t.atom.alts, ignoreCase);
        if (nested) return nested;
      }
    }
  }
  return null;
}

/**
 * Decide whether a user-supplied regex source is safe to run against untrusted input.
 * Rejects invalid syntax too, so callers get one verdict for "won't compile" and "will hang".
 *
 * PASS THE FLAGS THE PATTERN WILL ACTUALLY RUN WITH. Ambiguity is a property of the compiled
 * regex, not of its source text: `^(a|A)+b$` has two distinct branches as written and one branch
 * twice under `i`. Callers that hard-code a flag when they match — the IOC whitelist and exclude
 * lists both use `new RegExp(pattern, "i")` — must say so here, or the check answers a question
 * about a regex nobody runs.
 */
export function checkRegexSafety(src: string, flags = ""): RegexSafetyResult {
  const ignoreCase = flags.includes("i");
  if (src.length > MAX_PATTERN_LEN) {
    return { ok: false, reason: `pattern is too long (${src.length} chars, max ${MAX_PATTERN_LEN})` };
  }
  try {
    new RegExp(src, flags);
  } catch (err) {
    return { ok: false, reason: `not a valid regular expression: ${(err as Error).message}` };
  }

  let alts: Term[][];
  try {
    alts = new Parser(src).parse();
  } catch {
    // Compiles but this checker can't model it — refuse rather than run something unanalysed.
    return { ok: false, reason: "pattern uses constructs this ReDoS check cannot verify" };
  }

  const why = scan(alts, ignoreCase);
  if (why) return { ok: false, reason: `${why} — rewrite it to avoid catastrophic backtracking (ReDoS)` };
  return { ok: true };
}
