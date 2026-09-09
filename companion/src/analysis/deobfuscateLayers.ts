// Layered PowerShell payload decoding (#909 item 2).
//
// deobfuscate.ts peels ONE base64 layer. Real droppers stack them: base64 wrapping gzip wrapping
// base64, a string rebuilt from character codes, a format operator reordering fragments, a
// -replace chain scrubbing filler, a reversed literal. Each is trivial to write and each defeats a
// single-layer decoder completely.
//
// ─────────────────────────── THE RULE THAT SHAPES THIS FILE ───────────────────────────
//
// NEVER EXECUTE THE PAYLOAD, and never use a general-purpose evaluator. This module is a CONSTANT
// FOLDER: it recognises an explicitly enumerated set of expressions whose operands are literals,
// and computes them. `'iXXx' -replace 'XX','e'` folds because both arguments are constants.
// `'iXXx' -replace $a,$b` does not fold and is reported as PARTIAL, because resolving it would
// mean running the script. A decoder that guesses is worse than one that admits it stopped: the
// analyst can read a partial result and know to look further, but cannot un-see a fabricated one.
//
// ─────────────────────────── BOUNDS, BECAUSE THE INPUT IS HOSTILE ───────────────────────────
//
// The text being decoded was written by the attacker whose case this is. Every loop is capped:
// depth, output size, decompression ratio, and wall-clock. A gzip bomb decodes to the ceiling and
// stops, flagged partial — it does not exhaust memory.
//
// `version` is stamped on every result. Improving this decoder does not retroactively improve
// events already decoded and stored, so the version is what lets a later pass find stale results
// and redo them deliberately rather than silently.

import { gunzipSync, inflateSync, inflateRawSync } from "node:zlib";

/** Bump when a transform is added or changed, so stored results can be found and redone. */
export const DECODER_VERSION = 2;

/** How many layers to peel before giving up and reporting the result partial. */
export const MAX_DEPTH = 6;

/** Ceiling on any decoded output. A decompression bomb stops here rather than exhausting memory. */
export const MAX_OUTPUT = 256 * 1024;

/** Ceiling on the input this module will look at. */
export const MAX_INPUT = 128 * 1024;

/** Wall-clock budget for one payload, so a pathological input cannot stall an import. */
const TIME_BUDGET_MS = 250;

export interface DecodeStep {
  method: string; // "powershell-enc" | "base64" | "gzip" | "deflate" | "char-codes" | "format" | "replace" | "reverse"
  detail?: string; // short human note, e.g. how many bytes came out
}

export interface LayeredResult {
  decoded: string; // the innermost text reached
  steps: DecodeStep[]; // the layers peeled, outermost first
  partial: boolean; // a limit was hit, or an unsupported construct remained
  version: number; // DECODER_VERSION at the time of decoding
}

// ─────────────────────────── layer detectors ───────────────────────────

const PS_ENC_RE = /(?:-enc(?:odedcommand)?|-e)\s+([A-Za-z0-9+/]{20,}={0,2})/i;
const FROM_B64_RE = /frombase64string\(\s*["']([A-Za-z0-9+/]{16,}={0,2})["']\s*\)/i;
const GZIP_RE = /gzipstream[^\n]{0,120}?["']([A-Za-z0-9+/]{16,}={0,2})["']/i;
const DEFLATE_RE = /deflatestream[^\n]{0,120}?["']([A-Za-z0-9+/]{16,}={0,2})["']/i;
const BARE_B64_RE = /(?:^|["'`\s]|[=:]\s*)([A-Za-z0-9+/]{40,}={0,2})(?:["'`]|\s|$)/;
// A bare base64 block is only a payload when something nearby intends to RUN it. Without this a
// commit hash, an API key or a certificate in a benign command line decodes to mojibake and is
// reported to the analyst as a recovered payload.
const EXEC_MARKER_RE = /iex\b|invoke-expression|certutil|frombase64string|downloadstring|-enc\b/i;

// `[char]105+[char]101+[char]120`. The `+` is REQUIRED between terms: PowerShell does not
// concatenate two adjacent [char] casts, so folding `[char]65 [char]66` into "AB" would invent text.
const CHAR_CODES_RE = /\[char\]\s*\d{1,7}(?:\s*\+\s*\[char\]\s*\d{1,7})+/i;
// `[char[]](105,101,120) -join ''` — the join is consumed when present, because a bare [char[]] is
// an ARRAY, and rendering it as a string is something only the join does.
const CHAR_ARRAY_RE = /\[char\[\]\]\s*\(\s*((?:\d{1,7}\s*,\s*){1,}\d{1,7})\s*\)(\s*-join\s*(["'])\3)?/i;
// `"{1}{0}" -f 'X','IE'`
const FORMAT_RE = /(["'])((?:\{\d+\}){2,})\1\s*-f\s*((?:\s*["'][^"']*["']\s*,)*\s*["'][^"']*["'])/i;
// `'iXXx' -replace 'XX','e'` — both arguments must be literals AND the pattern must contain no
// regex metacharacter. PowerShell's -replace is REGEX-based and case-insensitive; folding it with a
// literal split/join is only faithful for a pattern that is already literal. `'abc' -replace '.','X'`
// yields "XXX" in PowerShell and would yield "abc" here, so that shape is refused rather than
// guessed — see REPLACE_META_RE.
const REPLACE_RE = /(["'])([^"']*)\1\s*-replace\s*(["'])([^"']*)\3\s*,\s*(["'])([^"']*)\5/i;
const REPLACE_META_RE = /[\\^$.|?*+()[\]{}]/;
// `'xei'[-1..-3] -join ''` — a reversal of a LITERAL, where the range covers the whole string.
// A form indexing a VARIABLE cannot be folded: binding it means tracking assignments, which is
// interpretation, not folding. The old pattern matched `$s='abcd'; $s[-1..-2]` and produced
// `$s=dcba ''`, which is not what PowerShell computes.
const REVERSE_RE = /(["'])([^"']{2,})\1\s*\[\s*-1\s*\.\.\s*-(\d+)\s*\]\s*-join\s*(["'])\4/i;
// A -replace or -f whose operands are variables cannot be folded — see the header.
const NON_CONSTANT_RE = /-replace\s*\$|-f\s*\$|\[char\]\s*\$/i;

function clamp(s: string): { text: string; clipped: boolean } {
  return s.length > MAX_OUTPUT
    ? { text: s.slice(0, MAX_OUTPUT), clipped: true }
    : { text: s, clipped: false };
}

// Decoded bytes are only useful if they are text. Binary noise means we guessed wrong about the
// encoding, and returning it would show the analyst garbage labelled as a recovered payload.
function looksLikeText(s: string): boolean {
  if (!s) return false;
  let printable = 0;
  // Sample ACROSS the string, not just its head. A prefix-only check passes any value whose first
  // 2 KB is ASCII and whose remainder is binary.
  const n = Math.min(s.length, 2048);
  const stride = Math.max(1, Math.floor(s.length / n));
  for (let k = 0; k < n; k++) {
    const c = s.charCodeAt(k * stride);
    // ASCII printable only. Counting the 160-65533 range as "printable" made latin1 mojibake pass:
    // a 64-character hex hash is valid base64, decodes to high-byte noise, and was then reported to
    // the analyst as a recovered payload — while destroying the hash IOC that was really there.
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++;
  }
  return printable / n > 0.85;
}

// Hash and key material is valid base64 by accident: hex digits are a subset of the base64
// alphabet, so a 32/40/64/128-character hex string decodes cleanly to nothing meaningful. Decoding
// one loses the hash IOC and invents a payload, so a pure-hex candidate is never a layer.
function looksLikeHash(s: string): boolean {
  return /^[a-f0-9]+$/i.test(s) && [32, 40, 64, 96, 128].includes(s.length);
}

// Escape a literal so it can be used as a case-insensitive regex without any metacharacter taking
// effect. The pattern is already known to be metacharacter-free; this guards the boundary anyway.
function escapeLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function b64Bytes(s: string): Buffer | null {
  try {
    const buf = Buffer.from(s, "base64");
    return buf.length > 0 ? buf : null;
  } catch {
    return null;
  }
}

function decodeB64Text(s: string, encoding: BufferEncoding): string | null {
  const buf = b64Bytes(s);
  if (!buf) return null;
  const text = buf.subarray(0, MAX_OUTPUT).toString(encoding);
  return looksLikeText(text) ? text : null;
}

// Inflate with a hard output ceiling. zlib's own maxOutputLength throws when exceeded, which is
// exactly the bomb case — so a throw is caught and the truncated prefix is returned as partial.
function inflateBounded(buf: Buffer, kind: "gzip" | "deflate"): { text: string; clipped: boolean } | null {
  // A gzip member ends with ISIZE: the uncompressed length mod 2^32. Reading it first turns a
  // decompression bomb from "allocate until zlib throws" into "decline before starting". The value
  // is attacker-controlled and can lie, so maxOutputLength below is still the real guard — this is
  // only a cheap early exit, and the honest answer for a bomb is to report that it was refused
  // rather than to hand back a plausible-looking fragment.
  if (kind === "gzip" && buf.length >= 4) {
    const isize = buf.readUInt32LE(buf.length - 4);
    if (isize > MAX_OUTPUT) return { text: "", clipped: true };
  }
  const opts = { maxOutputLength: MAX_OUTPUT };
  const attempts = kind === "gzip" ? [gunzipSync] : [inflateSync, inflateRawSync];
  for (const fn of attempts) {
    try {
      const out = fn(buf, opts);
      const text = out.toString("utf8");
      return looksLikeText(text) ? { text, clipped: false } : null;
    } catch (err) {
      // ONLY an output-limit refusal is a bomb. Treating every zlib error as one recorded corrupt
      // data as a successful empty decode, and — worse — stopped the deflate path from ever trying
      // inflateRawSync after inflateSync rejected genuinely raw data.
      if ((err as { code?: string })?.code === "ERR_BUFFER_TOO_LARGE") return { text: "", clipped: true };
      continue; // wrong format for this decoder: try the next one
    }
  }
  return null;
}

// Splice a folded value back into the surrounding text.
//
// Two hazards, both real. `String.replace` interprets `$&`, `` $` ``, `$'` and `$1` inside the
// REPLACEMENT, and the replacement here is attacker-controlled — so a function replacement is used,
// which is not scanned for those tokens. And a fold must not be allowed to outgrow the ceiling
// before clamp() ever runs: `'<2000 A>' -replace '','<2000 B>'` builds four million characters,
// which is how a legal input near MAX_INPUT can request billions and take the process down.
function splice(text: string, match: string, built: string): { text: string; clipped: boolean } | null {
  if (built.length > MAX_OUTPUT) return null;
  const out = text.replace(match, () => built);
  return out.length > MAX_OUTPUT
    ? { text: out.slice(0, MAX_OUTPUT), clipped: true }
    : { text: out, clipped: false };
}

// One layer. Returns the text of the next layer in, or null when nothing here decodes.
//
// `depth` is 0 for the original command line and rises with each layer peeled. It gates the bare
// base64 branch: at the top level a long base64-looking run is usually a hash, a key or a
// certificate, so an execution marker must vouch for it. Once we are INSIDE a decoded payload that
// concern is gone — the text only exists because something encoded it — so the guard lifts.
function peel(text: string, depth: number): { text: string; step: DecodeStep; clipped: boolean } | null {
  let m: RegExpExecArray | null;

  if ((m = PS_ENC_RE.exec(text))) {
    const out = decodeB64Text(m[1], "utf16le") ?? decodeB64Text(m[1], "utf8");
    if (out) {
      const c = clamp(out);
      return {
        text: c.text,
        step: { method: "powershell-enc", detail: `${out.length} chars` },
        clipped: c.clipped,
      };
    }
  }

  if ((m = GZIP_RE.exec(text))) {
    const buf = b64Bytes(m[1]);
    const inf = buf && inflateBounded(buf, "gzip");
    if (inf)
      return {
        text: inf.text,
        step: { method: "gzip", detail: `${inf.text.length} chars` },
        clipped: inf.clipped,
      };
  }

  if ((m = DEFLATE_RE.exec(text))) {
    const buf = b64Bytes(m[1]);
    const inf = buf && inflateBounded(buf, "deflate");
    if (inf)
      return {
        text: inf.text,
        step: { method: "deflate", detail: `${inf.text.length} chars` },
        clipped: inf.clipped,
      };
  }

  if ((m = FROM_B64_RE.exec(text))) {
    const out = decodeB64Text(m[1], "utf8") ?? decodeB64Text(m[1], "utf16le");
    if (out) {
      const c = clamp(out);
      return { text: c.text, step: { method: "base64", detail: `${out.length} chars` }, clipped: c.clipped };
    }
  }

  if ((m = CHAR_ARRAY_RE.exec(text))) {
    const codes = m[1].split(",").map((n) => Number(n.trim()));
    // PowerShell throws on a value outside the char range; String.fromCharCode would silently wrap
    // it modulo 65536 and invent a character. Refuse instead.
    if (codes.every((c) => Number.isInteger(c) && c >= 0 && c <= 0xffff)) {
      const built = codes.map((c) => String.fromCharCode(c)).join("");
      const sp = splice(text, m[0], built);
      if (sp)
        return {
          text: sp.text,
          step: { method: "char-codes", detail: built.slice(0, 40) },
          clipped: sp.clipped,
        };
    }
  }

  if ((m = CHAR_CODES_RE.exec(text))) {
    const codes = [...m[0].matchAll(/\[char\]\s*(\d{1,7})/gi)].map((x) => Number(x[1]));
    if (codes.every((c) => c >= 0 && c <= 0xffff)) {
      const built = codes.map((c) => String.fromCharCode(c)).join("");
      const sp = splice(text, m[0], built);
      if (sp)
        return {
          text: sp.text,
          step: { method: "char-codes", detail: built.slice(0, 40) },
          clipped: sp.clipped,
        };
    }
  }

  if ((m = FORMAT_RE.exec(text))) {
    const args = [...m[3].matchAll(/["']([^"']*)["']/g)].map((x) => x[1]);
    // A double-quoted argument containing $var or $() is not a constant — its value depends on
    // state we do not have. And an out-of-range index is a PowerShell formatting ERROR, not an
    // empty string, so substituting "" would invent a result.
    const constant = args.every((a) => !/\$/.test(a));
    const indexes = [...m[2].matchAll(/\{(\d+)\}/g)].map((x) => Number(x[1]));
    if (constant && indexes.every((i) => i < args.length)) {
      const built = m[2].replace(/\{(\d+)\}/g, (_a, i: string) => args[Number(i)]);
      const sp = splice(text, m[0], built);
      if (sp)
        return { text: sp.text, step: { method: "format", detail: built.slice(0, 40) }, clipped: sp.clipped };
    }
  }

  if ((m = REPLACE_RE.exec(text))) {
    const [src, pattern, replacement] = [m[2], m[4], m[6]];
    // PowerShell's -replace is a REGEX match and is case-INSENSITIVE by default. Folding it with a
    // literal split/join is faithful only when the pattern contains no metacharacter; otherwise the
    // decoder would produce text PowerShell never would. An empty pattern is refused too: it
    // inserts the replacement between every character, which is both wrong and quadratic.
    const foldable =
      pattern.length > 0 &&
      !REPLACE_META_RE.test(pattern) &&
      src.length * Math.max(replacement.length, 1) <= MAX_OUTPUT;
    if (foldable) {
      // Case-insensitive literal replacement, matching PowerShell's default.
      const built = src.split(new RegExp(escapeLiteral(pattern), "gi")).join(replacement);
      const sp = splice(text, m[0], built);
      if (sp)
        return {
          text: sp.text,
          step: { method: "replace", detail: built.slice(0, 40) },
          clipped: sp.clipped,
        };
    }
  }

  if ((m = REVERSE_RE.exec(text))) {
    const literalText = m[2];
    // `[-1..-N]` selects the last N characters in reverse. Only fold when N covers the whole
    // string, because a partial range yields a SUBSTRING and folding it as a full reversal would
    // report characters PowerShell never produced.
    if (Number(m[3]) === literalText.length) {
      const built = [...literalText].reverse().join("");
      const sp = splice(text, m[0], built);
      if (sp)
        return {
          text: sp.text,
          step: { method: "reverse", detail: built.slice(0, 40) },
          clipped: sp.clipped,
        };
    }
  }

  if ((depth > 0 || EXEC_MARKER_RE.test(text)) && (m = BARE_B64_RE.exec(text)) && !looksLikeHash(m[1])) {
    const out = decodeB64Text(m[1], "utf16le") ?? decodeB64Text(m[1], "utf8");
    if (out) {
      // SPLICED IN PLACE, never returned as the whole next layer. Replacing the layer let a base64
      // decoy planted inside a real script discard the script and leave only the decoy's
      // indicators — which the IOC extractor then persisted as the case's evidence.
      const sp = splice(text, m[1], out);
      if (sp)
        return {
          text: sp.text,
          step: { method: "base64", detail: `${out.length} chars` },
          clipped: sp.clipped,
        };
    }
  }

  return null;
}

/**
 * Peel every layer this module supports, outermost first. Returns null when the text carries
 * nothing decodable — which is the common case and must stay cheap.
 */
export function decodeLayers(raw: string): LayeredResult | null {
  const src = typeof raw === "string" ? raw : "";
  if (!src || src.length > MAX_INPUT) return null;

  const started = Date.now();
  const steps: DecodeStep[] = [];
  let current = src;
  let partial = false;

  for (let depth = 0; depth < MAX_DEPTH; depth++) {
    if (Date.now() - started > TIME_BUDGET_MS) {
      partial = true;
      break;
    }
    const next = peel(current, depth);
    if (!next) break;
    steps.push(next.step);
    if (next.clipped) partial = true;
    if (next.text === current) break; // a transform that changed nothing cannot be repeated
    current = next.text;
  }

  if (steps.length === 0) return null;

  // More layers than the cap allows, or an expression whose operands are not constants: say so
  // rather than presenting the half-peeled text as the final answer.
  // Reaching the cap is itself the signal. Peeling once more just to LABEL the result partial ran a
  // seventh transform — the most expensive thing the input can ask for — purely for a boolean.
  if (steps.length >= MAX_DEPTH) partial = true;
  if (NON_CONSTANT_RE.test(current)) partial = true;

  const c = clamp(current);
  return { decoded: c.text, steps, partial: partial || c.clipped, version: DECODER_VERSION };
}
