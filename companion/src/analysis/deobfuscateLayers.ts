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

// `[char]105+[char]101+[char]120`
const CHAR_CODES_RE = /(?:\[char\]\s*(\d{1,7})\s*\+?\s*){2,}/i;
// `[char[]](105,101,120)`
const CHAR_ARRAY_RE = /\[char\[\]\]\s*\(\s*((?:\d{1,7}\s*,\s*){1,}\d{1,7})\s*\)/i;
// `"{1}{0}" -f 'X','IE'`
const FORMAT_RE = /(["'])((?:\{\d+\}){2,})\1\s*-f\s*((?:\s*["'][^"']*["']\s*,)*\s*["'][^"']*["'])/i;
// `'iXXx' -replace 'XX','e'` — both arguments must be literals.
const REPLACE_RE = /(["'])([^"']*)\1\s*-replace\s*(["'])([^"']*)\3\s*,\s*(["'])([^"']*)\5/i;
// `$s='xei'; $s[-1..-3] -join ''`
const REVERSE_RE = /(["'])([^"']{2,})\1\s*;?\s*\$?\w*\s*\[\s*-1\s*\.\.\s*-\s*\d+\s*\]\s*-join/i;
// A -replace or -f whose operands are variables cannot be folded — see the header.
const NON_CONSTANT_RE = /-replace\s*\$|-f\s*\$|\[char\]\s*\$/i;

function clamp(s: string): { text: string; clipped: boolean } {
  return s.length > MAX_OUTPUT ? { text: s.slice(0, MAX_OUTPUT), clipped: true } : { text: s, clipped: false };
}

// Decoded bytes are only useful if they are text. Binary noise means we guessed wrong about the
// encoding, and returning it would show the analyst garbage labelled as a recovered payload.
function looksLikeText(s: string): boolean {
  if (!s) return false;
  let printable = 0;
  const n = Math.min(s.length, 2048);
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
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
    } catch {
      // zlib refused to allocate past the ceiling. That IS the bomb case: say so, do not guess.
      return { text: "", clipped: true };
    }
  }
  return null;
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
      return { text: c.text, step: { method: "powershell-enc", detail: `${out.length} chars` }, clipped: c.clipped };
    }
  }

  if ((m = GZIP_RE.exec(text))) {
    const buf = b64Bytes(m[1]);
    const inf = buf && inflateBounded(buf, "gzip");
    if (inf) return { text: inf.text, step: { method: "gzip", detail: `${inf.text.length} chars` }, clipped: inf.clipped };
  }

  if ((m = DEFLATE_RE.exec(text))) {
    const buf = b64Bytes(m[1]);
    const inf = buf && inflateBounded(buf, "deflate");
    if (inf) return { text: inf.text, step: { method: "deflate", detail: `${inf.text.length} chars` }, clipped: inf.clipped };
  }

  if ((m = FROM_B64_RE.exec(text))) {
    const out = decodeB64Text(m[1], "utf8") ?? decodeB64Text(m[1], "utf16le");
    if (out) {
      const c = clamp(out);
      return { text: c.text, step: { method: "base64", detail: `${out.length} chars` }, clipped: c.clipped };
    }
  }

  if ((m = CHAR_ARRAY_RE.exec(text))) {
    const built = m[1]
      .split(",")
      .map((n) => String.fromCharCode(Number(n.trim())))
      .join("");
    return { text: text.replace(m[0], built), step: { method: "char-codes", detail: built.slice(0, 40) }, clipped: false };
  }

  if (CHAR_CODES_RE.test(text)) {
    const span = CHAR_CODES_RE.exec(text);
    if (span) {
      const codes = [...span[0].matchAll(/\[char\]\s*(\d{1,7})/gi)].map((x) => Number(x[1]));
      const built = codes.map((c) => String.fromCharCode(c)).join("");
      return { text: text.replace(span[0], built), step: { method: "char-codes", detail: built.slice(0, 40) }, clipped: false };
    }
  }

  if ((m = FORMAT_RE.exec(text))) {
    const args = [...m[3].matchAll(/["']([^"']*)["']/g)].map((x) => x[1]);
    const built = m[2].replace(/\{(\d+)\}/g, (_a, i: string) => args[Number(i)] ?? "");
    return { text: text.replace(m[0], built), step: { method: "format", detail: built.slice(0, 40) }, clipped: false };
  }

  if ((m = REPLACE_RE.exec(text))) {
    // A literal replacement, applied literally — no regex compilation of attacker-supplied text.
    const built = m[2].split(m[4]).join(m[6]);
    return { text: text.replace(m[0], built), step: { method: "replace", detail: built.slice(0, 40) }, clipped: false };
  }

  if ((m = REVERSE_RE.exec(text))) {
    const built = [...m[2]].reverse().join("");
    return { text: text.replace(m[0], built), step: { method: "reverse", detail: built.slice(0, 40) }, clipped: false };
  }

  if ((depth > 0 || EXEC_MARKER_RE.test(text)) && (m = BARE_B64_RE.exec(text)) && !looksLikeHash(m[1])) {
    const out = decodeB64Text(m[1], "utf16le") ?? decodeB64Text(m[1], "utf8");
    if (out) {
      const c = clamp(out);
      return { text: c.text, step: { method: "base64", detail: `${out.length} chars` }, clipped: c.clipped };
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
  if (steps.length >= MAX_DEPTH && peel(current, steps.length)) partial = true;
  if (NON_CONSTANT_RE.test(current)) partial = true;

  const c = clamp(current);
  return { decoded: c.text, steps, partial: partial || c.clipped, version: DECODER_VERSION };
}
