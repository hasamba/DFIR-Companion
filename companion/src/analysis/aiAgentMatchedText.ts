// What a YARA hit's "Matched text" shows (#2912).
//
// The run used to build it with `format(format="%.200s", args=[String.Data])`. String.Data is a byte
// array, Velociraptor spreads it into one argument per byte, and Go formatting printed debris:
// `%!s(uint8=000…105)%!(EXTRA uint8=103, uint8=110, …)` — the first byte zero-padded to width 200,
// then the rest. Reproduced on Velociraptor 0.75.6.
//
// New runs send the bytes as hex (`MatchedHex`, at most 200 bytes) plus the full match length, so the
// value is exact and unambiguous. Rows from older runs are decoded from the debris, using complete
// tokens only. Either way the order is: bytes → text → redact secrets in the PLAIN text → escape
// invisible characters for display. Redacting after escaping would let `password=\"…\"` slip past.
import { AI_AGENT_SNIPPET_MAX, redactSnippetText } from "./aiAgentRows.js";

export interface MatchedBytes {
  bytes: number[];
  /** The match was longer than the bytes here (a capped source, or a cut-off older row). */
  partial: boolean;
}

/** Hex from the run → bytes. Undefined on anything that is not whole hex. */
export function hexToBytes(hex: string): number[] | undefined {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) return undefined;
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

const DEBRIS_HEAD = /^%!s\(uint8=(\d+)\)/;
const EXTRA = "%!(EXTRA ";
const TOKEN = /^uint8=(\d{1,3})(, |\))/;
// The start of one more token, cut off by the row's length cap.
const CUT_TOKEN = /^(u(i(n(t(8(=\d{0,3},?)?)?)?)?)?)?$/;

/**
 * The byte list inside an older run's formatting debris. Strict: a value over 255 or text that does
 * not follow the grammar voids it (undefined). A token the row's length cap cut off mid-way is
 * dropped, never read as a different byte, and the result is marked partial.
 */
export function legacyDebrisToBytes(text: string): MatchedBytes | undefined {
  const head = DEBRIS_HEAD.exec(text);
  if (!head) return undefined;
  const first = Number(head[1]);
  if (!Number.isSafeInteger(first) || first > 255) return undefined;
  const bytes = [first];
  let rest = text.slice(head[0].length);
  if (rest === "") return { bytes, partial: false };
  if (!rest.startsWith(EXTRA)) return EXTRA.startsWith(rest) ? { bytes, partial: true } : undefined;
  rest = rest.slice(EXTRA.length);
  for (;;) {
    const m = TOKEN.exec(rest);
    if (!m) return CUT_TOKEN.test(rest) ? { bytes, partial: true } : undefined;
    const v = Number(m[1]);
    if (v > 255) return undefined;
    bytes.push(v);
    rest = rest.slice(m[0].length);
    if (m[2] === ")") return rest === "" ? { bytes, partial: false } : undefined;
  }
}

function utf8Length(b: number): number {
  if (b < 0x80) return 1;
  if (b >= 0xc2 && b <= 0xdf) return 2;
  if (b >= 0xe0 && b <= 0xef) return 3;
  if (b >= 0xf0 && b <= 0xf4) return 4;
  return 0;
}

function decodeSeq(seq: readonly number[]): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(seq));
  } catch {
    return undefined;
  }
}

/**
 * Bytes → text, keeping every byte: valid UTF-8 is decoded, and a byte that is not part of a valid
 * sequence is written `\x{NN}` instead of being replaced by U+FFFD.
 */
export function bytesToText(bytes: readonly number[]): string {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const len = utf8Length(bytes[i]);
    const ch = len && i + len <= bytes.length ? decodeSeq(bytes.slice(i, i + len)) : undefined;
    if (ch === undefined) {
      out += `\\x{${bytes[i].toString(16).padStart(2, "0")}}`;
      i += 1;
    } else {
      out += ch;
      i += len;
    }
  }
  return out;
}

const NAMED: Record<string, string> = { "\n": "\\n", "\r": "\\r", "\t": "\\t" };

/** Invisible and control characters (bidi overrides, tag characters, NUL…) written as visible escapes. */
export function escapeInvisible(text: string): string {
  return text.replace(
    /[\p{C}\u2028\u2029]/gu,
    (c) => NAMED[c] ?? `\\u{${(c.codePointAt(0) ?? 0).toString(16)}}`,
  );
}

/** Cap the display text without cutting an escape in half; "…" when anything was left out. */
function capDisplay(text: string, partial: boolean): string {
  if (text.length <= AI_AGENT_SNIPPET_MAX) return partial ? `${text}…` : text;
  const cut = text.slice(0, AI_AGENT_SNIPPET_MAX).replace(/\\(?:[ux](?:\{[0-9a-f]*)?|[nrt])?$/, "");
  return `${cut}…`;
}

type MatchRow = { MatchedHex?: unknown; MatchedLength?: unknown; MatchedText?: unknown };

/** The decoded match of a hit row, or undefined when the row carries none that can be read. */
export function matchedBytesOf(row: MatchRow): MatchedBytes | { text: string } | undefined {
  if (typeof row.MatchedHex === "string") {
    const bytes = hexToBytes(row.MatchedHex);
    if (!bytes) return undefined;
    const len = Number(row.MatchedLength);
    return { bytes, partial: Number.isFinite(len) && len > bytes.length };
  }
  if (typeof row.MatchedText !== "string" || row.MatchedText === "") return undefined;
  if (row.MatchedText.startsWith("%!s(uint8=")) return legacyDebrisToBytes(row.MatchedText);
  return { text: row.MatchedText };
}

/** The "Matched text" the panel and reports show: decoded, secrets redacted, invisible chars escaped. */
export function matchedSnippet(row: MatchRow): string {
  const m = matchedBytesOf(row);
  if (!m) {
    const had =
      typeof row.MatchedHex === "string" || (typeof row.MatchedText === "string" && row.MatchedText !== "");
    return had ? "matched bytes could not be read from this row" : "";
  }
  const partial = "bytes" in m ? m.partial : false;
  const plain = "bytes" in m ? bytesToText(m.bytes) : m.text;
  return capDisplay(escapeInvisible(redactSnippetText(plain, partial)), partial);
}
