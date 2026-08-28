// The bytes a YARA rule actually matched.
//
// Velociraptor reports a hit as a rule name, a file, and `HitContext` — the bytes around the match,
// base64-encoded. velociraptorImport deliberately refuses to flatten a YARA row into IOCs (#102: a
// pagefile scan scraped 700+ hashes and 360+ URLs out of rule metadata that described SAMPLES, not
// this host). That decision stands and this module does not touch it.
//
// What it recovers is the one field the analyst cannot do without. A pagefile scan reports every hit
// against `C:\pagefile.sys` at one timestamp: forty findings, identical but for a rule name, and
// nothing to tell apart the rule that matched a coinminer string from the rule that matched
// `sekurlsa::logonpasswords`. The matched string is the difference, and it is sitting in the row.
//
// The decoded text goes into the DESCRIPTION, never into the IOC sink. It is a fragment of whatever
// happened to be in memory — worth reading, not worth pivoting on unverified.

/** Longest printable run to keep. Long enough for a full command fragment, short enough for a row. */
const MAX_SNIPPET = 120;
/** Below this a "match" is punctuation and tells the analyst nothing. */
const MIN_SNIPPET = 5;

// Match context is raw memory, so most of the buffer is usually binary. Take the longest printable
// run rather than stripping non-printables everywhere: stripping would splice unrelated fragments
// into one plausible-looking string, which is worse than showing nothing.
function longestPrintableRun(text: string): string {
  let best = "";
  let cur = "";
  for (const ch of text) {
    const c = ch.codePointAt(0)!;
    if (c === 9 || (c >= 0x20 && c <= 0x7e)) cur += ch;
    else {
      if (cur.length > best.length) best = cur;
      cur = "";
    }
  }
  return (cur.length > best.length ? cur : best).trim();
}

// Windows tooling logs command lines as UTF-16LE, so a match on `sekurlsa::logonpasswords` in memory
// arrives as alternating characters and NULs. Decoding that as UTF-8 yields a string whose every
// second character is a NUL — which the printable-run scan would then cut down to one letter.
function looksUtf16le(buf: Buffer): boolean {
  if (buf.length < 4) return false;
  let zeros = 0;
  for (let i = 1; i < buf.length; i += 2) if (buf[i] === 0) zeros++;
  return zeros / Math.ceil(buf.length / 2) > 0.6;
}

/**
 * Decode a `HitContext` into a readable snippet, or "" when there is nothing readable in it.
 *
 * Returning "" is a normal outcome, not a failure: a rule that matched a byte pattern rather than a
 * string has no text to show, and inventing one would be worse than leaving the finding as it was.
 */
export function decodeHitContext(raw: string): string {
  const b64 = raw.trim();
  if (!b64 || !/^[A-Za-z0-9+/=\s]+$/.test(b64)) return "";
  let buf: Buffer;
  try {
    buf = Buffer.from(b64, "base64");
  } catch {
    return "";
  }
  if (buf.length === 0) return "";
  const text = buf.toString(looksUtf16le(buf) ? "utf16le" : "latin1");
  const run = longestPrintableRun(text).replace(/\s+/g, " ");
  if (run.length < MIN_SNIPPET) return "";
  return run.length > MAX_SNIPPET ? `${run.slice(0, MAX_SNIPPET)}…` : run;
}
