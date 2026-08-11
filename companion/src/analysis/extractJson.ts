// LLMs frequently wrap JSON in a markdown code fence (```json ... ```) or add
// prose around it, even when told to return JSON only. This pulls the JSON
// payload out of such responses so JSON.parse can succeed.
export function extractJsonText(raw: string): string {
  const text = raw.trim();

  // Case 1: the whole thing is a fenced block — ```json\n{...}\n``` or ```\n{...}\n```
  const wholeFence = text.match(/^```(?:json)?\s*\n?([\s\S]*?)\n?```$/i);
  if (wholeFence) return wholeFence[1].trim();

  // Case 2: a fenced block appears somewhere inside surrounding prose.
  const innerFence = text.match(/```(?:json)?\s*\n?([\s\S]*?)```/i);
  if (innerFence) return innerFence[1].trim();

  // Case 3: no fence — slice from the first "{" to the last "}" to drop any
  // leading/trailing prose around a bare JSON object.
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (first !== -1 && last > first) return text.slice(first, last + 1);

  // Nothing JSON-like found; return as-is so the caller's parse error is honest.
  return text;
}

// Given a (possibly truncated) JSON string, compute the closing brackets needed to
// balance any still-open arrays/objects, respecting string literals and escapes.
function neededClosers(s: string): string {
  const stack: string[] = [];
  let inStr = false;
  let esc = false;
  for (const c of s) {
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === "{") stack.push("}");
    else if (c === "[") stack.push("]");
    else if (c === "}" || c === "]") stack.pop();
  }
  return stack.reverse().join("");
}

// Best-effort repair of a TRUNCATED JSON response (the usual cause: the model hit its
// max_tokens limit mid-array). Cut back to the last complete object (last "}"), drop a
// dangling comma, and append the closers needed to balance still-open structures. The
// result parses to a partial-but-valid object — and since the response schema makes most
// fields optional/defaulted, a partial findings/events array is still useful (and the
// deterministic high-severity backfill fills any finding the truncation dropped).
export function repairTruncatedJson(s: string): string {
  const lastBrace = s.lastIndexOf("}");
  if (lastBrace === -1) {
    // Truncation landed inside the FIRST (and only) object — no complete '}' exists yet. The
    // usual case is the model hit max_tokens mid-description on the first finding. The previous
    // behavior returned the input unchanged, leaving an unterminated string; neededClosers() can
    // only emit structural closers (it never closes an open string), so JSON.parse failed on
    // "Unterminated string" and the whole response was thrown away. Recover a partial-but-valid
    // object: close the open string (keeping the partial value), or — when that still doesn't
    // parse, e.g. truncation landed inside a KEY or right after a ':' — cut back to the last
    // complete key-value boundary. A partial findings array (even []) is still useful — the
    // deterministic high-severity backfill fills the truncated finding.
    return repairInsideFirstObject(s);
  }
  const prefix = s.slice(0, lastBrace + 1).replace(/,\s*$/, "");
  return prefix + neededClosers(prefix);
}

// Repair a truncation that landed inside the FIRST object (no complete '}' anywhere). Used only
// when lastBrace === -1.
//
// Two candidate repairs, tried most-informative first and validated by an actual JSON.parse —
// closing the string and cutting back are BOTH wrong in the other's case, so picking blindly
// produces invalid JSON. (Doing both at once, as an earlier version did, is wrong in every case
// where a cut happened: `{"a":1,"b":"oops` cut to `{"a":1` then given a stray closing quote
// became `{"a":1"}`, which parses nowhere.)
//
//  A. Close the open string in place — keeps the partial value, which is the common truncation
//     (max_tokens mid-description). Fails when the cut landed inside a KEY, or right after a ':'.
//  B. Cut back to the last comma that was NOT inside a string, dropping the whole incomplete
//     key-value pair. Structurally sound whenever A isn't, at the cost of that one pair.
//
// Neither is tried when it can't apply; if nothing parses we return B (or A) so the caller's
// error message still describes real input.
function repairInsideFirstObject(s: string): string {
  const { inStr, lastCommaOutsideString } = scanStringState(s);
  const candidates: string[] = [];
  if (inStr) candidates.push(closeAndBalance(s + '"'));
  if (lastCommaOutsideString >= 0) candidates.push(closeAndBalance(s.slice(0, lastCommaOutsideString)));
  candidates.push(closeAndBalance(s));
  for (const c of candidates) {
    try {
      JSON.parse(c);
      return c;
    } catch {
      /* try the next candidate */
    }
  }
  return candidates[candidates.length - 1];
}

// Drop a dangling separator, then append the closers needed to balance still-open structures.
function closeAndBalance(s: string): string {
  const prefix = s.replace(/,\s*$/, "");
  return prefix + neededClosers(prefix);
}

// Whether the string ends mid-literal, and the index of the last comma that sat OUTSIDE any
// string literal (-1 when there is none). Commas inside a string are content, not separators.
function scanStringState(s: string): { inStr: boolean; lastCommaOutsideString: number } {
  let inStr = false;
  let esc = false;
  let lastCommaOutsideString = -1;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === ",") lastCommaOutsideString = i;
  }
  return { inStr, lastCommaOutsideString };
}

// JSON forbids raw control characters (U+0000–U+001F) inside string literals, but models
// routinely emit a LITERAL newline/tab in a long description instead of the \n / \t escape.
// JSON.parse rejects the whole response for it ("Bad control character in string literal"),
// and the truncation repair can't help because the bad byte sits mid-response — so an
// otherwise-perfect answer is thrown away and the caller burns another full AI call.
// This escapes those characters, but ONLY inside string literals: newlines/tabs BETWEEN
// tokens are legal JSON whitespace and must survive untouched. Already-escaped sequences
// pass through unchanged (the escape flag skips the char after a backslash).
export function escapeControlCharsInStrings(s: string): string {
  const ESCAPES: Record<string, string> = {
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
  };
  let out = "";
  let inStr = false;
  let esc = false;
  for (const c of s) {
    if (inStr) {
      if (esc) {
        esc = false;
        out += c;
        continue;
      }
      if (c === "\\") {
        esc = true;
        out += c;
        continue;
      }
      if (c === '"') {
        inStr = false;
        out += c;
        continue;
      }
      if (c < " ") {
        out += ESCAPES[c] ?? `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`;
        continue;
      }
      out += c;
      continue;
    }
    if (c === '"') inStr = true;
    out += c;
  }
  return out;
}

// Parse model JSON tolerantly: strip fences/prose, then on a parse failure attempt the
// control-character escape and the truncation repair (individually and combined, since a
// single response can hit both) before giving up. Returns the parsed value or throws if
// nothing parses (so the caller's retry/error path still fires).
export function parseJsonLoose(raw: string): unknown {
  // A response that is ALREADY valid JSON wins outright: extraction is fence-based and a model
  // that quotes a ```fenced``` command inside a description would otherwise get its own response
  // sliced apart mid-string. Only pay this when the text actually looks like a JSON document.
  const trimmed = raw.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return JSON.parse(trimmed);
    } catch {
      // The strict parse failed. Before falling through to fence/prose extraction (which
      // matches the FIRST ```json fence ANYWHERE and would slice the response down to a tiny
      // inner snippet when a string value legitimately contains a fenced block), retry with
      // control-char escaping on the WHOLE document. Models routinely emit a literal newline
      // inside a long description instead of \n; JSON.parse rejects the whole response for it,
      // and the fence extractor would grab an inner ```json snippet instead of the outer object.
      // escapeControlCharsInStrings is string-literal-aware (tracks inStr/esc), so it's safe to
      // run on the whole document — it only escapes raw control chars INSIDE string literals,
      // preserving legal whitespace between tokens. (bug #2)
      try {
        return JSON.parse(escapeControlCharsInStrings(trimmed));
      } catch {
        // fall through to fence/prose extraction below
      }
    }
  }
  const cleaned = extractJsonText(raw);
  try {
    return JSON.parse(cleaned);
  } catch {
    // Try each repair on its own before the combination, so the least-invasive one wins.
    const escaped = escapeControlCharsInStrings(cleaned);
    try {
      return JSON.parse(escaped);
    } catch {
      try {
        return JSON.parse(repairTruncatedJson(cleaned));
      } catch {
        // Escape first, then truncate: neededClosers() tracks string state, and an
        // unescaped newline would otherwise leave it mid-string at the cut point.
        return JSON.parse(repairTruncatedJson(escaped));
      }
    }
  }
}
