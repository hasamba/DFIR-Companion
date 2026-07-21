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
  if (lastBrace === -1) return s;
  const prefix = s.slice(0, lastBrace + 1).replace(/,\s*$/, "");
  return prefix + neededClosers(prefix);
}

// Parse model JSON tolerantly: strip fences/prose, then on a parse failure attempt the
// truncation repair before giving up. Returns the parsed value or throws if even the
// repair can't parse (so the caller's retry/error path still fires).
export function parseJsonLoose(raw: string): unknown {
  // A response that is ALREADY valid JSON wins outright: extraction is fence-based and a model
  // that quotes a ```fenced``` command inside a description would otherwise get its own response
  // sliced apart mid-string. Only pay this when the text actually looks like a JSON document.
  const trimmed = raw.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return JSON.parse(trimmed);
    } catch {
      // fall through to fence/prose extraction below
    }
  }
  const cleaned = extractJsonText(raw);
  try {
    return JSON.parse(cleaned);
  } catch {
    return JSON.parse(repairTruncatedJson(cleaned));
  }
}
