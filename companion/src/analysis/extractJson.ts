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
