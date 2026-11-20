/**
 * Fences for untrusted case text inside an AI prompt. Case data (event descriptions, pasted logs,
 * chat) can carry adversary-controlled strings, so every prompt that shows it wraps it in a labelled
 * <<<LABEL>>> … <<<END LABEL>>> block and tells the model that the block is data, never
 * instructions. Moved out of Watson's prompt builder so synthesis fences its timeline the same way.
 */

/** Every fence label. One list feeds both the fences and the defang, so no label is left forgeable. */
export const FENCE_LABELS = [
  "TIMELINE",
  "CONTEXT",
  "MEMORY",
  "CHAT",
  "PASTE",
  "HISTORY",
  "LOOKUP",
  "SUPERTIMELINE",
  "ANALYST",
  "STEPS",
] as const;
export type FenceLabel = (typeof FENCE_LABELS)[number];
const MARKER_RE = new RegExp(`<<<\\s*(END\\s+)?(${FENCE_LABELS.join("|")})`, "gi");

/** Any fence marker inside untrusted text is defanged so it cannot close or open a fence. */
export function defang(s: string): string {
  return s.replace(MARKER_RE, "<<‹$1$2").replace(/>>>/g, "›››");
}

/** Wraps untrusted text in one labelled fence, with any marker inside it defanged. */
export function fence(label: FenceLabel, body: string, attrs = ""): string {
  return `<<<${label}${attrs}>>>\n${defang(body)}\n<<<END ${label}>>>`;
}
