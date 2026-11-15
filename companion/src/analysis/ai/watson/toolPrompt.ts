import { WATSON_TOOL } from "./toolSpecs.js";

// The tool-mode addendum to Watson's system prompt (D11, phase 5). getWatsonPrompt() can resolve to
// an ejected file, so the tool rules are added in code, in tool mode only. They override the JSON
// 'search' and 'lookup' rules for the round. ASD-STE100: short, procedural sentences.

/** The line the finalization send adds (D7c, R3). */
export const WATSON_FINALIZE_LINE = "Answer now. Reply with the JSON object only.";

/** The addendum for a round that offers `names` and allows `max` lookups. */
export function watsonToolsAddendum(max: number, names: readonly string[]): string {
  const lines = [
    "TOOLS FOR THIS QUESTION:",
    `You can use these tools: ${names.join(", ")}.`,
    `You can make up to ${max} lookups for this question.`,
    "Use a tool when you need data that the prompt does not show.",
    "Do not use the 'search' and 'lookup' fields. Set them to null.",
    "When you have enough data, stop calling tools. Then reply with the JSON object only.",
  ];
  if (names.includes(WATSON_TOOL.super)) {
    lines.push(
      "Each SUPER-TIMELINE SEARCH result contains at most 100 raw rows.",
      "Cite a raw row only when you rely on it.",
      "Cite only the ids in square brackets from a search result of this question.",
      "When you cite a raw row, the companion tries to promote it into the forensic timeline.",
      "If it cannot, it removes the items that use that row.",
    );
  }
  return lines.join("\n");
}
