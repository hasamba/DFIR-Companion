import type { VqlToken } from "./vqlTokens.js";

// Shape rules for Watson's launch VQL (final review G1-G3). The launch path does not send the VQL
// as written: it splits it on blank lines, drops lines that start with `--` (splitVqlStatements)
// and embeds the result in a '''…''' literal on the server. Any of those inside a string or a
// comment would make the text the allowlist checked differ from the text Velociraptor runs, so
// they are refused outright. Comments are refused entirely: they are the fail-open direction
// (a lexer that disagrees about where one ends hides a call from the check).

const BLANK_LINE = /\n[^\S\n]*\n/;
export const TRIPLE_QUOTE = "'''";
export const TRIPLE_QUOTE_REASON = "''' (a triple-quoted string) is not allowed";

/** Does a string token's text hold something the launch path would split or drop? */
function splitsString(text: string): boolean {
  if (BLANK_LINE.test(text)) return true;
  return text
    .split("\n")
    .slice(1)
    .some((line) => line.trim().startsWith("--"));
}

/** Text between tokens that is not whitespace — a comment, since the tokenizer skipped it. */
function hasComment(src: string, tokens: readonly VqlToken[]): boolean {
  let at = 0;
  for (const t of [...tokens, { start: src.length, end: src.length }]) {
    if (src.slice(at, t.start).trim()) return true;
    at = t.end;
  }
  return false;
}

/** Why this raw VQL's shape is refused for a Watson launch (empty when it is fine). */
export function vqlShapeProblems(src: string, tokens: readonly VqlToken[]): string[] {
  const reasons: string[] = [];
  if (src.includes(TRIPLE_QUOTE)) reasons.push(TRIPLE_QUOTE_REASON);
  if (src.includes("\r")) reasons.push("a carriage return in the VQL");
  if (hasComment(src, tokens)) reasons.push("comments are not allowed");
  if (tokens.some((t) => t.kind === "string" && splitsString(t.text)))
    reasons.push("a string literal holds a blank line or a line starting with --");
  return reasons;
}
