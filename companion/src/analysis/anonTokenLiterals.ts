// #2569 — token-shaped literals that are already in the text an anonymizer masks.
//
// Case text is adversary-controlled. A planted "ANON_HOST_1" must never collide with a token the
// anonymizer mints, or restore() turns the planted string into a real victim value and the AI
// reads two different things as one entity. Every literal found is either:
//   - escaped to "ANON-LITERAL_…" when that exact token was already minted by an earlier apply()
//     call (the same spelling supportLogRedact uses), so it can never read as ours; or
//   - returned for the caller to reserve, so assign() skips that number from now on.
// The text is otherwise unchanged.

/** The spelling a literal takes when it equals a token this anonymizer already minted. */
export const ANON_LITERAL_PREFIX = "ANON-LITERAL_";

export interface TokenLiteralScan {
  /** The input with every already-minted literal escaped. */
  readonly text: string;
  /** Upper-case literals that were NOT minted yet — the caller reserves these numbers. */
  readonly literals: readonly string[];
}

/**
 * Scan `text` for token-shaped literals. `tokenSource` is the token regex source (matched
 * case-insensitively); `isMinted` receives the literal in upper case.
 */
export function scanTokenLiterals(
  text: string,
  tokenSource: string,
  isMinted: (upperToken: string) => boolean,
): TokenLiteralScan {
  const literals: string[] = [];
  const out = text.replace(new RegExp(tokenSource, "gi"), (m) => {
    const upper = m.toUpperCase();
    if (isMinted(upper)) return ANON_LITERAL_PREFIX + m.slice("ANON_".length);
    literals.push(upper);
    return m;
  });
  return { text: out, literals };
}
