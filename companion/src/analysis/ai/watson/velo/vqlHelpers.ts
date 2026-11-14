import type { VqlToken } from "./vqlTokens.js";

// Small token predicates shared by the VQL allowlist modules (vqlAllowed.ts, vqlArgs.ts).

export const lc = (s: string): string => s.toLowerCase();

/** Case-insensitive membership. */
export const has = (list: readonly string[], name: string): boolean => list.some((x) => lc(x) === lc(name));

export const isPunct = (t: VqlToken | undefined, text: string): boolean =>
  t?.kind === "punct" && t.text === text;

export const isWord = (t: VqlToken | undefined, word: string): boolean =>
  t?.kind === "ident" && lc(t.text) === word;

/** What a LET defines, as far as the call checks need to know. */
export interface LetDef {
  callable: boolean;
}
