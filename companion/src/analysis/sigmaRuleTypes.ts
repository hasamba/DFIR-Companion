// The typed shape of one parsed Sigma rule (#796). This is the contract between the parser
// (sigmaRule.ts) and the VQL compiler (#797): everything the compiler needs is here, and nothing
// here depends on the target language. Values keep their exact bytes; escaping is the compiler's
// job, so the parser never has to know what it feeds.

/** A Sigma value as YAML typed it. A string keeps its bytes; a number or boolean stays typed. */
export type SigmaScalar = string | number | boolean;

/** The value modifiers the Companion can express. Every other modifier is refused by name. */
export const SIGMA_MODIFIERS = [
  "contains",
  "startswith",
  "endswith",
  "all",
  "re",
  "cidr",
  "gt",
  "gte",
  "lt",
  "lte",
] as const;
export type SigmaModifier = (typeof SIGMA_MODIFIERS)[number];

/** One `Field|mod|mod: value(s)` line. A list of values is an OR unless `all` is among the modifiers. */
export interface SigmaFieldMatch {
  field: string;
  modifiers: SigmaModifier[];
  values: SigmaScalar[];
}

/**
 * A named block under `detection`. `map` is an AND of fields; `list` is an OR of ANDs (a YAML list
 * of maps); `keywords` is a YAML list of bare values matched against the whole event.
 */
export type SigmaSelection =
  | { kind: "map"; name: string; fields: SigmaFieldMatch[] }
  | { kind: "list"; name: string; alternatives: SigmaFieldMatch[][] }
  | { kind: "keywords"; name: string; values: SigmaScalar[] };

/**
 * The condition as an AST. `oneOf` / `allOf` carry the selection names their pattern matched at
 * parse time, so the compiler never sees a wildcard.
 */
export type SigmaCondition =
  | { kind: "ref"; name: string }
  | { kind: "not"; operand: SigmaCondition }
  | { kind: "and"; operands: SigmaCondition[] }
  | { kind: "or"; operands: SigmaCondition[] }
  | { kind: "oneOf"; names: string[] }
  | { kind: "allOf"; names: string[] };

export interface SigmaLogsource {
  category?: string;
  product?: string;
  service?: string;
}

export interface SigmaRule {
  title: string;
  id?: string;
  level?: string;
  description?: string;
  /** Every tag as written, tactic tags included. */
  tags: string[];
  /** Technique ids lifted from `attack.tNNNN[.NNN]` tags, in tag order, e.g. "T1059.001". */
  mitreTechniques: string[];
  logsource: SigmaLogsource;
  detection: {
    selections: SigmaSelection[];
    condition: SigmaCondition;
  };
}

/** One thing the Companion cannot express, at a YAML path, in a sentence written for an analyst. */
export interface SigmaRefusal {
  path: string;
  message: string;
}

export type SigmaParseResult = { ok: true; rule: SigmaRule } | { ok: false; refusals: SigmaRefusal[] };
