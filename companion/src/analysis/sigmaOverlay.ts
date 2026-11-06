// The import-time Sigma overlay on a row's text, split off again (#2206, #2350). PURE, with no
// imports, so both the Sigma re-grade (sigmaRegrade.ts) and the content tagger (taggerRules.ts)
// can read it without pulling in each other's dependencies.
//
// sigmaImportGrade.applySigmaMatches writes a head at the START of the description
// ("Sigma: <title> - " or "Sigma (<level>, tag only): <title> - ") and one "Sigma rule:" line per
// matched rule into the message. A head is removed ONLY when the message carries the matching
// "Sigma rule: <title> [<id>] — level …" line, so a description that merely starts with "Sigma:"
// (adversary-controlled text, or another importer's own Sigma head) is left as it is.

const SIGMA_LINE = /^Sigma (?:rule|note): /;
const RULE_LINE = /^Sigma rule: (.*) \[([^\]\s]+)\] — level (\w+)/;

export interface SigmaOverlay {
  /** The description without the Sigma head. */
  description: string;
  /** The message without the Sigma lines. */
  message: string;
  /** The Sigma lines, in order. */
  lines: string[];
  ruleIds: string[];
}

/** The Sigma overlay split off a row's text (sigmaImportGrade.applySigmaMatches writes it). */
export function splitSigmaOverlay(description: string, message: string | undefined): SigmaOverlay {
  const all = (message ?? "").split("\n");
  const lines = all.filter((l) => SIGMA_LINE.test(l));
  const rules = lines.flatMap((l) => {
    const m = RULE_LINE.exec(l);
    return m ? [{ title: m[1], id: m[2], level: m[3] }] : [];
  });
  const more = rules.length > 1 ? ` (+${rules.length - 1} more)` : "";
  const heads = rules.flatMap((r) => [
    `Sigma: ${r.title}${more} - `,
    `Sigma (${r.level}, tag only): ${r.title}${more} - `,
  ]);
  const head = heads.find((h) => description.startsWith(h));
  return {
    description: head ? description.slice(head.length) : description,
    message: all.filter((l) => !SIGMA_LINE.test(l)).join("\n"),
    lines,
    ruleIds: rules.map((r) => r.id),
  };
}
