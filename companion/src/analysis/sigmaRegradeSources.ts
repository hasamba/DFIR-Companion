// Re-grade an imported case with the current Sigma rules (#2206): the per-importer hooks.
//
// Each Sigma-graded source is parsed again from the stored import file with the SAME parser the
// import used, so the record mapping, the CloudTrail replica merge, the Entra audit first-row rule
// and the web log's pack choice and veto are the importer's own — not a copy. The parse runs with
// aggregation off, no severity floor and no row cap, so every record comes back as its own row,
// before grouping; sigmaRegrade.ts pairs those rows with the stored ones by raw-record locator.

import { parseCloudTrail } from "./awsImport.js";
import { parseM365Audit } from "./m365Import.js";
import { parseCombinedLog } from "./combinedLogImport.js";
import { sourceArtifactHash } from "./canonicalEvent.js";
import type { SigmaGradingSnapshot } from "./sigmaImportGrade.js";
import type { ForensicEvent } from "./stateTypes.js";
import type { SiemEvent } from "./siemImport.js";
import type { SigmaRuleMitre } from "./sigmaRegrade.js";
import type { SigmaRuleSet } from "./sigmaRuleSet.js";

/** The importers whose rows the import-time Sigma engine grades (#2202, #2203, #2204). */
export const SIGMA_REGRADE_IMPORTERS: ReadonlySet<string> = new Set([
  "aws-cloudtrail",
  "m365",
  "m365-audit",
  "combined-log",
]);

const ALL = { aggregate: false, maxEvents: Number.MAX_SAFE_INTEGER } as const;

/** The importer that wrote a row, when it is one the re-grade can parse again. */
export function regradeImporterOf(e: Pick<ForensicEvent, "canonical">): string | undefined {
  const importer = e.canonical?.producer?.importer;
  return importer && SIGMA_REGRADE_IMPORTERS.has(importer) ? importer : undefined;
}

/** The stored import file a row came from: the first of its labels that names one. */
export function storedFileOf(
  e: Pick<ForensicEvent, "sourceScreenshots">,
  files: ReadonlySet<string>,
): string | undefined {
  return (e.sourceScreenshots ?? []).find((s) => files.has(s));
}

/**
 * True when a row carries the hash of the text it was parsed from and the stored file is not that
 * text. Only CloudTrail rows carry the hash; the others are paired by stored file name alone.
 */
export function storedFileChanged(e: Pick<ForensicEvent, "canonical">, text: string): boolean {
  const hash = e.canonical?.evidence?.sourceArtifactHash;
  return !!hash && hash !== sourceArtifactHash(text);
}

/** Every record of one stored file, graded by `snapshot`, one row per record. */
export function reparseForRegrade(
  importer: string,
  text: string,
  snapshot: SigmaGradingSnapshot,
): SiemEvent[] {
  if (importer === "aws-cloudtrail") return parseCloudTrail(text, { ...ALL, sigma: snapshot }).events;
  if (importer === "m365" || importer === "m365-audit")
    return parseM365Audit(text, { ...ALL, sigma: snapshot }).events;
  if (importer === "combined-log") return parseCombinedLog(text, { ...ALL, sigma: snapshot }).events;
  return [];
}

/**
 * Rule id → techniques, from the rules a rule set loaded plus any `extra` set (the same release
 * with no rule switched off, so a rule the analyst disabled still resolves).
 */
export function sigmaRuleMitreIndex(...sets: readonly (SigmaRuleSet | undefined)[]): SigmaRuleMitre {
  const index = new Map<string, readonly string[]>();
  for (const set of sets) {
    if (!set) continue;
    for (const src of set.sources.values()) {
      const loaded = [...src.always, ...[...src.index.values()].flatMap((m) => [...m.values()].flat())];
      for (const r of loaded) if (!index.has(r.ref.id)) index.set(r.ref.id, r.ref.mitre);
    }
  }
  return (id) => index.get(id);
}
