// Which query language a hunt is written in (#2559), from the evidence family it is about
// (caseMainSource.ts) and the DFIR_HUNT_PLATFORMS allowlist (huntPlatforms.ts).
//
// - Velociraptor, no evidence, or a host tool with no query language (Hayabusa, THOR, KAPE …) → VQL,
//   the existing hunt path, deployable. The host-tool case carries a note.
// - CrowdStrike → CQL; Defender/Sentinel → KQL on the Device* tables; Microsoft 365 / Entra → KQL on
//   the sign-in, directory-audit and Office activity tables; Elastic → ES|QL; Splunk → SPL. These are
//   copy-ready only — never deployed.
// - Other cloud logs (AWS, GCP, Azure, Okta, Google Workspace) → no language yet: no hunt at all, a
//   note pointing to the Query Translator. Never VQL — a tenant log case has no endpoint to run it on.
// - A language whose platform the server disabled falls back to VQL, with a note.
//
// Pure, no I/O.

import { FAMILY_LABELS, type MainSourceResult, type SourceFamily } from "./caseMainSource.js";
import { resolveHuntPlatforms, type HuntPlatform } from "./huntPlatforms.js";
import { PLATFORM_SCHEMA_HINTS } from "./queryTranslate.js";

export const HUNT_LANGUAGES = ["vql", "cql", "kql-device", "kql-cloud", "esql", "spl"] as const;
export type HuntLanguage = (typeof HUNT_LANGUAGES)[number];
/** The non-VQL languages: written by the language-hunt path, copy-ready, never deployed. */
export type CopyHuntLanguage = Exclude<HuntLanguage, "vql">;

/** The DFIR_HUNT_PLATFORMS key that enables each language. */
export const LANGUAGE_PLATFORM: Readonly<Record<HuntLanguage, HuntPlatform>> = {
  vql: "velociraptor",
  cql: "crowdstrike",
  "kql-device": "defender",
  "kql-cloud": "defender",
  esql: "elastic",
  spl: "splunk",
};

export const LANGUAGE_LABELS: Readonly<Record<HuntLanguage, string>> = {
  vql: "Velociraptor VQL",
  cql: "CrowdStrike Falcon CQL",
  "kql-device": "Defender / Sentinel KQL",
  "kql-cloud": "Sentinel KQL (sign-in and audit logs)",
  esql: "Elastic ES|QL",
  spl: "Splunk SPL",
};

const KQL_CLOUD_HINT =
  "Microsoft Sentinel / Defender XDR KQL over the Microsoft 365 and Entra ID tables. Tables: SigninLogs and " +
  "AADNonInteractiveUserSignInLogs (TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType, " +
  "ResultDescription, Location, UserAgent, ConditionalAccessStatus, AuthenticationRequirement), AuditLogs " +
  "(OperationName, Category, Result, InitiatedBy, TargetResources), OfficeActivity (Operation, UserId, ClientIP, " +
  "Workload, OfficeObjectId, Parameters), CloudAppEvents (ActionType, AccountDisplayName, IPAddress). Pipe with " +
  "`| where`; operators =~, in~, has, has_any, contains; summarize with `| summarize count() by …`. There are NO " +
  "Device* tables here — this is tenant evidence, not endpoint telemetry.";

/** The schema reference the language-hunt prompt grounds each language in. */
export const LANGUAGE_SCHEMA_HINTS: Readonly<Record<CopyHuntLanguage, string>> = {
  cql: PLATFORM_SCHEMA_HINTS.crowdstrike,
  "kql-device": PLATFORM_SCHEMA_HINTS.defender,
  "kql-cloud": KQL_CLOUD_HINT,
  esql: PLATFORM_SCHEMA_HINTS.elastic,
  spl: PLATFORM_SCHEMA_HINTS.splunk,
};

const FAMILY_LANGUAGE: Readonly<Record<SourceFamily, HuntLanguage | null>> = {
  velociraptor: "vql",
  crowdstrike: "cql",
  defender: "kql-device",
  m365: "kql-cloud",
  elastic: "esql",
  splunk: "spl",
  "cloud-other": null,
  "host-other": "vql",
};

/** The hunt platforms DFIR_HUNT_PLATFORMS enables (all when unset). */
export const enabledHuntPlatforms = (): HuntPlatform[] =>
  resolveHuntPlatforms(process.env.DFIR_HUNT_PLATFORMS);

export interface LanguageChoice {
  /** null = no hunt language for this evidence (other cloud logs): show no hunt. */
  language: HuntLanguage | null;
  /** Shown to the analyst beside the hunts; "" when the language is the family's own. */
  note: string;
}

export const NO_LANGUAGE_NOTE =
  "No hunt language for other cloud logs (AWS, GCP, Azure, Okta, Google Workspace) yet — use the Query Translator.";

/** The hunt language for one evidence family, honouring the enabled platforms. */
export function huntLanguageFor(
  family: SourceFamily | null,
  enabled: readonly HuntPlatform[],
): LanguageChoice {
  if (!family) return { language: "vql", note: "" };
  const language = FAMILY_LANGUAGE[family];
  if (!language) return { language: null, note: NO_LANGUAGE_NOTE };
  if (family === "host-other")
    return {
      language: "vql",
      note: `The main evidence comes from host tools with no hunt language; showing Velociraptor VQL.`,
    };
  if (language !== "vql" && !enabled.includes(LANGUAGE_PLATFORM[language]))
    return {
      language: "vql",
      note: `${LANGUAGE_LABELS[language]} is disabled on this server (DFIR_HUNT_PLATFORMS); showing Velociraptor VQL instead of ${FAMILY_LABELS[family]} queries.`,
    };
  return { language, note: "" };
}

export interface HuntGroup {
  language: HuntLanguage;
  ids: string[];
}

export interface HuntGroupPlan {
  groups: HuntGroup[];
  /** Distinct notes for the analyst (fallbacks, items with no hunt language). */
  notes: string[];
}

/**
 * Split findings or playbook tasks by hunt language. With a main source every item uses it; on a
 * mixed case each item uses its own evidence's family (`familyOf`), and an item with no evidence uses
 * `fallback` — the default (VQL) unless the case is tenant-only, where a VQL hunt has no host to run on. Items whose evidence has no hunt language are left out, with a note. Groups come
 * in HUNT_LANGUAGES order, so the VQL group (the existing path) is always first.
 */
export function planHuntGroups<T>(
  items: readonly T[],
  familyOf: (item: T) => SourceFamily | null,
  idOf: (item: T) => string,
  main: Pick<MainSourceResult, "effective">,
  enabled: readonly HuntPlatform[],
  /** The family an item with no evidence family falls back to — "cloud-other" on a tenant-only case. */
  fallback: SourceFamily | null = null,
): HuntGroupPlan {
  const byLanguage = new Map<HuntLanguage, string[]>();
  const notes = new Set<string>();
  for (const item of items) {
    const family = (main.effective === "mixed" ? familyOf(item) : main.effective) ?? fallback;
    const choice = huntLanguageFor(family, enabled);
    if (choice.note) notes.add(choice.note);
    if (!choice.language) continue;
    byLanguage.set(choice.language, [...(byLanguage.get(choice.language) ?? []), idOf(item)]);
  }
  const groups = HUNT_LANGUAGES.filter((l) => byLanguage.has(l)).map((language) => ({
    language,
    ids: byLanguage.get(language) ?? [],
  }));
  return { groups, notes: [...notes] };
}
