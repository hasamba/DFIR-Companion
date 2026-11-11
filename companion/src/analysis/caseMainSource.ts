// The case's MAIN EVIDENCE SOURCE (#2559): which tool most of the case's evidence came from, so hunts
// and the automatic "collect X to settle this" next steps can speak that tool's language (VQL, CQL,
// KQL, ES|QL, SPL) instead of always Velociraptor's.
//
// Derived data, computed on read from the FORENSIC timeline only (never the super-timeline, §7): no
// migration, no new import history, retroactive for every existing case. Only the analyst's override
// is stored (caseMainSourceStore.ts).
//
// COUNTING UNIT — one evidence FILE (the user's decision on #2559, the issue's literal wording). Rows
// carry no file name, so a file is identified from row provenance:
//   - `importBatchId` marks one settle call = one import action. An uploaded export settles once, so
//     for every family except Velociraptor the batch IS the file.
//   - A Velociraptor hunt settles ONCE for the whole hunt but writes one evidence file per artifact
//     (veloEvidenceFirst.ts: `velo-hunt_<hunt>_<artifact>.json`), and every Velociraptor row carries
//     the artifact that emitted it (`artifactName`, velociraptorImport.ts). So for Velociraptor the
//     file is batch + artifact. An offline collection uploaded as one zip therefore counts once per
//     artifact inside it — each is its own result file in the collection.
//   - Rows with no batch id (cases from before #1173, correlation-made rows) count once per family
//     (per family + artifact for Velociraptor).
// Known miscounts, accepted for v1: a multi-page cloud pull settles once per page (each page counts);
// a re-import of rows already present adds no batch (no new count); a row merged into another tool's
// row keeps one batch id, so an import whose every row merged can lose its count; an import whose
// every row was graded Info never reached the forensic timeline and is not counted.
//
// Pure, no I/O.

import { hasCloudProvenance } from "./cloudOnlyCase.js";
import { isGeneratedCoverageRow } from "./cloudMetadataAccess.js";
import type { Finding, ForensicEvent } from "./stateTypes.js";

/** Evidence families, in tie-break order. */
export const SOURCE_FAMILIES = [
  "velociraptor",
  "crowdstrike",
  "defender",
  "m365",
  "elastic",
  "splunk",
  "cloud-other",
  "host-other",
] as const;

export type SourceFamily = (typeof SOURCE_FAMILIES)[number];
export type MainSourceOverride = SourceFamily | "mixed" | null;
/** What the case's hunts are keyed by: one family, "mixed" (per finding/task), or null (no evidence). */
export type EffectiveMainSource = SourceFamily | "mixed" | null;

export const FAMILY_LABELS: Readonly<Record<SourceFamily, string>> = {
  velociraptor: "Velociraptor",
  crowdstrike: "CrowdStrike Falcon",
  defender: "Microsoft Defender / Sentinel",
  m365: "Microsoft 365 / Entra ID",
  elastic: "Elastic",
  splunk: "Splunk",
  "cloud-other": "Other cloud logs (AWS, GCP, Azure, Okta, Google Workspace)",
  "host-other": "Host tools with no query language",
};

/** One family needs at least this share of the counted files to be the main source. */
export const MAIN_SOURCE_THRESHOLD = 0.7;
/** With two or more families present, the winner also needs at least this many files. */
export const MAIN_SOURCE_MIN_FILES = 2;

const M365_LABELS: ReadonlySet<string> = new Set(["microsoft 365", "entra id"]);
const ENTRA_SIGNIN_RE = /^Entra sign-in:/;

// Importer label (lowercased `sources` entry) → family. SIEM exports get their tool from detectTool
// (toolDetect.ts) — these are its canonical names.
const LABEL_FAMILY: ReadonlyMap<string, SourceFamily> = new Map<string, SourceFamily>([
  ["velociraptor", "velociraptor"],
  ["crowdstrike falcon", "crowdstrike"],
  ["microsoft defender", "defender"],
  ["microsoft sentinel", "defender"],
  // mdeHuntingImport.ts's MDE_HUNTING_SOURCE, spelled out: case may not import ingest (a test pins it).
  ["microsoft defender xdr (advanced hunting)", "defender"],
  ["elastic", "elastic"],
  ["splunk", "splunk"],
]);

// A generic "SIEM import" row keeps its vendor only in the description prefix (siemImport.ts:
// `${vendor}: ${base}`), so the vendor names detectVendor returns are read from there.
const DESCRIPTION_VENDOR: ReadonlyArray<[RegExp, SourceFamily]> = [
  [/^CrowdStrike Falcon:/, "crowdstrike"],
  [/^Microsoft Defender:/, "defender"],
  [/^Elastic:/, "elastic"],
  [/^Splunk:/, "splunk"],
];

// A SIEM/EDR export of cloud logs keeps its tool: the analyst queries those rows in Splunk, Elastic or
// Falcon, so that is the hunt language. Defender/Sentinel exports of tenant logs read as Microsoft 365.
const TOOLS_OVER_CLOUD: ReadonlySet<SourceFamily> = new Set(["crowdstrike", "elastic", "splunk"]);

/**
 * The evidence family one forensic row belongs to. Precedence: a CrowdStrike / Elastic / Splunk label
 * (or SIEM vendor prefix) → that tool, even for cloud rows; then cloud provenance (read through
 * cloudOnlyCase.ts) → Microsoft 365 / Entra or other cloud; then any other tool label; else host-other.
 */
export function familyOfEvent(e: ForensicEvent): SourceFamily {
  const labels = (e.sources ?? []).map((s) => s.trim().toLowerCase());
  const tool = toolFamily(labels, e.description ?? "");
  if (hasCloudProvenance(e)) {
    if (tool && TOOLS_OVER_CLOUD.has(tool)) return tool;
    const m365 = labels.some((l) => M365_LABELS.has(l)) || ENTRA_SIGNIN_RE.test(e.description ?? "");
    return m365 ? "m365" : "cloud-other";
  }
  return tool ?? "host-other";
}

function toolFamily(labels: readonly string[], desc: string): SourceFamily | null {
  const found = labels.map((l) => LABEL_FAMILY.get(l)).filter((f): f is SourceFamily => !!f);
  if (found.length) return earliest(found);
  for (const [re, fam] of DESCRIPTION_VENDOR) if (re.test(desc)) return fam;
  return null;
}

function earliest(families: readonly SourceFamily[]): SourceFamily {
  return [...families].sort((a, b) => SOURCE_FAMILIES.indexOf(a) - SOURCE_FAMILIES.indexOf(b))[0];
}

/** The evidence file a row came from (see the header): batch, plus the artifact for Velociraptor. */
export function evidenceFileKey(e: ForensicEvent, family: SourceFamily): string {
  const batch = e.importBatchId ? `batch:${e.importBatchId}` : `legacy:${family}`;
  return family === "velociraptor" ? `${batch}|${e.artifactName ?? ""}` : batch;
}

export interface MainSourceCount {
  family: SourceFamily;
  files: number;
}

export interface MainSourceResult {
  /** The computed choice: a family, "mixed", or null when the forensic timeline has no evidence. */
  auto: EffectiveMainSource;
  override: MainSourceOverride;
  /** The override when set, else `auto`. */
  effective: EffectiveMainSource;
  /** Files per family, most first (ties in family order). */
  counts: MainSourceCount[];
  totalFiles: number;
}

/** Count evidence files per family. Each file counts once, for the family most of its rows have. */
export function countEvidenceFiles(events: readonly ForensicEvent[]): MainSourceCount[] {
  const fileRows = new Map<string, Map<SourceFamily, number>>();
  for (const e of events) {
    if (isGeneratedCoverageRow(e)) continue;
    const fam = familyOfEvent(e);
    const key = evidenceFileKey(e, fam);
    const perFam = fileRows.get(key) ?? new Map<SourceFamily, number>();
    perFam.set(fam, (perFam.get(fam) ?? 0) + 1);
    fileRows.set(key, perFam);
  }
  const files = new Map<SourceFamily, number>();
  for (const perFam of fileRows.values()) {
    const fam = mostCommon(perFam);
    if (fam) files.set(fam, (files.get(fam) ?? 0) + 1);
  }
  return SOURCE_FAMILIES.filter((f) => files.has(f))
    .map((family) => ({ family, files: files.get(family) ?? 0 }))
    .sort(
      (a, b) => b.files - a.files || SOURCE_FAMILIES.indexOf(a.family) - SOURCE_FAMILIES.indexOf(b.family),
    );
}

function mostCommon(counts: ReadonlyMap<SourceFamily, number>): SourceFamily | null {
  let best: SourceFamily | null = null;
  let bestN = 0;
  for (const fam of SOURCE_FAMILIES) {
    const n = counts.get(fam) ?? 0;
    if (n > bestN) {
      best = fam;
      bestN = n;
    }
  }
  return best;
}

/** The 70% / single-family rule over file counts. */
export function pickMainSource(counts: readonly MainSourceCount[]): EffectiveMainSource {
  const total = counts.reduce((sum, c) => sum + c.files, 0);
  if (!total) return null;
  const [top] = counts;
  if (counts.length === 1) return top.family;
  if (top.files < MAIN_SOURCE_MIN_FILES) return "mixed";
  return top.files / total >= MAIN_SOURCE_THRESHOLD ? top.family : "mixed";
}

/** The case's main source, computed from its forensic timeline, with the analyst's override applied. */
export function computeMainSource(
  events: readonly ForensicEvent[],
  override: MainSourceOverride,
): MainSourceResult {
  const counts = countEvidenceFiles(events);
  const auto = pickMainSource(counts);
  return {
    auto,
    override,
    effective: override ?? auto,
    counts,
    totalFiles: counts.reduce((sum, c) => sum + c.files, 0),
  };
}

/** The most common family among some rows (null when there are none). Used per finding / task. */
export function familyOfEvents(events: readonly ForensicEvent[]): SourceFamily | null {
  const counts = new Map<SourceFamily, number>();
  for (const e of events) {
    if (isGeneratedCoverageRow(e)) continue;
    const fam = familyOfEvent(e);
    counts.set(fam, (counts.get(fam) ?? 0) + 1);
  }
  return mostCommon(counts);
}

/** The family of one finding's own evidence (its related forensic events), or null when it cites none. */
export function familyForFinding(
  finding: Pick<Finding, "relatedEventIds">,
  eventsById: ReadonlyMap<string, ForensicEvent>,
): SourceFamily | null {
  const rows = (finding.relatedEventIds ?? [])
    .map((id) => eventsById.get(id))
    .filter((e): e is ForensicEvent => !!e);
  return familyOfEvents(rows);
}

/** Validate an override value from a request or the stored file. */
export function parseMainSourceOverride(
  raw: unknown,
): { ok: true; value: MainSourceOverride } | { ok: false } {
  if (raw === null || raw === undefined || raw === "") return { ok: true, value: null };
  if (raw === "mixed") return { ok: true, value: "mixed" };
  if (typeof raw === "string" && (SOURCE_FAMILIES as readonly string[]).includes(raw))
    return { ok: true, value: raw as SourceFamily };
  return { ok: false };
}
