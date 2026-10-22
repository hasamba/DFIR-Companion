// Dry-run a pasted Sigma rule against the case's stored events (#2211): "this rule would match N of
// the E process events in this case". Deterministic, read-only, no AI.
//
// The paste card compiles only the four Windows endpoint categories (sigmaVqlTemplates.ts), so the
// dry-run answers for the same four. Stored rows are normalized ForensicEvents, not raw records, so
// each Sigma field is read through the Hunt field catalogue (huntQueryFields.ts) by a fixed table.
//
// The silent zero is the failure this file exists to prevent. Two cases, both reported per field:
//   - a field the table does not map (OriginalFileName, Hashes, …) is "not checkable here". Its
//     lookup answers "incomplete", so Kleene logic in sigmaMatch.ts never turns it into a match or
//     a non-match: only a definite `true` is counted, and the undecided rows are counted apart;
//   - a mapped field that no eligible event carries (ParentImage on rows that keep only a bare
//     parent name) is reported with carried: 0, so the analyst sees why the rule cannot fire here.
//
// It reads the super-timeline. That is allowed: CLAUDE.md §7 forbids the AI from reading it, and
// nothing here reaches a model — this module imports nothing AI-related, writes nothing, and its
// matched ids go back to the analyst only.

import { readHuntField } from "./huntQueryFields.js";
import type { HuntEventSource } from "./huntQueryExecutor.js";
import type { HuntDataset } from "./huntQueryTypes.js";
import { compileSigmaRule, type SigmaFieldResolver } from "./sigmaMatch.js";
import type { SigmaFieldLookup } from "./sigmaLookup.js";
import { parseSigmaRule } from "./sigmaRule.js";
import type { SigmaRefusal, SigmaRule } from "./sigmaRuleTypes.js";
import type { CanonicalEventCategory } from "./canonicalEvent.js";
import type { ForensicEvent } from "./stateTypes.js";

/** Most rows one dry-run reads across both timelines. */
export const SIGMA_DRY_RUN_MAX_ROWS = 200_000;
/** Rows per page read from a timeline. */
export const SIGMA_DRY_RUN_PAGE_SIZE = 1_000;
/** Matched event ids returned for the analyst to open. */
export const SIGMA_DRY_RUN_SAMPLE_IDS = 20;

const CATEGORY: Readonly<Record<string, CanonicalEventCategory>> = {
  process_creation: "process",
  network_connection: "network",
  file_event: "file",
  registry_set: "registry",
  registry_event: "registry",
  registry_add: "registry",
  registry_delete: "registry",
};

// Sigma field → Hunt catalogue field, per stored event category.
const COMMON: Readonly<Record<string, string>> = {
  Image: "process.executable",
  User: "user.name",
  ProcessId: "process.pid",
};
const BY_CATEGORY: Readonly<Partial<Record<CanonicalEventCategory, Readonly<Record<string, string>>>>> = {
  process: { CommandLine: "process.command_line", ParentImage: "process.parent.executable" },
  network: {
    DestinationIp: "destination.ip",
    DestinationPort: "destination.port",
    DestinationHostname: "destination.hostname",
    SourceIp: "source.ip",
    SourcePort: "source.port",
  },
  file: { TargetFilename: "file.path" },
  registry: { TargetObject: "registry.key", Details: "registry.value_data" },
};

export interface SigmaDryRunField {
  /** The field as the rule spells it. */
  field: string;
  /** The Hunt catalogue field it is read from; absent when the stored events do not keep it. */
  storedAs?: string;
  checkable: boolean;
  /** Eligible events that carry a value for it. */
  carried: number;
}

export interface SigmaDryRunDone {
  ok: true;
  category: string;
  eventCategory: CanonicalEventCategory;
  datasets: HuntDataset[];
  /** Distinct events read, across both timelines. */
  scanned: number;
  /** Events in the rule's category. */
  eligible: number;
  /** Events the rule definitely matches. */
  matched: number;
  /** Events the rule could not decide because it reads a field that is not checkable here. */
  undecided: number;
  sampleIds: string[];
  /** The row cap stopped the scan before both timelines were read to the end. */
  truncated: boolean;
  maxRows: number;
  fields: SigmaDryRunField[];
}

export type SigmaDryRunResult = SigmaDryRunDone | { ok: false; refusals: SigmaRefusal[] };

export interface SigmaDryRunOptions {
  caseId: string;
  datasets: readonly HuntDataset[];
  signal?: AbortSignal;
  maxRows?: number;
  pageSize?: number;
}

const ABSENT: SigmaFieldLookup = { present: false, values: [], incomplete: false };
const UNKNOWN: SigmaFieldLookup = { present: false, values: [], incomplete: true };

/** Every field name the rule reads, in first-seen order. */
function ruleFields(rule: SigmaRule): string[] {
  const seen = new Set<string>();
  for (const sel of rule.detection.selections) {
    if (sel.kind === "map") sel.fields.forEach((f) => seen.add(f.field));
    if (sel.kind === "list") sel.alternatives.flat().forEach((f) => seen.add(f.field));
  }
  return [...seen];
}

function mappedField(category: CanonicalEventCategory, field: string): string | undefined {
  const table = { ...COMMON, ...BY_CATEGORY[category] };
  const key = Object.keys(table).find((k) => k.toLowerCase() === field.toLowerCase());
  return key ? table[key] : undefined;
}

function toLookup(value: unknown): SigmaFieldLookup {
  const items = (Array.isArray(value) ? value : [value]).filter(
    (v) => v !== undefined && v !== null && v !== "",
  );
  return items.length ? { present: true, values: items.map((v) => String(v)), incomplete: false } : ABSENT;
}

// The catalogue's process.executable falls back to the flat `path`, which on a file or registry
// row is the FILE's path. Outside the process category, Image is read from the canonical process
// alone, so a file_event rule's `Image|contains: 'temp'` cannot fire on the file it names.
function readField(event: ForensicEvent, category: CanonicalEventCategory, stored: string): unknown {
  if (stored === "process.executable" && category !== "process") return event.canonical?.process?.executable;
  return readHuntField(event, stored);
}

function refuse(rule: SigmaRule): SigmaRefusal[] {
  const out: SigmaRefusal[] = [];
  const category = rule.logsource.category?.trim().toLowerCase() ?? "";
  if (!CATEGORY[category])
    out.push({
      path: "logsource.category",
      message: `a dry-run tests only ${Object.keys(CATEGORY).join(", ")} rules; this rule's category is ${category || "missing"}`,
    });
  for (const sel of rule.detection.selections)
    if (sel.kind === "keywords")
      out.push({
        path: `detection.${sel.name}`,
        message: "a keyword list has no field to match against; name the field the keywords belong to",
      });
  return out;
}

export async function dryRunSigma(
  rule: SigmaRule,
  source: HuntEventSource,
  opts: SigmaDryRunOptions,
): Promise<SigmaDryRunResult> {
  const refusals = refuse(rule);
  if (refusals.length) return { ok: false, refusals };
  let compiled;
  try {
    compiled = compileSigmaRule(rule);
  } catch (err) {
    return { ok: false, refusals: [{ path: "detection", message: (err as Error).message }] };
  }
  const category = rule.logsource.category!.trim().toLowerCase();
  const eventCategory = CATEGORY[category];
  const names = ruleFields(rule);
  const stored = new Map(names.map((n) => [n, mappedField(eventCategory, n)]));
  const carried = new Map(names.map((n) => [n, 0]));
  const resolve: SigmaFieldResolver = (record, field) => {
    const target = stored.get(field) ?? mappedField(eventCategory, field);
    if (!target) return UNKNOWN;
    return toLookup(readField(record as unknown as ForensicEvent, eventCategory, target));
  };
  const maxRows = opts.maxRows ?? SIGMA_DRY_RUN_MAX_ROWS;
  const pageSize = opts.pageSize ?? SIGMA_DRY_RUN_PAGE_SIZE;
  const seen = new Set<string>();
  const sampleIds: string[] = [];
  let eligible = 0;
  let matched = 0;
  let undecided = 0;
  let truncated = false;

  const visit = (event: ForensicEvent): void => {
    if (event.canonical?.event.category !== eventCategory) return;
    eligible++;
    for (const [name, target] of stored)
      if (target && toLookup(readField(event, eventCategory, target)).present)
        carried.set(name, (carried.get(name) ?? 0) + 1);
    const verdict = compiled.evaluate(event as unknown as Record<string, unknown>, resolve);
    if (verdict === "incomplete") undecided++;
    else if (verdict) {
      matched++;
      if (sampleIds.length < SIGMA_DRY_RUN_SAMPLE_IDS) sampleIds.push(event.id);
    }
  };

  scan: for (const dataset of opts.datasets) {
    let cursor: number | null = null;
    do {
      if (opts.signal?.aborted) throw new Error("dry-run aborted");
      const page = await source.readPage({ caseId: opts.caseId, dataset, plan: {}, cursor, limit: pageSize });
      for (const [i, event] of page.events.entries()) {
        if (seen.has(event.id)) continue;
        if (seen.size >= maxRows) {
          truncated = true;
          break scan;
        }
        seen.add(event.id);
        visit(event);
        if (seen.size >= maxRows && (i < page.events.length - 1 || page.nextCursor !== null)) {
          truncated = true;
          break scan;
        }
      }
      cursor = page.nextCursor;
    } while (cursor !== null);
  }

  const fields = names.map((field) => {
    const target = stored.get(field);
    return target
      ? { field, storedAs: target, checkable: true, carried: carried.get(field) ?? 0 }
      : { field, checkable: false, carried: 0 };
  });
  return {
    ok: true,
    category,
    eventCategory,
    datasets: [...opts.datasets],
    scanned: seen.size,
    eligible,
    matched,
    undecided,
    sampleIds,
    truncated,
    maxRows,
    fields,
  };
}

/** Parse, then dry-run. Parse refusals come back as they are. */
export async function dryRunSigmaText(
  text: string,
  source: HuntEventSource,
  opts: SigmaDryRunOptions,
): Promise<SigmaDryRunResult> {
  const parsed = parseSigmaRule(text);
  if (!parsed.ok) return parsed;
  return dryRunSigma(parsed.rule, source, opts);
}
