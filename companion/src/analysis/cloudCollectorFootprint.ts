// The collector's own API calls, tagged in the evidence (#2487).
//
// A live cloud collection's own reads (M365 AuditSearchCreated/Completed, AWS LookupEvents /
// DescribeRegions / GetObject…, GCP ListLogEntries…) come back in the case like anyone else's. This
// pass marks them so the analyst can tell the investigator's footprint from the tenant's or the
// intruder's use of the same APIs. It runs at the import tagger seam (routes/routeSettleDeps.ts,
// server.ts) over the rows an import already hands the tagger — it never reads the super-timeline.
//
// TAG AND NOTE ONLY. One event tag per row, label `dfir-collector`, author
// `tagger:dfir-collector:<collectionId>` (the note: which collection's identity and window it
// matches). Severity, MITRE, `origin` and the description are never touched and no row is dropped.
// The host collector's `origin: "collector"` marker is deliberately NOT used: it freezes a row's
// grade (tagger.ts never raises it), and a stolen collector credential must stay gradeable. The
// `tagger:` author keeps these automatic tags from protecting rows against the super-timeline cap.
//
// A row is tagged for a run only when ALL hold:
//   1. it is a single-call cloud row (CloudTrail `api`, UAL `audit-operation`, Azure Activity
//      `activity-operation`, GCP `api-call`) — every summary row (lineage, compute lifecycle,
//      privilege path, service-account join, the #2482/#2493 collection summaries) has its own type
//      and is never tagged;
//   2. its action is one of the calls the collector itself makes (COLLECTOR_CALLS) — so every write,
//      and every read outside that set, by the collector identity stays untagged and stands out;
//   3. its actor is the identity the run recorded in OUR manifest (never anything the row claims);
//   4. its whole time span lies inside one of the run's spans, widened by a clock-skew allowance.

import type { NewTag } from "./tags.js";
import type { ForensicEvent } from "./stateTypes.js";
import { TAGGER_AUTHOR_PREFIX } from "./superTimeline.js";

export const COLLECTOR_LABEL = "dfir-collector";
export const COLLECTOR_AUTHOR_PREFIX = `${TAGGER_AUTHOR_PREFIX}dfir-collector:`;
/** Clock skew between this machine and the cloud's log clock; also covers the identity call made just before a run's recorded start. */
export const COLLECTOR_SPAN_SKEW_MS = 5 * 60_000;

/** One stretch of a run that talked to the cloud, as the run itself recorded it. ISO times, unwidened. */
export interface CollectorSpan {
  from: string;
  to: string;
  /** The identity this stretch ran as (manifest header, or its resume line). */
  caller: string;
}

/** One collection of the case, as the matcher sees it (built by integrations/cloudCollect/collectRuns.ts). */
export interface CollectorRun {
  collectionId: string;
  /** "aws" | "microsoft" | "gcp" — the collection's provider. */
  provider: string;
  spans: CollectorSpan[];
}

/**
 * The calls the collector itself makes, per provider, lowercased. A row's action matches when it
 * equals an entry or ends with `.`/`/`/`:` + the entry — a qualified entry (storage.objects.get) is
 * matched whole, never shortened. tests/architecture/collectorCallsAllowlist.test.ts fails when an
 * AWS collector command is missing here.
 */
export const COLLECTOR_CALLS: Readonly<Record<string, readonly string[]>> = {
  aws: [
    "getcalleridentity",
    "lookupevents",
    "describeregions",
    "describetrails",
    "listobjects",
    "listobjectsv2",
    "getobject",
    "listdetectors",
    "listfindings",
    "getfindings",
  ],
  microsoft: ["auditsearchcreated", "auditsearchcompleted"],
  gcp: ["listlogentries", "listsinks", "testiampermissions", "storage.objects.list", "storage.objects.get"],
};

/** The canonical event types of a row that stands for ONE cloud call (not a summary). */
const SINGLE_CALL_TYPES = new Set(["api", "api-call", "audit-operation", "activity-operation"]);

/** The row providers each collection provider's calls can appear under. */
const ROW_PROVIDERS: Readonly<Record<string, readonly string[]>> = {
  aws: ["aws"],
  microsoft: ["m365", "azure"],
  gcp: ["gcp"],
};

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ASSUMED_ROLE = /^arn:([^:]+):sts::(\d{12}):assumed-role\/([^/]+)\/(.+)$/;
const IAM_USER = /^arn:([^:]+):iam::(\d{12}):user\/(?:.*\/)?([^/]+)$/;

function isCollectorCall(provider: string, action: string): boolean {
  const a = action.trim().toLowerCase();
  if (!a) return false;
  return (COLLECTOR_CALLS[provider] ?? []).some(
    (entry) => a === entry || a.endsWith(`.${entry}`) || a.endsWith(`/${entry}`) || a.endsWith(`:${entry}`),
  );
}

/** The row's single-call cloud facts, or null when it is not one. */
function callFacts(event: ForensicEvent) {
  const c = event.canonical;
  if (!c || c.event.category !== "cloud" || !SINGLE_CALL_TYPES.has(c.event.type)) return null;
  const action = c.event.action ?? "";
  return action ? { c, action } : null;
}

/** True when some provider's collector could have made this call — the cheap pre-check before reading runs. */
function couldBeCollectorCall(event: ForensicEvent): boolean {
  const facts = callFacts(event);
  return !!facts && Object.keys(COLLECTOR_CALLS).some((p) => isCollectorCall(p, facts.action));
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

type Canonical = NonNullable<ForensicEvent["canonical"]>;

function awsIdentityMatches(c: Canonical, caller: string): boolean {
  const assumed = ASSUMED_ROLE.exec(caller);
  if (assumed) {
    const [, partition, account, role, session] = assumed;
    const issuer = c.authentication?.issuer ?? "";
    const roleArn = new RegExp(
      `^arn:${escapeRegex(partition)}:iam::${account}:role/(?:.*/)?${escapeRegex(role)}$`,
    );
    const principal = c.cloud?.principalId ?? "";
    return (
      roleArn.test(issuer) &&
      principal.endsWith(`:${session}`) &&
      (!c.cloud?.accountId || c.cloud.accountId === account)
    );
  }
  const user = IAM_USER.exec(caller);
  if (user) {
    const [, , account, name] = user;
    return c.actor?.name === name && c.cloud?.accountId === account && !c.authentication?.issuer;
  }
  return false;
}

function microsoftIdentityMatches(c: Canonical, caller: string): boolean {
  if (!GUID.test(caller)) return false;
  const text = `${c.actor?.name ?? ""} ${c.actor?.id ?? ""}`.toLowerCase();
  return new RegExp(`(^|[^0-9a-f])${caller.toLowerCase()}($|[^0-9a-f])`).test(text);
}

function gcpIdentityMatches(c: Canonical, caller: string): boolean {
  const name = (c.actor?.name ?? "").trim().toLowerCase();
  return !!name && name.includes("@") && name === caller.trim().toLowerCase();
}

function identityMatches(provider: string, c: Canonical, caller: string): boolean {
  if (!(ROW_PROVIDERS[provider] ?? []).includes(c.cloud?.provider ?? "")) return false;
  if (provider === "aws") return awsIdentityMatches(c, caller);
  if (provider === "microsoft") return microsoftIdentityMatches(c, caller);
  if (provider === "gcp") return gcpIdentityMatches(c, caller);
  return false;
}

function insideSpan(event: ForensicEvent, span: CollectorSpan): boolean {
  const start = Date.parse(event.timestamp);
  const end = Date.parse(event.endTimestamp || event.timestamp);
  const from = Date.parse(span.from) - COLLECTOR_SPAN_SKEW_MS;
  const to = Date.parse(span.to) + COLLECTOR_SPAN_SKEW_MS;
  if (![start, end, from, to].every(Number.isFinite)) return false;
  return start >= from && end <= to;
}

/** Earliest span start of a run, for the deterministic "earliest run names the tag" order. */
function runStart(run: CollectorRun): number {
  const starts = run.spans.map((s) => Date.parse(s.from)).filter(Number.isFinite);
  return starts.length ? Math.min(...starts) : Number.POSITIVE_INFINITY;
}

/** The collection whose own call this row is, or null. Pure. */
export function collectorRunFor(event: ForensicEvent, runs: readonly CollectorRun[]): string | null {
  const facts = callFacts(event);
  if (!facts) return null;
  const ordered = [...runs].sort((a, b) => runStart(a) - runStart(b));
  for (const run of ordered) {
    if (!isCollectorCall(run.provider, facts.action)) continue;
    const hit = run.spans.some(
      (span) => identityMatches(run.provider, facts.c, span.caller) && insideSpan(event, span),
    );
    if (hit) return run.collectionId;
  }
  return null;
}

/** The tags to write for `rows`: one per collector call. Pure. */
export function collectorFootprintTags(
  rows: readonly ForensicEvent[],
  runs: readonly CollectorRun[],
): NewTag[] {
  if (!runs.length) return [];
  const out: NewTag[] = [];
  for (const row of rows) {
    const collectionId = collectorRunFor(row, runs);
    if (!collectionId) continue;
    out.push({
      targetType: "event",
      targetId: row.id,
      label: COLLECTOR_LABEL,
      author: `${COLLECTOR_AUTHOR_PREFIX}${collectionId}`,
    });
  }
  return out;
}

/** True when a tag author is this pass's note (the dashboard words the pill from it). */
export function isCollectorNote(author: string): boolean {
  return author.startsWith(COLLECTOR_AUTHOR_PREFIX);
}

export interface CollectorFootprintDeps {
  tags: { addMany(caseId: string, inputs: readonly NewTag[]): Promise<readonly unknown[]> };
  /** Every collection of the case (collectRuns.ts). */
  runsFor(caseId: string): Promise<CollectorRun[]>;
  onTags?: (caseId: string) => void;
  logLine?: (message: string) => void;
}

/**
 * Tag the collector's own calls among `rows` (rows an import just handed the tagger). Best effort:
 * never throws, never fails an import. Returns the tags written.
 */
export async function tagCollectorFootprint(
  deps: CollectorFootprintDeps,
  caseId: string,
  rows: readonly ForensicEvent[],
): Promise<number> {
  const candidates = rows.filter(couldBeCollectorCall);
  if (!candidates.length) return 0;
  try {
    const inputs = collectorFootprintTags(candidates, await deps.runsFor(caseId));
    if (!inputs.length) return 0;
    const written = (await deps.tags.addMany(caseId, inputs)).length;
    if (written) deps.onTags?.(caseId);
    return written;
  } catch (err) {
    deps.logLine?.(`collector footprint tagging skipped for case ${caseId}: ${(err as Error).message}`);
    return 0;
  }
}
