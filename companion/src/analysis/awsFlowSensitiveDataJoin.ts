// Joins an AWS flow's own already-computed resource attribution to the bulk object-read summaries
// the shipped bulk-read pass (cloudBulkRead.ts, #908 item 8) ALREADY emitted for a session whose
// credentials CloudTrail records as delivered to that same instance (#1295 — the "sensitive-data
// activity" half of #931 item 13, deferred from #1151). Third pass of the flow family: reads ONLY
// the attribution note text (never re-derives the attribution) and appends its own independent
// note, exactly as awsFlowIdentityExecutionJoin.ts does.
//
// What one note establishes, and what it never claims:
//   - "the bulk-read summary <id> the pass already graded was signed with instance-role
//     credentials CloudTrail records as delivered to this instance" — the session is identified
//     structurally on the raw read rows' own envelopes (AssumedRole, IMDSv1/IMDSv2 delivery, the
//     session name is an instance id, provider aws), never from summary prose and never from a
//     role name. Rows that are merely SILENT on delivery (another importer, no mechanism word)
//     never veto; rows that positively name another session or provider always do;
//   - the counts and window are the summary's own; the note points at the summary by id;
//   - NOT that the flow carried the objects, NOT that the read was performed FROM the instance
//     (IMDS-delivered credentials can be stolen and used elsewhere — #908 item 7), NOT causation
//     in either direction. The reader's recorded source address is disclosed as-is and compared
//     to the attributed endpoint's address as a stated fact, never a verdict;
//   - the join keeps a summary whose read window OVERLAPS the ±24h around the flow (inclusive,
//     and worded as overlap, never as "within") and never claims "unusual" — no baseline exists
//     to judge that honestly;
//   - the envelope-side session rule is WEAKER than awsCompute.ts's own ownSessionInstance: the
//     session ARN is not on the envelope, so its ARN-agreement check cannot be repeated here, and
//     only ec2RoleDelivery "1.0"/"2.0" are visible as a protocol word. A miss is possible; a false
//     join is not made from the envelope's own words;
//   - a group whose recomputed summary id collides with another's (a hash collision — the key
//     itself is as discriminating as groupKey since #1356) is an ambiguous pointer and is skipped, as is
//     a credential-less group and a credential whose rows disagree on the session;
//   - re-runs on every merge; strips its own prior note first; an empty index still strips.

import type { ForensicEvent } from "./stateTypes.js";
import { appendDerivedNote } from "./derivedNote.js";
import { INSTANCE_ID } from "./canonicalAwsCompute.js";
import { FLOW_ATTRIBUTION_MARKER } from "./awsFlowResourceAttribution.js";
import { parseAttributionEndpoints, type AttributedEndpoint } from "./awsFlowIdentityExecutionJoin.js";
import { groupBulkReads, summaryId, type BulkGroup } from "./cloudBulkRead.js";

export const FLOW_SENSITIVE_DATA_MARKER = "[flow sensitive-data:";
const FLOW_SENSITIVE_DATA_NOTE_RE = /\s*\[flow sensitive-data:[^\]]*\]/gu;

export const SENSITIVE_DATA_WINDOW_MS = 24 * 3_600_000;
const MAX_SUMMARIES_PER_ENDPOINT = 5;
const MAX_CONTAINER_NAMES = 3;
const MAX_KEY_CHARS = 20;
const IMDS_PROTOCOLS = new Set(["IMDSv1", "IMDSv2"]);

const lower = (s: string): string => (s ?? "").trim().toLowerCase();

function ms(timestamp: string | undefined): number | null {
  const t = Date.parse(timestamp ?? "");
  return Number.isFinite(t) ? t : null;
}

// Provider-gated (#1294): an Azure/GCP flow row must never be joined to AWS bulk-read summaries,
// even when its description carries a (forged or stale) attribution marker that the now-gated
// attribution pass no longer strips (#1367); the AWS flow importer has always stamped provider
// "aws", so no AWS row is excluded by this.
function isFlowEvent(e: ForensicEvent): boolean {
  const c = e.canonical;
  return c?.event.category === "network" && c.event.type === "flow" && c.cloud?.provider === "aws";
}

// Same rule as the sibling: bracket content never nests inside a derived note, and every
// evidence-derived string (a role name, a key id, a container name, an address) is stripped of
// brackets before it is interpolated — a report-integrity requirement, not polish.
function sanitizeForNote(s: string): string {
  return s.replace(/[[\]]/gu, "");
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/**
 * What one row's envelope says about the session that signed it (Ollama code review, finding 2):
 *   - `instance`: an AWS AssumedRole session whose credentials CloudTrail records as IMDS-delivered
 *     and whose session name is an instance id — a positive reading;
 *   - `disagrees`: the envelope positively names something else — a different provider, a
 *     non-AssumedRole mechanism, an IMDS-delivered session whose name is NOT an instance id, or an
 *     AssumedRole session whose name is not an instance id;
 *   - `silent`: no envelope, or no mechanism, or an instance-shaped AssumedRole session with no
 *     delivery word (another importer, or a record type that carries none) — says nothing either
 *     way and never vetoes a join on its own.
 */
export type SessionReading =
  { kind: "instance"; instanceId: string; protocol: string } | { kind: "disagrees" } | { kind: "silent" };

export function sessionReadingOf(e: ForensicEvent): SessionReading {
  const c = e.canonical;
  if (!c) return { kind: "silent" };
  const provider = lower(c.cloud?.provider ?? "");
  if (provider && provider !== "aws") return { kind: "disagrees" };
  const mechanism = c.authentication?.mechanism;
  if (mechanism === undefined) return { kind: "silent" };
  if (mechanism !== "AssumedRole") return { kind: "disagrees" };
  const principalId = c.cloud?.principalId ?? "";
  // awsIdentity.ts's own session-name derivation: the text after the LAST ":"; no colon, no session.
  const colon = principalId.lastIndexOf(":");
  const session = colon < 0 ? "" : principalId.slice(colon + 1);
  const protocol = c.authentication?.protocol;
  if (!INSTANCE_ID.test(session)) {
    // No principal at all and no delivery word: nothing asserted. A named-but-not-instance session,
    // or a colon-less principal beside a delivery word, is a positive reading of something else.
    return !principalId && protocol === undefined ? { kind: "silent" } : { kind: "disagrees" };
  }
  if (protocol === undefined) return { kind: "silent" };
  if (!IMDS_PROTOCOLS.has(protocol)) return { kind: "disagrees" };
  // Instance-shaped and IMDS-delivered, but no provider word: the row cannot say "CloudTrail".
  if (!provider) return { kind: "silent" };
  return { kind: "instance", instanceId: session, protocol };
}

interface SessionAgreement {
  instances: Set<string>;
  protocols: Set<string>;
  /** Rows carrying this credential whose envelope positively reads as NOT an instance session. */
  disagreeingRows: number;
}

/** Every row signed with a credential, keyed on (account, credentialId): the credential IS the session. */
function sessionAgreementByCredential(events: readonly ForensicEvent[]): Map<string, SessionAgreement> {
  const out = new Map<string, SessionAgreement>();
  for (const e of events) {
    const c = e.canonical;
    const credentialId = (c?.authentication?.credentialId ?? "").trim();
    if (!credentialId) continue;
    const account = (c?.cloud?.accountId ?? c?.cloud?.tenant ?? "").trim();
    const key = `${lower(account)}|${lower(credentialId)}`;
    const entry = out.get(key) ?? { instances: new Set(), protocols: new Set(), disagreeingRows: 0 };
    const reading = sessionReadingOf(e);
    if (reading.kind === "instance") {
      entry.instances.add(lower(reading.instanceId));
      entry.protocols.add(reading.protocol);
    } else if (reading.kind === "disagrees") {
      entry.disagreeingRows += 1;
    }
    out.set(key, entry);
  }
  return out;
}

interface SummaryEntry {
  summaryId: string;
  first: string;
  last: string;
  firstMs: number;
  lastMs: number;
  objectCount: number;
  containerCount: number;
  containers: string[];
  sourceIp: string;
  role: string;
  credentialId: string;
  protocol: string;
  truncated: boolean;
}

function toEntry(group: BulkGroup, id: string, protocol: string): SummaryEntry | null {
  const firstMs = ms(group.first);
  const lastMs = ms(group.last);
  if (firstMs === null || lastMs === null) return null;
  return {
    summaryId: id,
    first: group.first,
    last: group.last,
    firstMs,
    lastMs,
    objectCount: group.objectCount,
    containerCount: group.containerCount,
    containers: group.containers.map(sanitizeForNote),
    sourceIp: sanitizeForNote(group.sourceIp),
    role: sanitizeForNote(group.principal),
    credentialId: sanitizeForNote(group.credentialId),
    protocol,
    truncated: group.truncated,
  };
}

/** Bulk-read summaries the shipped pass emitted, keyed on the (account, instance) whose credentials signed them. */
function buildSummaryIndex(events: readonly ForensicEvent[]): Map<string, SummaryEntry[]> {
  const index = new Map<string, SummaryEntry[]>();
  const ids = new Set(events.map((e) => e.id));
  // Recomputes the shipped pass's own grouping (default opts, as the merge chain calls it). This
  // clobbers cloudBulkRead's module-private lastDropped; safe only because summarizeBulkReads runs
  // EARLIER in the chain and is that value's sole reader, immediately after its own call.
  const groups = groupBulkReads(events);
  // summaryId's key is as discriminating as groupKey since #1356, so two distinct groups share an
  // id only on a hash collision — still an ambiguous pointer, still skipped rather than guessed.
  const idCounts = new Map<string, number>();
  for (const g of groups) {
    const id = summaryId(g);
    idCounts.set(id, (idCounts.get(id) ?? 0) + 1);
  }
  const agreement = sessionAgreementByCredential(events);
  for (const g of groups) {
    const id = summaryId(g);
    if (!ids.has(id) || (idCounts.get(id) ?? 0) > 1) continue;
    if (!g.credentialId || g.listOnly) continue;
    const agree = agreement.get(`${lower(g.account)}|${lower(g.credentialId)}`);
    // At least one positive reading, none contradicting it: silence never vetoes, disagreement always does.
    if (!agree || agree.disagreeingRows > 0 || agree.instances.size !== 1) continue;
    const instanceId = [...agree.instances][0];
    const protocol = [...agree.protocols].sort().join("/");
    const entry = toEntry(g, id, protocol);
    if (!entry) continue;
    const key = `${lower(g.account)}|${instanceId}`;
    index.set(key, [...(index.get(key) ?? []), entry]);
  }
  return index;
}

function overlapsWindow(entry: SummaryEntry, flowMs: number): boolean {
  return (
    entry.lastMs >= flowMs - SENSITIVE_DATA_WINDOW_MS && entry.firstMs <= flowMs + SENSITIVE_DATA_WINDOW_MS
  );
}

/** 0 when the flow lies inside the read window, else the distance to the nearest edge. */
function distance(entry: SummaryEntry, flowMs: number): number {
  if (flowMs >= entry.firstMs && flowMs <= entry.lastMs) return 0;
  return Math.min(Math.abs(flowMs - entry.firstMs), Math.abs(flowMs - entry.lastMs));
}

function containerWords(entry: SummaryEntry): string {
  const names = entry.containers.slice(0, MAX_CONTAINER_NAMES);
  const more = entry.containerCount > names.length ? ", …" : "";
  return names.length ? ` (${names.join(", ")}${more})` : "";
}

function keyWords(credentialId: string): string {
  return credentialId.length > MAX_KEY_CHARS ? `${credentialId.slice(0, MAX_KEY_CHARS)}…` : credentialId;
}

function formatEntry(entry: SummaryEntry, endpointIp: string): string {
  const what = entry.objectCount
    ? `${plural(entry.objectCount, "object")} across ${plural(entry.containerCount, "container")}`
    : plural(entry.containerCount, "container");
  const from = !entry.sourceIp
    ? "from an address the rows do not record"
    : lower(entry.sourceIp) === lower(endpointIp)
      ? `from ${entry.sourceIp} — the instance's own attributed address`
      : `from ${entry.sourceIp} — not the instance's attributed address`;
  const prefix = entry.truncated ? "; measured on a prefix of its records" : "";
  return (
    `bulk read summary ${entry.summaryId}, whose read window overlaps the ±24h around the flow — ${what}${containerWords(entry)} between ` +
    `${entry.first} and ${entry.last}, signed with instance-role credentials CloudTrail records as delivered to ` +
    `this instance (${entry.protocol}, role ${entry.role}, key ${keyWords(entry.credentialId)}), ${from}${prefix}`
  );
}

/** One fragment per attributed endpoint; exported so the truncation and overflow wording is unit-testable. */
export function formatSensitiveDataFragment(
  endpoint: AttributedEndpoint,
  entries: readonly SummaryEntry[],
  flowMs: number,
): string | null {
  const inWindow = entries.filter((e) => overlapsWindow(e, flowMs));
  if (inWindow.length === 0) return null;
  const byDistance = [...inWindow].sort((a, b) => distance(a, flowMs) - distance(b, flowMs));
  const shown = byDistance.slice(0, MAX_SUMMARIES_PER_ENDPOINT).sort((a, b) => a.firstMs - b.firstMs);
  const overflow = inWindow.length - shown.length;
  const overflowSuffix = overflow > 0 ? `, + ${overflow} more in window` : "";
  // The endpoint half is re-parsed from the sibling's note text — evidence-derived, sanitized like the rest.
  const ip = sanitizeForNote(endpoint.ip);
  const instanceId = sanitizeForNote(endpoint.instanceId);
  return (
    `${endpoint.label} ${ip} = ${instanceId}: ` +
    shown.map((e) => formatEntry(e, ip)).join(", ") +
    overflowSuffix +
    "; a read signed with this instance's credentials is not shown to be caused by this flow"
  );
}

export type { SummaryEntry as FlowSensitiveDataSummary };

export function correlateAwsFlowSensitiveData(events: readonly ForensicEvent[]): ForensicEvent[] {
  // No early return on an empty index: a case that loses its reads or summaries between merges
  // must still strip a now-stale note.
  const index = buildSummaryIndex(events);

  return events.map((e) => {
    if (!isFlowEvent(e)) return e;
    const stripped = (e.description ?? "").replace(FLOW_SENSITIVE_DATA_NOTE_RE, "");
    const accountId = e.canonical?.cloud?.accountId ?? "";
    const flowMs = ms(e.timestamp);
    if (!accountId || flowMs === null || !(e.description ?? "").includes(FLOW_ATTRIBUTION_MARKER)) {
      return stripped === e.description ? e : { ...e, description: stripped };
    }

    const fragments: string[] = [];
    for (const endpoint of parseAttributionEndpoints(e.description)) {
      const entries = index.get(`${lower(accountId)}|${lower(endpoint.instanceId)}`);
      if (!entries) continue;
      const fragment = formatSensitiveDataFragment(endpoint, entries, flowMs);
      if (fragment) fragments.push(fragment);
    }

    if (fragments.length === 0) {
      return stripped === e.description ? e : { ...e, description: stripped };
    }
    return {
      ...e,
      description: appendDerivedNote(stripped, FLOW_SENSITIVE_DATA_MARKER, fragments.join("; ")),
    };
  });
}
