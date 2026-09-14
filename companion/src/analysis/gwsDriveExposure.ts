// Drive document exposure (#1064, second half of #931 item 11): a broadening sharing change on
// one document, joined in time order to the access records that follow — built over the records
// of ONE Google Workspace export, the `gwsOAuthLifecycle.ts` pattern (a summary row per resource,
// joined by tenant + a resource id, over un-aggregated observations).
//
// What one row rests on, and what it never says:
//   - a document is (tenant, doc_id); a `drive` event with neither joins nothing;
//   - only five channels ever open or close a window, because only these have a direction
//     `gwsDrive.ts` already established on the documented chain: link visibility (one per
//     document), a per-target ACL grant, a domain link scope, shared-drive membership (each keyed
//     on the target the record names), and inheritance — which never gates, because the record
//     never states the parent's own permissions. A channel whose key needs a value the record does
//     not carry (no target, no domain) never gates: two unidentified changes are two unrelated
//     facts, never each other's open or close. `change_owner` and `change_acl_editors` gate
//     nothing; every change appears in the chronological list regardless;
//   - one dimension's window closes only on ITS OWN narrowing — never another dimension's;
//   - events of one dimension are grouped into EXACT-timestamp buckets (never merely sorted, so
//     array order never changes the result); a bucket carrying both a broadening and a narrowing
//     of the same dimension is a conflict — the window's state is left unchanged, and the row says
//     so; a record with no parseable time opens or closes nothing and is counted, never dropped;
//   - an access record counts as "inside an exposure window" only with a time strictly after a
//     window's open and strictly before its close (a tie establishes no order — the #983 rule);
//   - an access is never said to be "through" a window, and an accessor's identity is never
//     compared with a sharing event's `target_user` — aliases and groups are not resolved here;
//   - the row's grade is the highest severity `gwsDrive.ts` already assigned to one of the
//     broadening events on a gating dimension — never invented from access presence.

import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type {
  DriveDirection,
  DriveExposureBlock,
  DriveSharingBlock,
} from "./canonicalGwsDrive.js";
import { decodeGwsDrive, type GwsDriveReading } from "./gwsDrive.js";
import { readGwsParams } from "./gwsOAuth.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { getCI, getPath, isObject, normalizeTime, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

export const GWS_EXPOSURE_MAX = 256;
// Practically unreachable for one document in one export; past them, further records are counted
// (`dimsBeyond` / `accessBeyond`) but not read. The cap applies in scan order, so which specific
// records are read past the bound is not independent of record order — a known, stated limit
// (the #997 TLS-graph fix later made that join order-independent; this one has not needed to).
const DIMENSIONS_MAX = 4096;
const ACCESS_PER_DOC_MAX = 65536;
const ACCESSORS_NAMED_MAX = 16;
const ACCESS_PER_ACCESSOR_MAX = 8;
const CHANGES_NAMED_MAX = 8;
const NAME_MAX = 80;
const DESCRIPTION_MAX = 1600;
const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
/** The strongest verb leads an accessor's line: a download outranks an edit outranks a view. */
const ACCESS_STRENGTH: Record<string, number> = {
  download: 4,
  download_forms_response: 4,
  copy: 3,
  source_copy: 3,
  email_as_attachment: 3,
  edit: 3,
  sync_item_content: 3,
  print: 2,
  access_item_content: 2,
  prefetch_item_content: 2,
  access_url: 2,
  preview: 1,
  view: 0,
};
/** The five gating channels; anything else (owner, acl-editors, inheritance) gates nothing. */
const GATING_EVENTS = new Set([
  "change_document_visibility",
  "change_user_access",
  "change_document_access_scope",
  "shared_drive_membership_change",
]);
const RETENTION_NOTE = "anonymous views are not logged; anonymous edits and downloads are";

const show = (v: string, max = NAME_MAX): string => {
  const shown = breakHashRuns(showToken(v));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
const lower = (s: string): string => s.trim().toLowerCase();
const text = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v)).trim();
const ms = (iso: string): number | null => {
  const t = Date.parse(normalizeTime(iso));
  return Number.isFinite(t) ? t : null;
};
const iso = (t: number): string => new Date(t).toISOString();
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

// ───────────────────────────── the accessor ─────────────────────────────

type AccessorKind = "named" | "application" | "none";

function classifyAccessor(rec: Row): { kind: AccessorKind; identity?: string } {
  const email = text(getPath(rec, "actor.email"));
  const profileId = text(getPath(rec, "actor.profileId"));
  const callerType = text(getPath(rec, "actor.callerType")).toUpperCase();
  const appId = text(getPath(rec, "actor.applicationInfo.oauthClientId"));
  const appName = text(getPath(rec, "actor.applicationInfo.applicationName"));
  if (callerType === "APPLICATION" || appId)
    return { kind: "application", identity: appId || appName || undefined };
  if (email || profileId) return { kind: "named", identity: email || profileId };
  return { kind: "none" };
}

// ───────────────────────────── the per-document accumulator ─────────────────────────────

interface DimEvent {
  time: number;
  locator: string;
  direction: DriveDirection;
  severity: Severity;
  mitre: string[];
  words: string;
}
interface ChangeLine {
  time: number;
  base: string;
  words: string;
}
interface AccessEvent {
  time: number | null;
  locator: string;
  meaning: string;
  strength: number;
  accessor: { kind: AccessorKind; identity?: string };
}
interface DocAgg {
  tenant: string;
  docId: string;
  docTitle: string;
  dims: Map<string, DimEvent[]>;
  dimsBeyond: number;
  changes: ChangeLine[];
  access: AccessEvent[];
  accessBeyond: number;
  timeNotEstablished: number;
}

function docFor(docs: Map<string, DocAgg>, tenant: string, docId: string): DocAgg {
  const k = `${lower(tenant)}|${docId}`;
  const d =
    docs.get(k) ??
    docs
      .set(k, {
        tenant,
        docId,
        docTitle: "",
        dims: new Map(),
        dimsBeyond: 0,
        changes: [],
        access: [],
        accessBeyond: 0,
        timeNotEstablished: 0,
      })
      .get(k)!;
  return d;
}

/** Only these five channels ever gate; the rest (owner, acl-editors, inheritance) never do. */
function dimensionKey(base: string, sharing: DriveSharingBlock): string | null {
  if (!GATING_EVENTS.has(base)) return null;
  switch (base) {
    case "change_document_visibility":
      return "visibility";
    case "change_user_access":
      return sharing.target ? `acl:${lower(sharing.target)}` : null;
    case "change_document_access_scope":
      return sharing.targetDomain ? `domain-scope:${lower(sharing.targetDomain)}` : null;
    case "shared_drive_membership_change":
      return sharing.target ? `shared-drive-member:${lower(sharing.target)}` : null;
    default:
      return null;
  }
}

const sharingWords = (r: GwsDriveReading): string => [r.direction, r.target].filter(Boolean).join(" ").trim();

// ───────────────────────────── the scan ─────────────────────────────

interface Scanned {
  rec: Row;
  locator: string;
  time: number | null;
  name: string;
}

function scan(records: readonly Row[]): Scanned[] {
  const out: Scanned[] = [];
  records.forEach((rec, recordIndex) => {
    if (!isObject(rec)) return;
    const app = lower(text(getPath(rec, "id.applicationName")));
    if (app !== "drive") return;
    const time = ms(text(getPath(rec, "id.time")));
    const events = getCI(rec, "events");
    (Array.isArray(events) ? events : []).forEach((e, eventIndex) => {
      if (!isObject(e)) return;
      out.push({ rec, locator: `record:${recordIndex}/event:${eventIndex}`, time, name: text(getCI(e, "name")) });
      void e;
    });
  });
  return out;
}

/** One summary row per document with a broadening change in this export. */
export function gwsDriveExposureRows(records: readonly Row[]): MappedEvent[] {
  const docs = new Map<string, DocAgg>();
  const coverage = { records: 0, first: "", last: "" };
  const seenRecords = new Set<Row>();

  records.forEach((rec, recordIndex) => {
    if (!isObject(rec)) return;
    const app = lower(text(getPath(rec, "id.applicationName")));
    if (app !== "drive") return;
    if (!seenRecords.has(rec)) {
      seenRecords.add(rec);
      coverage.records += 1;
      const t = normalizeTime(text(getPath(rec, "id.time")));
      if (!coverage.first || t < coverage.first) coverage.first = t;
      if (!coverage.last || t > coverage.last) coverage.last = t;
    }
    const time = ms(text(getPath(rec, "id.time")));
    const tenant = text(getPath(rec, "id.customerId"));
    const events = getCI(rec, "events");
    (Array.isArray(events) ? events : []).forEach((e, eventIndex) => {
      if (!isObject(e)) return;
      const name = text(getCI(e, "name"));
      const locator = `record:${recordIndex}/event:${eventIndex}`;
      const params = readGwsParams(e);
      const reading = decodeGwsDrive(name, params, classifyAccessor(rec).kind !== "none");
      if (!reading || !tenant || !reading.docId) return;
      const doc = docFor(docs, tenant, reading.docId);
      if (!doc.docTitle && reading.docTitle) doc.docTitle = reading.docTitle;
      if (time === null) {
        doc.timeNotEstablished += 1;
        return;
      }
      if (reading.kind === "sharing") {
        const sharing = (reading.block as { sharing: DriveSharingBlock }).sharing;
        if (sharing.reconciled || !sharing.primary) return;
        const base = lower(name).replace(/_hierarchy_reconciled$/, "");
        doc.changes.push({ time, base, words: sharingWords(reading) });
        const dimKey = dimensionKey(base, sharing);
        if (dimKey) {
          let bucket = doc.dims.get(dimKey);
          if (!bucket) {
            if (doc.dims.size >= DIMENSIONS_MAX) {
              doc.dimsBeyond += 1;
              return;
            }
            bucket = [];
            doc.dims.set(dimKey, bucket);
          }
          bucket.push({
            time,
            locator,
            direction: sharing.direction,
            severity: reading.severity,
            mitre: reading.mitre,
            words: sharingWords(reading),
          });
        }
      } else {
        if (doc.access.length >= ACCESS_PER_DOC_MAX) {
          doc.accessBeyond += 1;
          return;
        }
        doc.access.push({
          time,
          locator,
          meaning: reading.direction,
          strength: ACCESS_STRENGTH[lower(name)] ?? 0,
          accessor: classifyAccessor(rec),
        });
      }
    });
  });

  const rows = [...docs.values()]
    .map((doc) => buildRow(doc, coverage))
    .filter((r): r is { row: MappedEvent; grade: Severity } => r !== null)
    .sort((a, b) => RANK[b.grade] - RANK[a.grade]);

  const kept = rows.slice(0, GWS_EXPOSURE_MAX).map((r) => r.row);
  if (rows.length > GWS_EXPOSURE_MAX)
    kept.push(omittedRow(rows.length - GWS_EXPOSURE_MAX, rows[GWS_EXPOSURE_MAX].grade));
  return kept;
}

// ───────────────────────────── windows ─────────────────────────────

interface Interval {
  start: number;
  startLocator: string;
  end?: number;
  endLocator?: string;
}
interface Conflict {
  time: number;
  locators: string[];
}

function buildWindows(events: readonly DimEvent[]): { intervals: Interval[]; conflicts: Conflict[] } {
  const byTime = new Map<number, DimEvent[]>();
  for (const e of events) (byTime.get(e.time) ?? byTime.set(e.time, []).get(e.time)!).push(e);
  const times = [...byTime.keys()].sort((a, b) => a - b);
  const intervals: Interval[] = [];
  const conflicts: Conflict[] = [];
  let openStart: number | null = null;
  let openStartLocator = "";
  for (const t of times) {
    const bucket = byTime.get(t)!;
    const broaden = bucket.find((e) => e.direction === "broadens");
    const narrow = bucket.find((e) => e.direction === "narrows");
    if (broaden && narrow) {
      conflicts.push({ time: t, locators: [broaden.locator, narrow.locator] });
      continue;
    }
    if (broaden && openStart === null) {
      openStart = t;
      openStartLocator = broaden.locator;
    } else if (narrow && openStart !== null) {
      intervals.push({ start: openStart, startLocator: openStartLocator, end: t, endLocator: narrow.locator });
      openStart = null;
    }
  }
  if (openStart !== null) intervals.push({ start: openStart, startLocator: openStartLocator });
  return { intervals, conflicts };
}

interface LabeledInterval extends Interval {
  dimension: string;
}

const windowsOpenAt = (all: readonly LabeledInterval[], t: number): LabeledInterval[] =>
  all.filter((iv) => t > iv.start && (iv.end === undefined || t < iv.end));

// ───────────────────────────── the row ─────────────────────────────

function buildRow(doc: DocAgg, coverage: { records: number; first: string; last: string }): { row: MappedEvent; grade: Severity } | null {
  const allIntervals: LabeledInterval[] = [];
  const allConflicts: { dimension: string; time: number; locators: string[] }[] = [];
  let topSeverity: Severity = "Info";
  const mitreSet = new Set<string>();
  for (const [dimension, events] of doc.dims) {
    const { intervals, conflicts } = buildWindows(events);
    for (const iv of intervals) allIntervals.push({ ...iv, dimension });
    for (const c of conflicts) allConflicts.push({ dimension, time: c.time, locators: c.locators });
    for (const e of events)
      if (e.direction === "broadens") {
        if (RANK[e.severity] > RANK[topSeverity]) topSeverity = e.severity;
        for (const m of e.mitre) mitreSet.add(m);
      }
  }
  if (allIntervals.length === 0 && allConflicts.length === 0) return null;

  const firstBroadening = allIntervals.length ? Math.min(...allIntervals.map((iv) => iv.start)) : null;
  const firstConflict = allConflicts.length ? Math.min(...allConflicts.map((c) => c.time)) : null;

  // Accessors: only access records whose time falls inside the union of open windows. A distinct
  // accessor beyond the cap is counted once (`accessorsBeyond`), not once per its access records.
  const accessors = new Map<string, { kind: AccessorKind; identity?: string; records: { time: number; locator: string; meaning: string; strength: number; windowsOpen: string[] }[] }>();
  const accessorsBeyondKeys = new Set<string>();
  for (const a of doc.access) {
    if (a.time === null) continue;
    const open = windowsOpenAt(allIntervals, a.time);
    if (open.length === 0) continue;
    const key = `${a.accessor.kind}|${a.accessor.identity ?? ""}`;
    let acc = accessors.get(key);
    if (!acc) {
      if (accessors.size >= ACCESSORS_NAMED_MAX) {
        accessorsBeyondKeys.add(key);
        continue;
      }
      acc = { kind: a.accessor.kind, identity: a.accessor.identity, records: [] };
      accessors.set(key, acc);
    }
    acc.records.push({
      time: a.time,
      locator: a.locator,
      meaning: a.meaning,
      strength: a.strength,
      windowsOpen: open.map((iv) => `${iv.dimension} (opened ${iso(iv.start)})`),
    });
  }
  const accessorsBeyond = accessorsBeyondKeys.size;

  const changes = [...doc.changes].sort((a, b) => a.time - b.time);
  const head = `Google Workspace Drive exposure: ${show(doc.docTitle || "(untitled)", 60)} (doc ${show(doc.docId, 50)})`;

  const windowWords = allIntervals
    .sort((a, b) => a.start - b.start)
    .map(
      (iv) =>
        `${iv.dimension}: opened ${iso(iv.start)}${iv.end !== undefined ? ` → narrowed ${iso(iv.end)}` : " — no narrowing record after this broadening in this export"}`,
    );
  const conflictWords = allConflicts.map(
    (c) => `conflicting same-instant sharing changes on ${c.dimension} at ${iso(c.time)} — window state not changed by this instant`,
  );
  const changeWords = changes
    .slice(0, CHANGES_NAMED_MAX)
    .map((c) => `${c.base} ${iso(c.time)}: ${c.words}`);
  const changesBeyond = Math.max(0, changes.length - CHANGES_NAMED_MAX);

  const accessorLines = [...accessors.values()].map((a) => {
    const recs = [...a.records].sort((x, y) => y.strength - x.strength || x.time - y.time);
    const shown = recs.slice(0, ACCESS_PER_ACCESSOR_MAX);
    const beyond = recs.length - shown.length;
    const who = a.identity ? show(a.identity, 60) : a.kind === "none" ? "no actor identity in this record" : "(unnamed)";
    const label = a.kind === "application" ? `an application (client ${who})` : who;
    const lines = shown.map(
      (r) => `${r.meaning} ${iso(r.time)} (windows open at that time: ${r.windowsOpen.join(", ")})`,
    );
    return `${label}: ${lines.join("; ")}${beyond ? ` [+${beyond} more access]` : ""}`;
  });

  const accessTotal = doc.access.length + doc.accessBeyond;
  const accessSection =
    accessorLines.length > 0
      ? `access after the first broadening${firstBroadening !== null ? ` (${iso(firstBroadening)})` : ""}: ${accessorLines.join("; ")} — access through a specific share is not established; the accessor and the share target are not compared`
      : `no access record fell inside an exposure window, among the ${plural(accessTotal, "access record")} of this export`;

  const parts = [
    head,
    changeWords.length ? `changes in time order: ${changeWords.join("; ")}${changesBeyond ? ` [+${changesBeyond} more]` : ""}` : "",
    windowWords.length ? `windows: ${windowWords.join("; ")}` : "",
    conflictWords.join("; "),
    accessSection,
    RETENTION_NOTE,
    `${plural(accessTotal, "access record")}${doc.accessBeyond ? ` (${plural(doc.accessBeyond, "record")} beyond the retained bound, not read)` : ""}, ${plural(changes.length, "sharing change")} of this document in this export (${coverage.first.slice(0, 10)} → ${coverage.last.slice(0, 10)})${doc.timeNotEstablished ? `; ${plural(doc.timeNotEstablished, "record")} with an unparseable time — excluded from ordering` : ""}${doc.dimsBeyond ? `; ${plural(doc.dimsBeyond, "dimension")} beyond the retained bound, not read` : ""}`,
  ].filter(Boolean);
  const description = parts.join(" — ").slice(0, DESCRIPTION_MAX);

  const grade = topSeverity;
  const block: DriveExposureBlock = {
    docId: doc.docId,
    tenant: doc.tenant,
    ...(doc.docTitle ? { docTitle: doc.docTitle } : {}),
    windows: allIntervals
      .sort((a, b) => a.start - b.start)
      .map((iv) => ({
        dimension: iv.dimension,
        opened: { time: iso(iv.start), locator: iv.startLocator, words: iv.dimension },
        ...(iv.end !== undefined ? { closed: { time: iso(iv.end), locator: iv.endLocator!, words: iv.dimension } } : {}),
      })),
    windowsBeyond: doc.dimsBeyond,
    conflicts: allConflicts.map((c) => ({ dimension: c.dimension, time: iso(c.time), locators: c.locators })),
    accessors: [...accessors.values()].map((a) => ({
      kind: a.kind,
      ...(a.identity ? { identity: a.identity } : {}),
      records: a.records
        .slice()
        .sort((x, y) => y.strength - x.strength || x.time - y.time)
        .slice(0, ACCESS_PER_ACCESSOR_MAX)
        .map((r) => ({ time: iso(r.time), locator: r.locator, meaning: r.meaning, windowsOpen: r.windowsOpen })),
      recordsBeyond: Math.max(0, a.records.length - ACCESS_PER_ACCESSOR_MAX),
    })),
    accessorsBeyond,
    accessRecordsTotal: accessTotal,
    timeNotEstablished: doc.timeNotEstablished,
    coverage,
    basis:
      "records of this export only; joined through the tenant and doc_id; each dimension's window is independent; an access inside a window is never said to be through it",
  };

  const identity = `gws-drive-exposure|${lower(doc.tenant)}|${doc.docId}`;
  const observed =
    firstBroadening !== null ? iso(firstBroadening) : firstConflict !== null ? iso(firstConflict) : coverage.first;
  const locators = [
    ...allIntervals.flatMap((iv) => [iv.startLocator, ...(iv.endLocator ? [iv.endLocator] : [])]),
    ...allConflicts.flatMap((c) => c.locators),
    ...[...accessors.values()].flatMap((a) => a.records.map((r) => r.locator)),
  ].slice(0, 256);

  const row: MappedEvent = {
    timestamp: normalizeTime(observed),
    description,
    severity: grade,
    mitre: [...mitreSet],
    aggKey: boundedAggKey(identity.toLowerCase()),
    sources: ["Google Workspace"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "drive-exposure", action: "exposure-join", outcome: "success" },
      object: { kind: "file", id: doc.docId, ...(doc.docTitle ? { name: doc.docTitle } : {}) },
      cloud: { provider: "google-workspace", tenant: doc.tenant, resource: doc.docId },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: {
        rawRecords: (locators.length ? locators : ["none"]).map((l) => ({
          source: "google-workspace-reports",
          locator: l,
        })),
      },
      producer: {
        importer: "google-workspace",
        parserVersion: "1",
        mappingVersion: "gws-drive-exposure-v1",
        ruleVersions: ["gws-drive-exposure-v1"],
      },
      driveExposure: block,
    }),
  };
  return { row, grade };
}

function omittedRow(count: number, severity: Severity): MappedEvent {
  const description = `Google Workspace Drive exposure: ${count} further document${count === 1 ? "" : "s"} with an exposure join in this export beyond the ${GWS_EXPOSURE_MAX} reported — not shown`;
  return {
    timestamp: "",
    description,
    severity,
    mitre: [],
    aggKey: boundedAggKey(`gws-drive-exposure|omitted|${count}`),
    sources: ["Google Workspace"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "drive-exposure", action: "omitted" },
      cloud: { provider: "google-workspace" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "google-workspace-reports", locator: "omitted" }] },
      producer: { importer: "google-workspace", parserVersion: "1", mappingVersion: "gws-drive-exposure-v1" },
    }),
  };
}
