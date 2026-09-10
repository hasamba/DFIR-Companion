// Cloud bulk-read behaviour (#908 item 8).
//
// Data theft from object storage does not look like an intrusion. It looks like reading, and every
// read is an ordinary, successful, authorised API call. There is no failed login, no malware, no
// alert — a principal that is allowed to read the bucket reads the bucket, and the only thing that
// separates theft from work is HOW MUCH, HOW FAST, FROM WHERE, and BY WHOM.
//
// ─────────────────────────── ONE SUMMARY, NOT TEN THOUSAND ROWS ───────────────────────────
//
// The issue is explicit: "Emit a bounded summary with supporting evidence instead of promoting
// every object read." That is not a performance note. Promoting forty thousand GetObject calls to
// the forensic timeline would destroy the timeline as a working surface AND put forty thousand rows
// in front of the AI, which is precisely what the forensic/super-timeline boundary exists to
// prevent. The individual reads stay where they are. This pass adds ONE event per group of them,
// carrying the counts, the window, and a bounded sample of what was read.
//
// ─────────────────────────── WHAT THE LOGS DO NOT CONTAIN ───────────────────────────
//
// Two absences matter enough to state on every finding:
//
//   • S3 DATA EVENTS ARE OFF BY DEFAULT. Without them CloudTrail records ListBuckets and
//     ListObjects — the management calls — and NOT a single GetObject. An account with data events
//     disabled produces a log in which a complete exfiltration is invisible, and "no bulk read
//     found" means "not logged", not "did not happen".
//   • THERE ARE NO BYTE COUNTS. CloudTrail does not record response size for GetObject. The number
//     of objects is knowable; the volume of data is not. A finding that implied otherwise would be
//     inventing the one number an analyst most wants.
//
// ─────────────────────────── WHY BREADTH ALONE IS ONLY MEDIUM ───────────────────────────
//
// A backup job, a replication task, a search indexer and an analytics pipeline all read tens of
// thousands of objects on a schedule, from one principal, all night, every night. Breadth alone is
// therefore a question, not an answer, and it is graded Medium with the alternative named. It
// becomes High when something else about the reader is wrong: the role was assumed by a different
// principal shortly before, or the source address is outside the cloud, or the client is an
// interactive sync tool rather than the service that normally does this work.

import type { ForensicEvent, Severity } from "./stateTypes.js";

/** The marker this pass puts on its summary events. Stripped by correlate.ts before dedup keying. */
export const BULK_READ_MARKER = "[cloud bulk read:";

/** How many distinct objects in one window before the pattern is reported. */
export const MIN_OBJECTS = 50;

/** How many distinct containers — buckets, sites, drives — is enough on its own. */
export const MIN_CONTAINERS = 5;

/** The window the reads must fall inside. */
export const DEFAULT_WINDOW_MS = 60 * 60 * 1000;

/** Summary events one merge may produce, so a large export cannot flood the timeline. */
export const MAX_GROUPS = 20;

/** Sample object names carried on a summary, so the finding links to evidence without becoming it. */
export const SAMPLE_SIZE = 10;

/** Read events considered per group key, bounding the work on a very large export. */
export const MAX_RECORDS = 200_000;

/** Actions that READ object content or enumerate it. */
const READ_ACTION_RE =
  /^(?:getobject(?:acl|tagging|torrent)?|headobject|selectobjectcontent|listobjects(?:v2)?|listbucket|getbucket(?:acl|policy|location)?|copyobject|storage\.objects\.(?:get|list)|filedownloaded|filesyncdownloadedfull|fileaccessed|filepreviewed|download|view|blob\.(?:read|download)|get blob|list blobs)$/i;

/** Actions that ENUMERATE only. Present without object reads, they are the "data events are off" shape. */
const LIST_ONLY_RE = /^(?:listobjects(?:v2)?|listbucket|listbuckets|storage\.objects\.list|list blobs)$/i;

/** Clients a person drives, as opposed to the services that normally move data on a schedule. */
const INTERACTIVE_CLIENT_RE =
  /\b(?:rclone|cyberduck|s3browser|winscp|filezilla|transmit|mountainduck|s5cmd|aws-cli|boto3|botocore|s3cmd|curl|wget|python-requests|megasync|megacmd|rsync)\b/i;

export interface ReadRecord {
  id: string;
  time: number;
  /** The identity that made the call. */
  principal: string;
  sourceIp: string;
  userAgent: string;
  action: string;
  /** The container — bucket, site, drive. */
  container: string;
  /** The object, when object-level logging recorded one. */
  object: string;
}

const lower = (s: string): string => (s ?? "").trim().toLowerCase();

/**
 * Read one timeline event as a cloud object-read record.
 *
 * The canonical envelope is used when the importer stamped one, because those are the source's own
 * fields. Falling back to the description is a last resort and is kept narrow: this codebase has
 * already been bitten by a pass that re-parsed prose and went silent when the prose changed.
 */
export function readCloudRecord(e: ForensicEvent): ReadRecord | null {
  const c = e.canonical;
  const action = c?.event?.action ?? actionFromDescription(e.description ?? "");
  if (!action || !READ_ACTION_RE.test(action.trim())) return null;

  const time = Date.parse(e.timestamp ?? "");
  if (!Number.isFinite(time)) return null;

  const principal = c?.actor?.name ?? principalFromDescription(e.description ?? "");
  if (!principal) return null;

  const resource = c?.cloud?.resource ?? c?.target?.name ?? "";
  const { container, object } = splitResource(resource);

  return {
    id: e.id,
    time,
    principal: principal.trim(),
    sourceIp: (c?.network?.source?.address ?? e.srcIp ?? "").trim(),
    userAgent: clientFromDescription(e.description ?? ""),
    action: action.trim(),
    container,
    object,
  };
}

/** `bucket/key/parts` → container + object. A bare name is a container with no object recorded. */
export function splitResource(resource: string): { container: string; object: string } {
  const r = (resource ?? "").trim().replace(/^(?:s3|gs|az):\/\//i, "");
  if (!r) return { container: "", object: "" };
  const slash = r.indexOf("/");
  if (slash < 0) return { container: r, object: "" };
  return { container: r.slice(0, slash), object: r.slice(slash + 1) };
}

// The importers write "AWS <EventName> (<source>) by <principal> from <ip>". Read back only what
// that format guarantees, and return "" rather than a guess when it does not match.
function actionFromDescription(d: string): string {
  return /^(?:AWS|GCP|Azure|M365|Google Workspace)\s+([A-Za-z][\w.]*)/.exec(d ?? "")?.[1] ?? "";
}

function principalFromDescription(d: string): string {
  return /\bby\s+([^\s][^\n]*?)(?:\s+from\s|\s+in\s|\s*\[|$)/.exec(d ?? "")?.[1]?.trim() ?? "";
}

/**
 * The client that made the call.
 *
 * NO IMPORTER RETAINS CloudTrail's `userAgent` FIELD TODAY. The issue names the user agent as one of
 * the five dimensions to aggregate on, and it is genuinely not in the evidence this codebase
 * produces — so this reads what IS there (an explicit `[ua: …]` annotation, or a client name the
 * description happens to carry, which the identity and collaboration importers do include) and
 * returns "" otherwise. gradeGroup then SAYS the client was not recorded rather than grouping every
 * caller together and implying they were one client.
 */
export function clientFromDescription(d: string): string {
  const tagged = /\[ua:\s*([^\]]{1,120})\]/i.exec(d ?? "")?.[1];
  if (tagged) return tagged.trim();
  const known = INTERACTIVE_CLIENT_RE.exec(d ?? "");
  return known ? known[0] : "";
}

export interface BulkGroup {
  principal: string;
  sourceIp: string;
  userAgent: string;
  objectCount: number;
  containerCount: number;
  containers: string[];
  sampleObjects: string[];
  eventIds: string[];
  first: string;
  last: string;
  /** true when the group holds only enumeration calls — the shape of object logging being off. */
  listOnly: boolean;
}

function groupKey(r: ReadRecord): string {
  return `${lower(r.principal)}|${r.sourceIp}|${lower(r.userAgent)}`;
}

/**
 * Group object reads by who, from where, with what client, inside one window.
 *
 * The issue's five dimensions are principal, source, user agent, time and object breadth. The first
 * three are the key, time is the window, and breadth is what the group is measured on.
 */
export function groupBulkReads(
  events: readonly ForensicEvent[],
  opts: { windowMs?: number; minObjects?: number; minContainers?: number } = {},
): BulkGroup[] {
  const windowMs = opts.windowMs ?? DEFAULT_WINDOW_MS;
  const minObjects = opts.minObjects ?? MIN_OBJECTS;
  const minContainers = opts.minContainers ?? MIN_CONTAINERS;

  const byKey = new Map<string, ReadRecord[]>();
  let seen = 0;
  for (const e of events) {
    if (seen >= MAX_RECORDS) break;
    const r = readCloudRecord(e);
    if (!r) continue;
    seen++;
    const list = byKey.get(groupKey(r)) ?? [];
    list.push(r);
    byKey.set(groupKey(r), list);
  }

  const out: BulkGroup[] = [];
  for (const records of byKey.values()) {
    records.sort((a, b) => a.time - b.time);
    // The densest window, walked once. Distinct OBJECTS are counted, not calls: a retry loop that
    // reads one object two hundred times is one object, and counting the calls would manufacture a
    // finding out of a flaky client.
    let best: {
      objects: Set<string>;
      containers: Set<string>;
      ids: string[];
      from: number;
      to: number;
    } | null = null;
    for (let start = 0; start < records.length; start++) {
      const objects = new Set<string>();
      const containers = new Set<string>();
      const ids: string[] = [];
      let end = start;
      while (end < records.length && records[end].time - records[start].time <= windowMs) {
        const r = records[end];
        if (r.object) objects.add(`${r.container}/${r.object}`);
        if (r.container) containers.add(r.container);
        if (ids.length < SAMPLE_SIZE * 4) ids.push(r.id);
        end++;
      }
      const score = objects.size + containers.size;
      const bestScore = best ? best.objects.size + best.containers.size : -1;
      if (score > bestScore) {
        best = { objects, containers, ids, from: records[start].time, to: records[end - 1].time };
      }
    }
    if (!best) continue;
    if (best.objects.size < minObjects && best.containers.size < minContainers) continue;

    const head = records[0];
    out.push({
      principal: head.principal,
      sourceIp: head.sourceIp,
      userAgent: head.userAgent,
      objectCount: best.objects.size,
      containerCount: best.containers.size,
      containers: [...best.containers].slice(0, SAMPLE_SIZE),
      sampleObjects: [...best.objects].slice(0, SAMPLE_SIZE),
      eventIds: best.ids.slice(0, SAMPLE_SIZE * 2),
      first: new Date(best.from).toISOString(),
      last: new Date(best.to).toISOString(),
      listOnly: best.objects.size === 0 && records.every((r) => LIST_ONLY_RE.test(r.action)),
    });
  }

  // Biggest first, then bounded: an export covering a whole estate can hold many groups, and the
  // analyst needs the largest, not the first twenty alphabetically.
  out.sort((a, b) => b.objectCount + b.containerCount - (a.objectCount + a.containerCount));
  return out.slice(0, MAX_GROUPS);
}

// ─────────────────────────── role assumption ───────────────────────────

export interface RoleAssumption {
  /** The role that was assumed, as it appears in the reader's principal. */
  role: string;
  /** Who assumed it. */
  by: string;
  time: number;
}

const ASSUME_RE = /^(?:sts\.)?assumerole(?:withsaml|withwebidentity)?$/i;

/** Read AssumeRole calls out of the timeline, so a bulk read can be tied back to who took the role. */
export function roleAssumptions(events: readonly ForensicEvent[]): RoleAssumption[] {
  const out: RoleAssumption[] = [];
  for (const e of events) {
    const action = e.canonical?.event?.action ?? actionFromDescription(e.description ?? "");
    if (!ASSUME_RE.test((action ?? "").trim())) continue;
    const time = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(time)) continue;
    const role = e.canonical?.cloud?.resource ?? e.canonical?.target?.name ?? "";
    const by = e.canonical?.actor?.name ?? principalFromDescription(e.description ?? "");
    if (!role || !by) continue;
    out.push({ role: role.trim(), by: by.trim(), time });
  }
  return out;
}

/** The assumption that produced this reader's session, when the timeline holds one. */
export function assumptionFor(
  group: BulkGroup,
  assumptions: readonly RoleAssumption[],
  windowMs = DEFAULT_WINDOW_MS,
): RoleAssumption | null {
  const start = Date.parse(group.first);
  if (!Number.isFinite(start)) return null;
  const p = lower(group.principal);
  let best: RoleAssumption | null = null;
  for (const a of assumptions) {
    // Before the reads, inside the window, and the role name appears in the reader's identity.
    if (a.time > start || start - a.time > windowMs) continue;
    const role = lower(a.role);
    if (!role || !p.includes(role)) continue;
    if (!best || a.time > best.time) best = a;
  }
  return best;
}

// ─────────────────────────── grading ───────────────────────────

function isPublicIp(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((ip ?? "").trim());
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a > 255 || b > 255) return false;
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

export interface BulkContext {
  /** Principals this environment expects to read in bulk — backup, replication, indexing. */
  expectedPrincipals?: readonly string[];
  /** Timeline-derived role assumptions, so a session can be tied to who opened it. */
  assumptions?: readonly RoleAssumption[];
}

export interface BulkVerdict {
  severity: Severity;
  reason: string;
}

/**
 * Grade one group.
 *
 * Breadth is the question. Something else about the reader is what answers it.
 */
export function gradeGroup(group: BulkGroup, ctx: BulkContext = {}): BulkVerdict | null {
  const expected = (ctx.expectedPrincipals ?? []).map(lower);
  if (expected.some((p) => lower(group.principal) === p)) return null;

  const minutes = Math.max(1, Math.round((Date.parse(group.last) - Date.parse(group.first)) / 60000));
  const what = group.objectCount
    ? `${group.objectCount} distinct object(s) across ${group.containerCount} container(s)`
    : `${group.containerCount} container(s)`;

  const corroboration: string[] = [];
  const assumption = assumptionFor(group, ctx.assumptions ?? []);
  if (assumption) {
    corroboration.push(
      `the session was opened by ${assumption.by} assuming this role ${Math.max(1, Math.round((Date.parse(group.first) - assumption.time) / 60000))} minute(s) beforehand`,
    );
  }
  if (isPublicIp(group.sourceIp))
    corroboration.push(`the reads came from ${group.sourceIp}, an address outside the cloud`);
  if (INTERACTIVE_CLIENT_RE.test(group.userAgent)) {
    corroboration.push(
      `the client was ${group.userAgent.slice(0, 80)}, a tool a person drives rather than a scheduled service`,
    );
  }

  const severity: Severity = corroboration.length ? "High" : "Medium";
  const head =
    `${group.principal} read ${what} in ${minutes} minute(s)` +
    (group.sourceIp ? ` from ${group.sourceIp}` : "") +
    (group.userAgent ? ` using ${group.userAgent.slice(0, 80)}` : "") +
    ".";

  const why = corroboration.length
    ? ` What makes this more than volume: ${corroboration.join("; ")}.`
    : " Volume alone is the only signal here. Backup, replication, indexing and analytics jobs all read at this scale on a schedule — confirm against the expected workload for this principal before treating it as collection.";

  const limits =
    " Object-level logging records WHICH objects were read, never HOW MANY BYTES — the volume of data taken cannot be established from these logs." +
    (group.userAgent
      ? ""
      : " The client that made these calls was not retained by the import, so calls from different tools under one identity are grouped together here.") +
    (group.listOnly
      ? " This group holds enumeration calls only and no object reads, which is what an account with S3 data events disabled looks like: the listing is logged and the downloads are not. Absence of reads here is not evidence that none happened."
      : "");

  const sample = group.sampleObjects.length
    ? ` Sample of what was read: ${group.sampleObjects.slice(0, SAMPLE_SIZE).join(", ")}.`
    : group.containers.length
      ? ` Containers: ${group.containers.join(", ")}.`
      : "";

  const evidence = group.eventIds.length ? ` Contributing events: ${group.eventIds.join(", ")}.` : "";

  return { severity, reason: `${head}${why}${limits}${sample}${evidence}` };
}

// ─────────────────────────── the timeline pass ───────────────────────────

/** A stable id for a group's summary, so a re-merge replaces its summary instead of adding another. */
export function summaryId(group: BulkGroup): string {
  const key = `${lower(group.principal)}|${group.sourceIp}|${lower(group.userAgent)}`;
  let h = 5381;
  for (let i = 0; i < key.length; i++) h = ((h * 33) ^ key.charCodeAt(i)) >>> 0;
  return `bulkread-${h.toString(36)}`;
}

/**
 * Add one bounded summary per bulk-read group.
 *
 * The individual object reads are NOT touched and NOT promoted. They stay Info, in the
 * super-timeline, where forty thousand of them belong.
 */
export function summarizeBulkReads(
  events: readonly ForensicEvent[],
  ctx: BulkContext = {},
  opts: { windowMs?: number; minObjects?: number; minContainers?: number } = {},
): ForensicEvent[] {
  const groups = groupBulkReads(events, opts);
  if (groups.length === 0) return events as ForensicEvent[];

  const assumptions = ctx.assumptions ?? roleAssumptions(events);
  const summaries: ForensicEvent[] = [];
  const replaced = new Set<string>();

  for (const group of groups) {
    const verdict = gradeGroup(group, { ...ctx, assumptions });
    if (!verdict) continue;
    const id = summaryId(group);
    replaced.add(id);
    summaries.push({
      id,
      timestamp: group.first,
      description: `Cloud bulk read ${BULK_READ_MARKER} ${verdict.reason}]`,
      severity: verdict.severity,
      mitreTechniques: ["T1530", "T1213"],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: ["Cloud bulk read"],
      ...(group.sourceIp ? { srcIp: group.sourceIp } : {}),
    });
  }
  if (summaries.length === 0) return events as ForensicEvent[];

  // A previous merge's summary for the same group is replaced, not duplicated: the group grows as
  // more of the export is imported, and two summaries of one session would read as two sessions.
  return [...events.filter((e) => !replaced.has(e.id)), ...summaries];
}

/**
 * What the case's cloud logging could and could not show, for the analyst.
 *
 * S3 data events are off by default. Saying "no bulk read found" without saying that would present
 * a configuration gap as a negative result.
 */
export function objectLoggingNote(events: readonly ForensicEvent[]): string {
  let reads = 0;
  let lists = 0;
  for (const e of events) {
    const r = readCloudRecord(e);
    if (!r) continue;
    if (r.object) reads++;
    else if (LIST_ONLY_RE.test(r.action)) lists++;
  }
  if (reads > 0)
    return `Object-level logging is on: ${reads} object read(s) are recorded. Byte counts are not recorded by any provider's audit log, so the volume of data read cannot be established from them.`;
  if (lists > 0) {
    return `This case holds ${lists} object ENUMERATION call(s) and no object reads. That is what an account with S3 data events (or the equivalent) disabled looks like — listings are logged, downloads are not. No conclusion about what was downloaded can be drawn from these logs.`;
  }
  return "This case holds no cloud object-storage activity, so nothing here can show whether objects were read.";
}
