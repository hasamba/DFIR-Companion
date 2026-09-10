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
import { addressReach } from "./publicAddress.js";

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

/**
 * Read events considered PER GROUP, bounding the work on a very large export.
 *
 * The first version capped the total records SEEN across all groups and called it a per-group cap,
 * so one principal could still hold every record — and the O(n²) scan below turned that into hours.
 * It also dropped every later group silently once the total was reached, in a pass whose whole
 * premise is disclosing what it could not see. The cap is now per group and it is reported.
 */
export const MAX_RECORDS_PER_GROUP = 20_000;

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

  const resource = c?.cloud?.resource ?? c?.target?.name ?? resourceFromDescription(e.description ?? "");
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

// The importers write "AWS <EventName> (<source>) by <principal> from <ip>", and the collaboration
// ones interpose a service: "M365 SharePoint: FileDownloaded by …". Reading the first word after
// the provider captured "SharePoint" for every one of those rows, so FileDownloaded,
// FileSyncDownloadedFull and FileAccessed — three of the actions READ_ACTION_RE lists — could
// never be reached. The optional service segment is skipped.
function actionFromDescription(d: string): string {
  const m =
    /^(?:AWS|GCP|Azure|M365|Google Workspace|Okta)\s+(?:([A-Za-z][\w ]*):\s*)?([A-Za-z][\w.]*)(\s+[A-Za-z]\w*)?/.exec(
      d ?? "",
    );
  if (!m) return "";
  // Azure writes a TWO-WORD operation — "Get Blob", "List Blobs" — and taking the first word alone
  // returned "Get", which matches no read action. The longer form is preferred when it is one of
  // the actions this pass knows; otherwise the single word stands.
  const one = m[2];
  const two = m[3] ? `${one}${m[3]}` : "";
  if (two && READ_ACTION_RE.test(two.trim())) return two.trim();
  return one;
}

/**
 * The object a non-AWS importer named, read back from its description.
 *
 * Only awsImport stamps `canonical.cloud.resource`, so without this the container and the object
 * were EMPTY for GCP, Azure, M365 and Workspace — which means the object count was zero and the
 * pass was blind to every provider but one. The importers do record the resource, in their own
 * wording: GCP and Azure append " on <resource>", M365 appends " → <target>".
 */
function resourceFromDescription(d: string): string {
  const text = d ?? "";
  const arrow = /\s→\s([^[]+?)(?:\s\[|$)/.exec(text)?.[1];
  if (arrow) return arrow.trim();
  const on = /\son\s([^[]+?)(?:\s\[|$)/.exec(text)?.[1];
  return on ? on.trim() : "";
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
  /** true when the group held more records than the cap and was measured on a prefix of them. */
  truncated: boolean;
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
  let bestCounts: { objects: number; containers: number } | null = null;
  for (const e of events) {
    const r = readCloudRecord(e);
    if (!r) continue;
    const list = byKey.get(groupKey(r)) ?? [];
    list.push(r);
    byKey.set(groupKey(r), list);
  }

  const out: BulkGroup[] = [];
  for (const records of byKey.values()) {
    records.sort((a, b) => a.time - b.time);
    // The cap is per group, and a group that hits it carries `truncated` so the finding says so.
    const list = records.slice(0, MAX_RECORDS_PER_GROUP);

    // ONE forward pass with two pointers, not a fresh scan from every index.
    //
    // The first version restarted a Set from each start index and walked forward — O(n²) with an
    // allocation per start. Measured on one group inside one window: 2,000 records took 1.2 s,
    // 10,000 took 21 s, 20,000 took 111 s. A real CloudTrail export reaches those sizes easily, and
    // this runs inside mergeDelta while it holds the state lock, so the whole server stops with it.
    //
    // Distinct objects in a sliding window need counts, not a set: an object leaving the left edge
    // is only gone when its last occurrence leaves. Hence the two count maps.
    const objectCounts = new Map<string, number>();
    const containerCounts = new Map<string, number>();
    let left = 0;
    let bestLeft = 0;
    let bestRight = -1;
    const add = (m: Map<string, number>, k: string) => m.set(k, (m.get(k) ?? 0) + 1);
    const drop = (m: Map<string, number>, k: string) => {
      const n = (m.get(k) ?? 0) - 1;
      if (n <= 0) m.delete(k);
      else m.set(k, n);
    };

    for (let right = 0; right < list.length; right++) {
      const r = list[right];
      if (r.object) add(objectCounts, `${r.container}/${r.object}`);
      if (r.container) add(containerCounts, r.container);
      while (list[right].time - list[left].time > windowMs) {
        const l = list[left];
        if (l.object) drop(objectCounts, `${l.container}/${l.object}`);
        if (l.container) drop(containerCounts, l.container);
        left++;
      }
      const score = objectCounts.size + containerCounts.size;
      if (!bestCounts || score > bestCounts.objects + bestCounts.containers) {
        // Only the BOUNDS and the counts are recorded here. Materialising the sample arrays on
        // every improvement put an O(n) copy inside the loop and gave back the quadratic cost the
        // sliding window was written to remove. The sample is built once, after the scan.
        bestLeft = left;
        bestRight = right;
        bestCounts = { objects: objectCounts.size, containers: containerCounts.size };
      }
    }
    if (!bestCounts || bestRight < 0) continue;
    if (bestCounts.objects < minObjects && bestCounts.containers < minContainers) {
      bestCounts = null;
      continue;
    }

    const window = list.slice(bestLeft, bestRight + 1);
    const sampleObjects: string[] = [];
    const containers: string[] = [];
    const seenObj = new Set<string>();
    const seenCon = new Set<string>();
    for (const r of window) {
      if (r.object && sampleObjects.length < SAMPLE_SIZE && !seenObj.has(`${r.container}/${r.object}`)) {
        seenObj.add(`${r.container}/${r.object}`);
        sampleObjects.push(`${r.container}/${r.object}`);
      }
      if (r.container && containers.length < SAMPLE_SIZE && !seenCon.has(r.container)) {
        seenCon.add(r.container);
        containers.push(r.container);
      }
    }

    const head = list[0];
    out.push({
      principal: head.principal,
      sourceIp: head.sourceIp,
      userAgent: head.userAgent,
      objectCount: bestCounts.objects,
      containerCount: bestCounts.containers,
      containers,
      sampleObjects,
      eventIds: window.slice(0, SAMPLE_SIZE * 2).map((r) => r.id),
      first: new Date(list[bestLeft].time).toISOString(),
      last: new Date(list[bestRight].time).toISOString(),
      // listOnly is judged on the WINDOW, not the whole group: a group whose densest window is
      // enumeration-only but which holds one object read elsewhere is not enumeration-only.
      listOnly: bestCounts.objects === 0 && window.every((r) => LIST_ONLY_RE.test(r.action)),
      truncated: records.length > MAX_RECORDS_PER_GROUP,
    });
    bestCounts = null;
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

/** The role NAME out of a role ARN, or the value as written when it is already a bare name. */
export function roleSegment(value: string): string {
  const v = (value ?? "").trim();
  if (!v) return "";
  const arn = /:role\/(?:.*\/)?([^/\s"']+)$/.exec(v);
  if (arn) return arn[1];
  return v.includes("/") ? (v.split("/").pop() ?? "") : v;
}

/** Read AssumeRole calls out of the timeline, so a bulk read can be tied back to who took the role. */
export function roleAssumptions(events: readonly ForensicEvent[]): RoleAssumption[] {
  const out: RoleAssumption[] = [];
  for (const e of events) {
    const action = e.canonical?.event?.action ?? actionFromDescription(e.description ?? "");
    if (!ASSUME_RE.test((action ?? "").trim())) continue;
    const time = Date.parse(e.timestamp ?? "");
    if (!Number.isFinite(time)) continue;
    const raw = e.canonical?.cloud?.resource ?? e.canonical?.target?.name ?? "";
    const by = e.canonical?.actor?.name ?? principalFromDescription(e.description ?? "");
    const role = roleSegment(raw);
    if (!role || !by) continue;
    out.push({ role, by: by.trim(), time });
  }
  return out;
}

/** The role an assumed-role principal is using, from its ARN. */
export function assumedRoleOf(principal: string): string {
  return /assumed-role\/([^/\s"']+)\//.exec(principal ?? "")?.[1] ?? "";
}

/** The assumption that produced this reader's session, when the timeline holds one. */
export function assumptionFor(
  group: BulkGroup,
  assumptions: readonly RoleAssumption[],
  windowMs = DEFAULT_WINDOW_MS,
): RoleAssumption | null {
  const start = Date.parse(group.first);
  if (!Number.isFinite(start)) return null;
  // The reader's identity is `arn:aws:sts::…:assumed-role/<role>/<session>`. The ROLE SEGMENT is
  // compared, not a substring of the whole string.
  //
  // A substring match was wrong in both directions and steerable from imported data: role `admin`
  // matched principal `…/superadmin-role/sess`, and role `a` matched almost anything. The pass then
  // raised the group to High and asserted in the report that one named person had opened another
  // person's session — a false causal attribution, from an attacker-nameable role.
  const readerRole = lower(assumedRoleOf(group.principal));
  if (!readerRole) return null;
  let best: RoleAssumption | null = null;
  for (const a of assumptions) {
    if (a.time > start || start - a.time > windowMs) continue;
    if (lower(a.role) !== readerRole) continue;
    if (!best || a.time > best.time) best = a;
  }
  return best;
}

// ─────────────────────────── grading ───────────────────────────

export interface BulkContext {
  /** Principals this environment expects to read in bulk — backup, replication, indexing. */
  expectedPrincipals?: readonly string[];
  /** Principals the case itself shows reading on a schedule. Computed, not configured. */
  recurringPrincipals?: readonly string[];
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
  if ((ctx.recurringPrincipals ?? []).some((p) => lower(p) === lower(group.principal))) return null;

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
  const reach = addressReach(group.sourceIp);
  if (reach === "public")
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
    // An address the code could not read must never be reported as "the source was internal". The
    // first version's two-state test did exactly that for every IPv6 and IPv4-mapped address, and
    // then printed "Volume alone is the only signal here" — an absence stated as a result.
    (reach === "unreadable" && group.sourceIp
      ? ` The source address recorded for these reads (${group.sourceIp}) could not be read, so whether they came from outside the cloud is unknown here rather than answered.`
      : "") +
    (group.truncated
      ? ` This principal produced more read records than one pass measures (${MAX_RECORDS_PER_GROUP}); the counts above are from the earliest of them and the real total is higher.`
      : "") +
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
 * Principals that read in bulk on several different days.
 *
 * This is the "environment context" the issue asks for, computed from the case rather than from a
 * setting nobody fills in. A backup job, a replication task and a search indexer read at scale
 * every night; an operator collecting data does it once. Three or more distinct days is a schedule.
 */
export function recurringPrincipals(events: readonly ForensicEvent[], minDays = 3): string[] {
  const days = new Map<string, Set<string>>();
  for (const e of events) {
    const r = readCloudRecord(e);
    if (!r) continue;
    const key = lower(r.principal);
    const day = new Date(r.time).toISOString().slice(0, 10);
    const set = days.get(key) ?? new Set<string>();
    set.add(day);
    days.set(key, set);
  }
  return [...days.entries()].filter(([, d]) => d.size >= minDays).map(([p]) => p);
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
  const coverage = objectLoggingEvent(events);
  if (groups.length === 0 && !coverage) return events as ForensicEvent[];

  const assumptions = ctx.assumptions ?? roleAssumptions(events);
  const recurring = ctx.recurringPrincipals ?? recurringPrincipals(events);
  const summaries: ForensicEvent[] = [];
  const replaced = new Set<string>();

  for (const group of groups) {
    const verdict = gradeGroup(group, { ...ctx, assumptions, recurringPrincipals: recurring });
    if (!verdict) continue;
    const id = summaryId(group);
    replaced.add(id);
    summaries.push({
      id,
      timestamp: group.first,
      // THE IDENTITY IS OUTSIDE THE MARKER, deliberately. correlate.ts keys exact-duplicate
      // detection on timestamp + cleanDescription + host, and cleanDescription strips the whole
      // `[cloud bulk read: …]` note — so when the identity lived only inside the note, every
      // summary cleaned to the same four words and two sessions that started in the same second
      // deduplicated into one. A data-theft finding disappeared from the record with no trace.
      description:
        `Cloud bulk read by ${group.principal}${group.sourceIp ? ` from ${group.sourceIp}` : ""}` +
        ` ${BULK_READ_MARKER} ${verdict.reason}]`,
      severity: verdict.severity,
      mitreTechniques: ["T1530", "T1213"],
      relatedFindingIds: [],
      sourceScreenshots: [],
      sources: ["Cloud bulk read"],
      count: group.objectCount || group.containerCount,
      ...(group.sourceIp ? { srcIp: group.sourceIp } : {}),
    });
  }
  if (coverage) {
    replaced.add(coverage.id);
    summaries.push(coverage);
  }
  if (summaries.length === 0) return events as ForensicEvent[];

  // A previous merge's summary for the same group is replaced, not duplicated: the group grows as
  // more of the export is imported, and two summaries of one session would read as two sessions.
  return [...events.filter((e) => !replaced.has(e.id)), ...summaries];
}

/** The id of the object-logging coverage event, so a re-merge replaces it. */
export const LOGGING_COVERAGE_ID = "cloud-object-logging-coverage";

/**
 * One event stating that object-level logging was off, when that is what the evidence shows.
 *
 * objectLoggingNote was an exported string builder no analyst ever saw. "No bulk read found" is the
 * wrong answer when nothing could have been found, and the only way to say so is to put it on the
 * timeline.
 */
export function objectLoggingEvent(events: readonly ForensicEvent[]): ForensicEvent | null {
  let reads = 0;
  let lists = 0;
  let firstTime = "";
  for (const e of events) {
    if (e.id === LOGGING_COVERAGE_ID) continue;
    const r = readCloudRecord(e);
    if (!r) continue;
    if (!firstTime) firstTime = e.timestamp ?? "";
    if (r.object) reads++;
    else if (LIST_ONLY_RE.test(r.action)) lists++;
  }
  if (reads > 0 || lists === 0) return null;
  return {
    id: LOGGING_COVERAGE_ID,
    timestamp: firstTime || new Date().toISOString(),
    description: `Cloud object logging is off ${BULK_READ_MARKER} ${objectLoggingNote(events)}]`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    sources: ["Coverage"],
  };
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
