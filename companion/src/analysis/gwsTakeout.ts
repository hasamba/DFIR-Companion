// Google Takeout audit records (#931 item 11): the Reports API `takeout` application, read per
// event-specific schema — STARTED / COMPLETED / DOWNLOADED carry a job id; SCHEDULED describes a
// periodic export and carries none — and the job lifecycle joined only by tenant + TAKEOUT_ID
// over the records of ONE export inside the importer (the shape #983 landed on).
//
// What one row rests on, and what it never says:
//   - three stages, each from its own record: requested (STARTED), prepared (COMPLETED with
//     status COMPLETED — any other status is quoted and is not "prepared"), download started
//     (DOWNLOADED); a missing stage is "no <stage> record in this export";
//   - the destination is a recorded setting — nothing says "transferred" or "delivered";
//   - the audit actor, USER_EMAIL (the target user) and the literal INITIATED_BY value are three
//     facts, never compared; the integer times are kept as recorded — no epoch is assumed;
//   - a scheduled record never joins a job; a Drive folder named Takeout is never a stage.

import { createHash } from "node:crypto";
import type { Severity } from "./stateTypes.js";
import { boundedAggKey } from "./aggKey.js";
import { createCanonicalEvent } from "./canonicalEvent.js";
import type { TakeoutBlock, TakeoutLifecycleBlock } from "./canonicalGwsDrive.js";
import { readGwsParams, type GwsParam } from "./gwsOAuth.js";
import { breakHashRuns, showToken } from "./recordIdentity.js";
import { getCI, getPath, isObject, normalizeTime, str, type MappedEvent } from "./siemImport.js";

type Row = Record<string, unknown>;

export const GWS_TAKEOUT_MAX = 256;
const NAME_MAX = 80;
const PRODUCTS_MAX = 12;
const DESCRIPTION_MAX = 1400;
const RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
const DESTINATIONS: Record<string, string> = {
  EMAIL: "a download link",
  DRIVE: "Google Drive",
  BOX: "Box",
  DROPBOX: "Dropbox",
  ONEDRIVE: "Microsoft OneDrive",
  UNKNOWN: "location unknown",
};
const STATUSES = new Set(["CANCELED", "COMPLETED", "FAILED", "IN_PROGRESS"]);
const COVERAGE_NOTE = "Takeout audit retention is not in this evidence";
const BASIS =
  "records of this export only; joined through the tenant and the Takeout job id; delivery to the destination is not evidenced by these records";
const FORMAT_CHARS = /[\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;

const show = (v: string, max = NAME_MAX): string => {
  const shown = breakHashRuns(showToken(v.replace(FORMAT_CHARS, "")));
  return shown.length > max ? `${shown.slice(0, max - 1)}…` : shown;
};
const lower = (s: string): string => s.trim().toLowerCase();
const seg = (v: string): string => `${v.length}:${v}`;
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;
const find = (params: readonly GwsParam[], name: string): GwsParam | undefined =>
  params.find((p) => p.name.toUpperCase() === name);
const text = (params: readonly GwsParam[], name: string): string => {
  const p = find(params, name);
  return (p?.value ?? p?.intText ?? (p?.intValue !== undefined ? String(p.intValue) : "")).trim();
};
const products = (params: readonly GwsParam[]): string[] => {
  const p = find(params, "PRODUCTS_REQUESTED");
  const all = [...(p?.multiValue ?? []), ...(p?.value ? p.value.split(",") : [])]
    .map((s) => s.trim())
    .filter(Boolean);
  return [...new Set(all)].slice(0, PRODUCTS_MAX);
};
const destinationWords = (d: string): string =>
  d
    ? `destination recorded as ${show(d, 20)}${DESTINATIONS[d.toUpperCase()] ? ` (${DESTINATIONS[d.toUpperCase()]})` : " (not a documented value)"}`
    : "";
const statusWords = (s: string): string =>
  s
    ? `status ${show(s, 20)}${STATUSES.has(s.toUpperCase()) ? "" : " (not a documented value)"}`
    : "status not in this record";

// ───────────────────────────── the record reading ─────────────────────────────

export interface GwsTakeoutReading {
  stage: TakeoutBlock["stage"];
  severity: Severity;
  mitre: string[];
  /** `Takeout requested — job …` / `periodic Takeout scheduled — …`. */
  posture: string;
  /** The literal fields, in fixed order. */
  object: string;
  keySegment: string;
  jobId: string;
  block: TakeoutBlock;
}

/** Decode a `takeout` event, or null when the name is not one of the four documented events. */
export function decodeGwsTakeout(eventName: string, params: readonly GwsParam[]): GwsTakeoutReading | null {
  const name = eventName.trim().toUpperCase();
  const stage: TakeoutBlock["stage"] | null =
    name === "STARTED_USER_TAKEOUT"
      ? "requested"
      : name === "SCHEDULED_USER_TAKEOUT"
        ? "scheduled"
        : name === "COMPLETED_USER_TAKEOUT"
          ? "completed"
          : name === "DOWNLOADED_USER_TAKEOUT"
            ? "downloaded"
            : null;
  if (!stage) return null;
  const jobId = stage === "scheduled" ? "" : text(params, "TAKEOUT_ID");
  const userEmail = text(params, "USER_EMAIL");
  const initiatedBy = text(params, "INITIATED_BY");
  const destination = text(params, "TAKEOUT_DESTINATION");
  const status = text(params, "TAKEOUT_STATUS");
  const startTime = text(params, "START_TIME");
  const completionTime = text(params, "COMPLETION_TIME");
  const downloadTime = text(params, "DOWNLOAD_TIME");
  const intervalValue = text(params, "TAKEOUT_INTERVAL_VALUE");
  const intervalUnits = text(params, "TAKEOUT_INTERVAL_UNITS");
  const scheduleExpiration = text(params, "SCHEDULED_TAKEOUT_EXPIRATION");
  const prods = products(params);
  const job = jobId ? `job ${show(jobId, 60)}` : stage === "scheduled" ? "" : "job id not in this record";
  const prepared = stage === "completed" && status.toUpperCase() === "COMPLETED";
  const posture =
    stage === "requested"
      ? `Takeout requested — ${job}`
      : stage === "scheduled"
        ? `periodic Takeout scheduled — every ${show(intervalValue, 10) || "?"} ${show(intervalUnits, 10) || "(unit not recorded)"}; expiration ${show(scheduleExpiration, 20) || "not recorded"} (as recorded); ${statusWords(status)}`
        : stage === "completed"
          ? `Takeout ${prepared ? "prepared" : "not prepared"} — ${job} — ${statusWords(status)}`
          : `Takeout download started — ${job}`;
  const object = [
    userEmail ? `target user ${show(userEmail, 60)}` : "target user not in this record",
    ...(initiatedBy ? [`initiated by (as recorded) ${show(initiatedBy, 60)}`] : []),
    ...(prods.length ? [`products ${prods.map((p) => show(p, 20)).join(", ")}`] : []),
    ...(destination ? [destinationWords(destination)] : []),
    ...(startTime ? [`START_TIME ${show(startTime, 20)} (as recorded)`] : []),
    ...(completionTime ? [`COMPLETION_TIME ${show(completionTime, 20)} (as recorded)`] : []),
    ...(downloadTime ? [`DOWNLOAD_TIME ${show(downloadTime, 20)} (as recorded)`] : []),
  ].join("; ");
  const severity: Severity =
    stage === "downloaded" ? "High" : stage === "completed" ? (prepared ? "Medium" : "Low") : "Medium";
  const block: TakeoutBlock = {
    stage,
    ...(jobId ? { jobId } : {}),
    ...(userEmail ? { userEmail } : {}),
    ...(initiatedBy ? { initiatedBy } : {}),
    products: prods,
    ...(destination ? { destination } : {}),
    ...(status ? { status } : {}),
    ...(startTime ? { startTime } : {}),
    ...(completionTime ? { completionTime } : {}),
    ...(downloadTime ? { downloadTime } : {}),
    ...(intervalValue ? { intervalValue } : {}),
    ...(intervalUnits ? { intervalUnits } : {}),
    ...(scheduleExpiration ? { scheduleExpiration } : {}),
  };
  return {
    stage,
    severity,
    mitre: ["T1530"],
    posture,
    object,
    keySegment: `|takeout|${[stage, jobId, userEmail, status, destination, startTime, completionTime, downloadTime].map(seg).join("|")}`,
    jobId,
    block,
  };
}

// ───────────────────────────── the lifecycle ─────────────────────────────

interface Cited {
  time: number;
  locator: string;
}
interface Job {
  tenant: string;
  id: string;
  userEmail: string;
  initiatedBy: string;
  products: string[];
  destination: string;
  requested: (Cited & { by: string }) | null;
  completion: (Cited & { status: string }) | null;
  downloaded: (Cited & { by: string }) | null;
  further: number;
  first: number;
  top: Severity;
}

const ms = (s: string): number | null => {
  const t = Date.parse(normalizeTime(s));
  return Number.isFinite(t) ? t : null;
};
const iso = (t: number): string => new Date(t).toISOString();
const actorOf = (rec: Row): string =>
  str(getPath(rec, "actor.email")).trim() ||
  str(getPath(rec, "actor.profileId")).trim() ||
  "(no actor identity)";

/** One summary row per Takeout job whose id appears in the export's `takeout` records. */
export function gwsTakeoutLifecycles(records: readonly Row[]): MappedEvent[] {
  const jobs = new Map<string, Job>();
  const coverage = { records: 0, first: "", last: "" };
  const scanned: { rec: Row; reading: GwsTakeoutReading; time: number; locator: string; tenant: string }[] =
    [];
  records.forEach((raw, recordIndex) => {
    if (!isObject(raw)) return;
    const rec = raw;
    if (lower(str(getPath(rec, "id.applicationName"))) !== "takeout") return;
    const time = ms(str(getPath(rec, "id.time")));
    if (time === null) return;
    const t = normalizeTime(str(getPath(rec, "id.time")));
    coverage.records += 1;
    if (!coverage.first || t < coverage.first) coverage.first = t;
    if (!coverage.last || t > coverage.last) coverage.last = t;
    const events = getCI(rec, "events");
    (Array.isArray(events) ? events : []).forEach((e, eventIndex) => {
      if (!isObject(e)) return;
      const reading = decodeGwsTakeout(str(getCI(e, "name")), readGwsParams(e));
      if (!reading || !reading.jobId) return;
      scanned.push({
        rec,
        reading,
        time,
        locator: `record:${recordIndex}/event:${eventIndex}`,
        tenant: str(getPath(rec, "id.customerId")).trim(),
      });
    });
  });
  // Time order with the record position as the tie-breaker — the file's order never decides.
  scanned.sort((a, b) => a.time - b.time || a.locator.localeCompare(b.locator));
  for (const s of scanned) {
    const key = `${lower(s.tenant)}|${lower(s.reading.jobId)}`;
    const job =
      jobs.get(key) ??
      jobs
        .set(key, {
          tenant: s.tenant,
          id: s.reading.jobId,
          userEmail: "",
          initiatedBy: "",
          products: [],
          destination: "",
          requested: null,
          completion: null,
          downloaded: null,
          further: 0,
          first: s.time,
          top: "Info",
        })
        .get(key)!;
    const b = s.reading.block;
    // The earliest record supplies the display facts; a later record fills only what is still empty.
    if (!job.userEmail && b.userEmail) job.userEmail = b.userEmail;
    if (!job.initiatedBy && b.initiatedBy) job.initiatedBy = b.initiatedBy;
    if (!job.products.length && b.products.length) job.products = b.products;
    if (!job.destination && b.destination) job.destination = b.destination;
    if (RANK[s.reading.severity] > RANK[job.top]) job.top = s.reading.severity;
    const cited = { time: s.time, locator: s.locator };
    if (s.reading.stage === "requested" && !job.requested) job.requested = { ...cited, by: actorOf(s.rec) };
    else if (s.reading.stage === "completed" && !job.completion)
      job.completion = { ...cited, status: b.status ?? "" };
    else if (s.reading.stage === "downloaded" && !job.downloaded)
      job.downloaded = { ...cited, by: actorOf(s.rec) };
    else job.further += 1;
  }
  const rows = [...jobs.values()]
    .map((job) => ({ job, grade: gradeOf(job) }))
    .sort(
      (a, b) =>
        RANK[b.grade] - RANK[a.grade] || a.job.first - b.job.first || a.job.id.localeCompare(b.job.id),
    );
  const out = rows.slice(0, GWS_TAKEOUT_MAX).map(({ job, grade }) => summaryRow(job, grade, coverage));
  if (rows.length > GWS_TAKEOUT_MAX)
    out.push(omittedRow(rows.length - GWS_TAKEOUT_MAX, rows[GWS_TAKEOUT_MAX].grade));
  return out;
}

/** Download started → High; prepared → Medium; requested only → Medium; a failed / canceled completion with no download → Low. */
function gradeOf(job: Job): Severity {
  if (job.downloaded) return "High";
  if (job.completion) return job.completion.status.toUpperCase() === "COMPLETED" ? "Medium" : "Low";
  return "Medium";
}

function summaryRow(
  job: Job,
  grade: Severity,
  coverage: { records: number; first: string; last: string },
): MappedEvent {
  const prepared = job.completion?.status.toUpperCase() === "COMPLETED";
  const range = `(${plural(coverage.records, "record")} of this export, ${coverage.first.slice(0, 19)}Z → ${coverage.last.slice(0, 19)}Z)`;
  const parts = [
    job.requested
      ? `requested ${iso(job.requested.time)} by ${show(job.requested.by, 60)} (${job.requested.locator})${[
          job.products.length ? `products ${job.products.map((p) => show(p, 20)).join(", ")}` : "",
          job.destination ? destinationWords(job.destination) : "",
          job.initiatedBy ? `initiated by (as recorded) ${show(job.initiatedBy, 60)}` : "",
        ]
          .filter(Boolean)
          .map((w, i) => (i === 0 ? ` — ${w}` : `; ${w}`))
          .join("")}`
      : "no requested record in this export",
    job.completion
      ? prepared
        ? `prepared ${iso(job.completion.time)} — status COMPLETED (${job.completion.locator})`
        : `completion recorded ${iso(job.completion.time)} — ${statusWords(job.completion.status)}, not prepared (${job.completion.locator})`
      : "no prepared record in this export",
    job.downloaded
      ? `download started ${iso(job.downloaded.time)} by ${show(job.downloaded.by, 60)} (${job.downloaded.locator})`
      : `no download record in this export ${range}`,
    ...(job.further ? [`${plural(job.further, "further record")} of this job not individually named`] : []),
    ...(!job.completion && !job.downloaded ? ["requested; not shown to be prepared or downloaded"] : []),
    COVERAGE_NOTE,
  ];
  const head = `Google Workspace Takeout job: ${show(job.id, 60)}${job.userEmail ? ` (target user ${show(job.userEmail, 60)})` : ""}`;
  const description = `${head} [${parts.join("; ")}]`.slice(0, DESCRIPTION_MAX);
  const identity = createHash("sha256")
    .update(`${seg(job.tenant)}|${seg(job.id)}`)
    .digest("hex")
    .slice(0, 32);
  const block: TakeoutLifecycleBlock = {
    jobId: job.id,
    tenant: job.tenant,
    ...(job.userEmail ? { userEmail: job.userEmail } : {}),
    ...(job.initiatedBy ? { initiatedBy: job.initiatedBy } : {}),
    products: job.products,
    ...(job.destination ? { destination: job.destination } : {}),
    ...(job.requested
      ? { requested: { time: iso(job.requested.time), locator: job.requested.locator, by: job.requested.by } }
      : {}),
    ...(job.completion
      ? {
          completion: {
            time: iso(job.completion.time),
            locator: job.completion.locator,
            status: job.completion.status,
          },
        }
      : {}),
    ...(job.downloaded
      ? {
          downloaded: {
            time: iso(job.downloaded.time),
            locator: job.downloaded.locator,
            by: job.downloaded.by,
          },
        }
      : {}),
    furtherRecords: job.further,
    coverage,
    basis: BASIS,
  };
  const observed = iso(job.first);
  const cited = [job.requested, job.completion, job.downloaded]
    .filter((c): c is NonNullable<typeof c> => c !== null)
    .map((c) => c.locator);
  return {
    timestamp: normalizeTime(observed),
    description,
    severity: grade,
    mitre: ["T1530"],
    aggKey: boundedAggKey(`gws-takeout-job|${identity}`),
    sources: ["Google Workspace"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "takeout-lifecycle", action: "lifecycle", outcome: "success" },
      ...(job.userEmail ? { subject: { kind: "account", name: job.userEmail } } : {}),
      cloud: {
        provider: "google-workspace",
        ...(job.tenant ? { tenant: job.tenant } : {}),
        resource: job.id,
      },
      time: { observed, normalized: normalizeTime(observed) },
      evidence: { rawRecords: cited.map((l) => ({ source: "google-workspace", locator: l })) },
      producer: {
        importer: "google-workspace",
        parserVersion: "1",
        mappingVersion: "gws-takeout-job-v1",
        ruleVersions: ["gws-takeout-v1"],
      },
      takeoutLifecycle: block,
    }),
  };
}

function omittedRow(count: number, severity: Severity): MappedEvent {
  const description = `Google Workspace Takeout jobs — ${count} further job${count === 1 ? "" : "s"} with records in this export beyond the ${GWS_TAKEOUT_MAX} reported — not shown`;
  return {
    timestamp: "",
    description,
    severity,
    mitre: [],
    aggKey: boundedAggKey(`gws-takeout-job|omitted|${count}`),
    sources: ["Google Workspace"],
    canonical: createCanonicalEvent({
      event: { category: "cloud", type: "takeout-lifecycle", action: "omitted" },
      cloud: { provider: "google-workspace" },
      time: { observed: "", normalized: "" },
      evidence: { rawRecords: [{ source: "google-workspace", locator: "omitted" }] },
      producer: { importer: "google-workspace", parserVersion: "1", mappingVersion: "gws-takeout-job-v1" },
    }),
  };
}
