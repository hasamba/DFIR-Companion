import type { ForensicEvent, InvestigationState } from "./stateTypes.js";
import { familyOf } from "./remediationShapes.js";
import type { TelemetryFamily } from "./remediationBoundary.js";
import type { ServedLocation } from "./servedLocation.js";

// A sensitive dump staged for retrieval through the victim's web server (#930 item 4): data
// leaving as a RESPONSE to an incoming request, read the opposite way from the archive→upload
// correlation, through the served locations the analyst declared.
//
// WHAT ONE RECORD ESTABLISHES, AND NOTHING MORE.
//   - A file/create or file/write row under a location's root opens a VERSION of a resource (with
//     the row's digest when it carries one); a file/delete row closes it. An MFT or listing row is
//     a POINT observation: the file existed at the row's own time. Amcache / ShimCache are
//     historical leads and place nothing in time.
//   - An access-log row whose request path maps through the location (fail-closed: query split
//     before decoding, ONE decoding pass, no encoded separators, no NUL, no escaping `..`, whole
//     segments compared under the declared case policy, a directory only through declared index
//     files, a vhost only when the row types it) is a RETRIEVAL REQUEST for that resource — one the
//     server answered with the status it logged.
//   - The status and the logged size establish what the server SAID: a body-permitting method with
//     200 / 206 and a numeric positive size → `response-size-recorded` (the response's size, not
//     the document's; never client receipt); 304 / 204 / 1xx are bodiless; 4xx / 5xx are an error
//     response whose size is the error page's; `-` is "size not recorded".
//   - A request is placed against the resource's versions: eligible when a version covers its
//     time, or a point observation sits at its time; otherwise "existence at request time not
//     established". A folded row (count > 1) whose interval straddles a version boundary is
//     ambiguous, said.
//   - Sensitivity comes only from the analyst (a confirmed relative path) or from content identity
//     (the covering version's digest among the declared sensitive digests). Corroborated
//     disclosure = a sensitive resource AND a response size recorded for a request a version
//     covers. A public location makes an unconfirmed resource a negative control; a confirmed one
//     is a conflict, surfaced.
//   - Every stage is evaluated over every admitted row; display caps apply after; a negative
//     reason is "not observed in a complete read" or "unknown: N rows unread / undated".
//
// Nothing is fetched and no server is contacted. A leak report has no importer here (said).

export const FILE_ROWS_PER_LOCATION_MAX = 5_000;
export const WEB_ROWS_PER_HOST_MAX = 20_000;
export const RESOURCES_PER_LOCATION_MAX = 500;
export const REQUESTS_NAMED_MAX = 20;

export type Stage =
  "suspected-exposure" | "retrieval-requested" | "response-size-recorded" | "corroborated-disclosure";

export interface ResourceVersion {
  from: string;
  to?: string;
  sha256?: string;
  openedBy: string;
  closedBy?: string;
}

export interface ResourceRequest {
  eventId: string;
  at: string;
  endAt?: string;
  count: number;
  client?: string;
  method: string;
  status?: number;
  size?: number;
  sizeWords: string;
  sizeRecorded: boolean;
  /** How the request sits against the resource's versions. */
  placement: "covered" | "point-observation" | "not-established" | "ambiguous";
}

export interface ServedResource {
  relativePath: string;
  url: string;
  versions: ResourceVersion[];
  observations: { eventId: string; at: string; sha256?: string }[];
  historicalLeads: string[];
  requests: ResourceRequest[];
  requestsTotal: number;
  sensitivity: "confirmed-by-analyst" | "content-identity" | "not-established";
  negativeControl: boolean;
  conflict?: string;
  stage: Stage;
  stageReason: string;
  evidence: Record<Stage, string[]>;
}

export interface LocationExposure {
  location: ServedLocation;
  resources: ServedResource[];
  resourcesNotShown: number;
  /** Requests under the prefix that map to a path with no file evidence — leads, no exposure. */
  unevidencedRequests: { path: string; count: number; statuses: number[]; eventIds: string[] }[];
  unevidencedRequestsTotal: number;
  unevidencedRequestsNotShown: number;
  unmapped: { count: number; reasons: Record<string, number> };
  gaps: string[];
  coverage: TelemetryFamily[];
  read: { fileRows: number; fileRowsUnread: number; webRows: number; webRowsUnread: number; undated: number };
}

export interface ServedExposure {
  locations: LocationExposure[];
  generated: string;
}

const hostKey = (h: string): string => h.trim().toLowerCase();

const ms = (iso: string | undefined): number | null => {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : null;
};

// ───────────────────────────── the path contract ─────────────────────────────

export type MapFailure =
  | "malformed escape"
  | "encoded separator"
  | "control character"
  | "escaping dot segment"
  | "outside the prefix"
  | "directory without index"
  | "vhost mismatch"
  | "foreign authority"
  | "ambiguous windows name";

/**
 * The relative path (below the root, `/`-separated) a request target maps to through a location,
 * or why it maps to nothing. Fail-closed on every ambiguity the design names.
 */
export function mapRequestPath(
  location: ServedLocation,
  target: string,
  rowHost?: string,
): { ok: true; relative: string; directory: boolean } | { ok: false; why: MapFailure } {
  let path = target;
  let authority = (rowHost ?? "").toLowerCase();
  if (!target.startsWith("/")) {
    // Absolute-form (a proxy log): the authority is the request's, and it must be a declared
    // vhost of this location — a forward-proxy row for a foreign origin maps to nothing.
    let url: URL;
    try {
      url = new URL(target);
    } catch {
      return { ok: false, why: "malformed escape" };
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return { ok: false, why: "foreign authority" };
    authority = url.hostname.toLowerCase();
    if (!location.vhost || authority !== location.vhost) return { ok: false, why: "foreign authority" };
    path = url.pathname;
  }
  if (location.vhost && authority !== location.vhost) return { ok: false, why: "vhost mismatch" };
  path = path.split("?")[0].split("#")[0];
  if (!/^(?:%[0-9A-Fa-f]{2}|[^%])*$/.test(path)) return { ok: false, why: "malformed escape" };
  if (/%2f|%5c|%00/i.test(path)) return { ok: false, why: "encoded separator" };
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return { ok: false, why: "malformed escape" };
  }
  if (/[\u0000-\u001f\u007f]/.test(decoded) || decoded.includes("\\"))
    return { ok: false, why: "control character" };
  const segments: string[] = [];
  for (const seg of decoded.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (!segments.length) return { ok: false, why: "escaping dot segment" };
      segments.pop();
      continue;
    }
    // A Windows name with a trailing dot or space is an alias of the name without it: ambiguous.
    if (location.caseInsensitive && /[. ]$/.test(seg)) return { ok: false, why: "ambiguous windows name" };
    segments.push(seg);
  }
  const prefixSegments = location.urlPrefix.split("/").filter(Boolean);
  const fold = (s: string) => (location.caseInsensitive ? s.toLowerCase() : s);
  for (const [i, p] of prefixSegments.entries()) {
    if (fold(segments[i] ?? "") !== fold(p)) return { ok: false, why: "outside the prefix" };
  }
  const relative = segments.slice(prefixSegments.length);
  const directory = decoded.endsWith("/") || relative.length === 0;
  if (directory && !location.indexFiles.length) return { ok: false, why: "directory without index" };
  return { ok: true, relative: relative.join("/"), directory };
}

/** A local file path's relative form below the location's root, or null when outside it. */
export function relativeUnderRoot(location: ServedLocation, localPath: string): string | null {
  const norm = (p: string) =>
    p
      .replace(/\//g, "\\")
      .replace(/\\{2,}/g, "\\")
      .replace(/\\+$/, "");
  const root = norm(location.localRoot);
  const file = norm(localPath);
  const fold = (s: string) => (location.caseInsensitive ? s.toLowerCase() : s);
  if (!fold(file).startsWith(fold(root) + "\\")) return null;
  return file.slice(root.length + 1).replace(/\\/g, "/");
}

const keyOf = (location: ServedLocation, relative: string) =>
  location.caseInsensitive ? relative.toLowerCase() : relative;

// ───────────────────────────── row readings ─────────────────────────────

const HISTORICAL = /amcache|shimcache|appcompat|prefetch/i;
const LISTING = /\bmft\b|mftecmd|\$mft|usn|directory listing|file listing/i;

type FileReading =
  | { kind: "open"; at: number; sha256?: string }
  | { kind: "close"; at: number }
  | { kind: "point"; at: number; sha256?: string }
  | { kind: "historical" };

function readFileRow(e: ForensicEvent): FileReading | null {
  const src = (e.sources ?? []).join(" ");
  const at = ms(e.timestamp);
  const sha = (e.sha256 ?? e.canonical?.file?.sha256)?.toLowerCase();
  // Provenance first: an MFT / listing row is a point observation whatever its canonical type
  // says (a "deleted" MFT record is an observation of a record, not a delete event); Amcache /
  // ShimCache / Prefetch are historical leads.
  if (HISTORICAL.test(src)) return { kind: "historical" };
  if (LISTING.test(src)) return at === null ? null : { kind: "point", at, ...(sha ? { sha256: sha } : {}) };
  const ev = e.canonical?.event;
  if (ev?.category === "file" && (ev.type === "create" || ev.type === "write" || ev.type === "modify"))
    return at === null ? null : { kind: "open", at, ...(sha ? { sha256: sha } : {}) };
  if (ev?.category === "file" && ev.type === "delete") return at === null ? null : { kind: "close", at };
  if (ev?.category === "file" && (ev.type === "observation" || ev.type === "listing"))
    return at === null ? null : { kind: "point", at, ...(sha ? { sha256: sha } : {}) };
  return null;
}

/** Whether a row is a file reading at all (before any bound is charged). */
const isFileReading = (e: ForensicEvent): boolean => {
  const src = (e.sources ?? []).join(" ");
  const ev = e.canonical?.event;
  return (
    HISTORICAL.test(src) ||
    LISTING.test(src) ||
    (ev?.category === "file" &&
      ["create", "write", "modify", "delete", "observation", "listing"].includes(ev.type))
  );
};

function sizeReading(
  method: string,
  status: number | undefined,
  size: number | undefined,
): { recorded: boolean; words: string } {
  const verb = method.toUpperCase();
  if (verb === "HEAD") return { recorded: false, words: "no body by definition (HEAD)" };
  if (verb !== "GET")
    return { recorded: false, words: `${verb}: a response to it is not the resource's body` };
  if (status === undefined) return { recorded: false, words: "status not recorded" };
  if (status === 304 || status === 204 || (status >= 100 && status < 200))
    return { recorded: false, words: `bodiless status ${status}` };
  if (status >= 400)
    return { recorded: false, words: `error response ${status}; a logged size is the error page's` };
  if (status >= 300) return { recorded: false, words: `redirect ${status}; no resource body` };
  if (status !== 200 && status !== 206)
    return { recorded: false, words: `status ${status} is not read as the resource's body` };
  if (size === undefined) return { recorded: false, words: "size not recorded (-)" };
  if (size <= 0) return { recorded: false, words: "size 0 logged" };
  return {
    recorded: true,
    words: `${status === 206 ? "partial (206) " : ""}response size ${size} logged — the response's size, not the document's; not client receipt`,
  };
}

// ───────────────────────────── the engine ─────────────────────────────

export function servedExposure(
  state: InvestigationState,
  locations: readonly ServedLocation[],
  now: string = new Date().toISOString(),
): ServedExposure {
  const events = state.forensicTimeline;
  const familiesByHost = new Map<string, Set<TelemetryFamily>>();
  for (const e of events) {
    if (!e.asset) continue;
    const f = familyOf(e);
    const k = hostKey(e.asset);
    if (f) (familiesByHost.get(k) ?? familiesByHost.set(k, new Set()).get(k)!).add(f);
  }
  return {
    locations: locations.map((location) => exposureFor(location, events, familiesByHost)),
    generated: now,
  };
}

function exposureFor(
  location: ServedLocation,
  events: readonly ForensicEvent[],
  familiesByHost: ReadonlyMap<string, Set<TelemetryFamily>>,
): LocationExposure {
  const host = hostKey(location.host);
  const onHost = (e: ForensicEvent) => hostKey(e.asset ?? "") === host;
  type Res = ServedResource & {
    versionsRaw: { at: number; kind: "open" | "close"; sha256?: string; id: string }[];
  };
  const resources = new Map<string, Res>();
  const resourceFor = (relative: string): Res => {
    const k = keyOf(location, relative);
    return (
      resources.get(k) ??
      resources
        .set(k, {
          relativePath: relative,
          url: `${location.urlPrefix}/${relative}`,
          versions: [],
          versionsRaw: [],
          observations: [],
          historicalLeads: [],
          requests: [],
          requestsTotal: 0,
          sensitivity: "not-established",
          negativeControl: false,
          stage: "suspected-exposure",
          stageReason: "",
          evidence: {
            "suspected-exposure": [],
            "retrieval-requested": [],
            "response-size-recorded": [],
            "corroborated-disclosure": [],
          },
        })
        .get(k)!
    );
  };
  const read = { fileRows: 0, fileRowsUnread: 0, webRows: 0, webRowsUnread: 0, undated: 0 };
  let anyFileRow = false;
  let anyWebRow = false;

  // File rows under the root: a row is charged to the bound only when it IS a file reading.
  for (const e of events) {
    if (!onHost(e) || e.canonical?.web) continue;
    const path = e.path ?? e.canonical?.file?.path;
    if (!path || !isFileReading(e)) continue;
    const relative = relativeUnderRoot(location, path);
    if (relative === null) continue;
    anyFileRow = true;
    if (read.fileRows >= FILE_ROWS_PER_LOCATION_MAX) {
      read.fileRowsUnread += 1;
      continue;
    }
    read.fileRows += 1;
    const reading = readFileRow(e);
    if (!reading) {
      read.undated += 1;
      continue;
    }
    const r = resourceFor(relative);
    if (reading.kind === "historical") r.historicalLeads.push(e.id);
    else if (reading.kind === "point")
      r.observations.push({
        eventId: e.id,
        at: e.timestamp,
        ...(reading.sha256 ? { sha256: reading.sha256 } : {}),
      });
    else
      r.versionsRaw.push({
        at: reading.at,
        kind: reading.kind,
        ...(reading.kind === "open" && reading.sha256 ? { sha256: reading.sha256 } : {}),
        id: e.id,
      });
  }
  // Versions from the open / close rows, in time order.
  for (const r of resources.values()) {
    // Same instant: the close comes first, so a delete-then-create at one time yields a version
    // that covers the boundary — never a choice made by event id.
    r.versionsRaw.sort((a, b) => a.at - b.at || (a.kind === b.kind ? 0 : a.kind === "close" ? -1 : 1));
    let current: ResourceVersion | null = null;
    for (const v of r.versionsRaw) {
      if (v.kind === "open") {
        if (current && !current.to) current.to = new Date(v.at).toISOString();
        current = {
          from: new Date(v.at).toISOString(),
          ...(v.sha256 ? { sha256: v.sha256 } : {}),
          openedBy: v.id,
        };
        r.versions.push(current);
      } else if (current && !current.to) {
        current.to = new Date(v.at).toISOString();
        current.closedBy = v.id;
      }
    }
  }

  // Web rows on the host.
  const unmapped: Record<string, number> = {};
  const unevidenced = new Map<
    string,
    { path: string; count: number; statuses: Set<number>; eventIds: string[] }
  >();
  for (const e of events) {
    const web = e.canonical?.web;
    if (!web || !onHost(e)) continue;
    anyWebRow = true;
    if (read.webRows >= WEB_ROWS_PER_HOST_MAX) {
      read.webRowsUnread += 1;
      continue;
    }
    read.webRows += 1;
    const at = ms(e.timestamp);
    if (at === null) {
      read.undated += 1;
      continue;
    }
    const mapped = mapRequestPath(location, web.target ?? "", web.host);
    if (!mapped.ok) {
      unmapped[mapped.why] = (unmapped[mapped.why] ?? 0) + 1;
      continue;
    }
    // A directory request resolves to the first declared index file that has evidence, else
    // to the first declared one (an unevidenced-path lead).
    let relativePath = mapped.relative;
    if (mapped.directory) {
      const candidates = location.indexFiles.map((f) => (relativePath ? `${relativePath}/${f}` : f));
      relativePath = candidates.find((c) => resources.has(keyOf(location, c))) ?? candidates[0];
    }
    const k = keyOf(location, relativePath);
    const r = resources.get(k);
    const size = sizeReading(web.method, web.statusCode, web.responseBodyLen);
    if (!r) {
      const u =
        unevidenced.get(k) ??
        unevidenced.set(k, { path: mapped.relative, count: 0, statuses: new Set(), eventIds: [] }).get(k)!;
      u.count += e.count ?? 1;
      if (web.statusCode !== undefined) u.statuses.add(web.statusCode);
      if (u.eventIds.length < REQUESTS_NAMED_MAX) u.eventIds.push(e.id);
      continue;
    }
    const endAt = e.endTimestamp ? ms(e.endTimestamp) : null;
    const req: ResourceRequest = {
      eventId: e.id,
      at: e.timestamp,
      ...(e.endTimestamp ? { endAt: e.endTimestamp } : {}),
      count: e.count ?? 1,
      ...(e.srcIp ? { client: e.srcIp } : {}),
      method: web.method,
      ...(web.statusCode !== undefined ? { status: web.statusCode } : {}),
      ...(web.responseBodyLen !== undefined ? { size: web.responseBodyLen } : {}),
      sizeWords: size.words,
      sizeRecorded: size.recorded,
      placement: placement(r, at, endAt),
    };
    r.requests.push(req);
  }

  // Stages, over every admitted row.
  const sensitivePaths = new Set(location.sensitive.map((p) => keyOf(location, p)));
  const sensitiveDigests = new Set(location.sensitiveDigests);
  for (const r of resources.values()) {
    r.requests.sort((a, b) => a.at.localeCompare(b.at) || a.eventId.localeCompare(b.eventId));
    r.requestsTotal = r.requests.reduce((n, q) => n + q.count, 0);
    const confirmed = sensitivePaths.has(keyOf(location, r.relativePath));
    // The sensitive digest binds to the version covering the request, or to a point observation
    // at exactly the request's time — never across a folded interval.
    const coveredWithSensitiveDigest = (q: ResourceRequest) => {
      if (q.placement === "ambiguous") return false;
      const t = ms(q.at)!;
      if (q.placement === "point-observation")
        return r.observations.some((o) => ms(o.at) === t && o.sha256 && sensitiveDigests.has(o.sha256));
      return r.versions.some(
        (v) => ms(v.from)! <= t && (!v.to || ms(v.to)! > t) && v.sha256 && sensitiveDigests.has(v.sha256),
      );
    };
    const identity =
      r.versions.some((v) => v.sha256 && sensitiveDigests.has(v.sha256)) ||
      r.observations.some((o) => o.sha256 && sensitiveDigests.has(o.sha256));
    r.sensitivity = confirmed ? "confirmed-by-analyst" : identity ? "content-identity" : "not-established";
    r.negativeControl = location.public && r.sensitivity === "not-established";
    if (location.public && r.sensitivity !== "not-established")
      r.conflict =
        "declared public location, but this resource is confirmed sensitive — the public declaration does not cover it";
    r.evidence["suspected-exposure"] = [
      ...r.versions.map((v) => v.openedBy),
      ...r.observations.map((o) => o.eventId),
    ];
    const eligible = r.requests.filter(
      (q) => q.placement === "covered" || q.placement === "point-observation",
    );
    r.evidence["retrieval-requested"] = eligible.map((q) => q.eventId);
    const sized = eligible.filter((q) => q.sizeRecorded);
    r.evidence["response-size-recorded"] = sized.map((q) => q.eventId);
    const disclosed = sized.filter((q) => confirmed || coveredWithSensitiveDigest(q));
    r.evidence["corroborated-disclosure"] = disclosed.map((q) => q.eventId);
    const incompleteNote =
      read.fileRowsUnread || read.webRowsUnread || read.undated
        ? ` — unknown beyond that: ${read.webRowsUnread + read.fileRowsUnread} row(s) unread, ${read.undated} undated`
        : " (a complete read)";
    if (disclosed.length) {
      r.stage = "corroborated-disclosure";
      r.stageReason = `a response size was logged for ${disclosed.length} request(s) while the resource was ${confirmed ? "confirmed sensitive by the analyst" : "the sensitive document by digest"}`;
    } else if (sized.length) {
      r.stage = "response-size-recorded";
      r.stageReason = `${sized.length} request(s) got a response with a logged size; sensitivity not established — confirm the path or add the document's digest${incompleteNote}`;
    } else if (eligible.length) {
      r.stage = "retrieval-requested";
      r.stageReason = `${eligible.length} request(s) reached the resource; none got a body-bearing response (${[...new Set(eligible.map((q) => q.sizeWords))].join("; ")})${incompleteNote}`;
    } else {
      r.stage = "suspected-exposure";
      r.stageReason = r.requests.length
        ? `${r.requests.length} request(s) mapped to the path but existence at request time is ${[...new Set(r.requests.map((q) => q.placement))].join(" / ")}${incompleteNote}`
        : `no request mapped to this path${incompleteNote}`;
    }
    // Display caps after the stages were judged.
    if (r.requests.length > REQUESTS_NAMED_MAX) r.requests = r.requests.slice(0, REQUESTS_NAMED_MAX);
  }
  const ordered = [...resources.values()].sort(
    (a, b) => stageRank(b.stage) - stageRank(a.stage) || a.relativePath.localeCompare(b.relativePath),
  );
  const shown = ordered.slice(0, RESOURCES_PER_LOCATION_MAX).map(({ versionsRaw: _v, ...rest }) => rest);
  const unevidencedList = [...unevidenced.values()]
    .sort((a, b) => b.count - a.count || a.path.localeCompare(b.path))
    .map((u) => ({
      path: u.path,
      count: u.count,
      statuses: [...u.statuses].sort((a, b) => a - b),
      eventIds: u.eventIds,
    }));
  const gaps: string[] = [];
  if (!anyFileRow)
    gaps.push(
      "no file rows under this root for this host in the case — served paths are not shown to have existed",
    );
  if (!anyWebRow) gaps.push("no web access-log rows for this host in the case — retrievals are not shown");
  if (read.fileRowsUnread || read.webRowsUnread)
    gaps.push(
      `read bound reached: ${read.fileRowsUnread} file row(s) and ${read.webRowsUnread} web row(s) unread`,
    );
  if (read.undated) gaps.push(`${read.undated} undated row(s) could not be placed`);
  return {
    location,
    resources: shown,
    resourcesNotShown: Math.max(0, ordered.length - shown.length),
    unevidencedRequests: unevidencedList.slice(0, RESOURCES_PER_LOCATION_MAX),
    unevidencedRequestsTotal: unevidencedList.length,
    unevidencedRequestsNotShown: Math.max(0, unevidencedList.length - RESOURCES_PER_LOCATION_MAX),
    unmapped: { count: Object.values(unmapped).reduce((n, c) => n + c, 0), reasons: unmapped },
    gaps,
    coverage: [...(familiesByHost.get(host) ?? [])],
    read,
  };
}

function placement(
  r: { versions: ResourceVersion[]; observations: { at: string }[] },
  at: number,
  endAt: number | null,
): ResourceRequest["placement"] {
  const covers = (t: number) => r.versions.some((v) => ms(v.from)! <= t && (!v.to || ms(v.to)! > t));
  // A folded row spans [first, last]: any version boundary inside the span makes it ambiguous.
  if (endAt !== null && endAt !== at) {
    const lo = Math.min(at, endAt);
    const hi = Math.max(at, endAt);
    const boundaries = r.versions.flatMap((v) => [ms(v.from)!, ...(v.to ? [ms(v.to)!] : [])]);
    if (boundaries.some((b) => b > lo && b <= hi)) return "ambiguous";
    if (covers(lo) !== covers(hi)) return "ambiguous";
  }
  if (covers(at)) return "covered";
  if (r.observations.some((o) => ms(o.at) === at)) return "point-observation";
  return "not-established";
}

function stageRank(s: Stage): number {
  return [
    "suspected-exposure",
    "retrieval-requested",
    "response-size-recorded",
    "corroborated-disclosure",
  ].indexOf(s);
}
