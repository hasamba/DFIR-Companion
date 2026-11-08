// The S3 trail source (#2313): one CloudTrail object per page, saved byte for byte (`.json.gz` as
// CloudTrail wrote it), with its S3 version id when the bucket is versioned.
//
// The walk is a fixed order of CELLS — trail folder × region × UTC day — and the page token is the
// cell plus the last key read in it (`StartAfter`), so a token never expires and means the same
// after a restart. Only days the window touches are listed, plus CLOUDTRAIL_DELIVERY_HORIZON_MS past
// its end (CloudTrail usually delivers within 5–15 minutes, but late files happen), never past now.
// Within a day an object is taken when the minute in its name falls in [the start's minute, end +
// horizon] — rounded so the starting minute and the whole last minute are kept. Files delivered
// later than the horizon are not collected; the source's notice says so in the result.
//
// A page's token is set only when ANOTHER object follows (the look-ahead is listed, and cached,
// before the object is read), so the last object ends the sub-window. An object the cloud refuses
// to hand over — a KMS-encrypted trail without kms:Decrypt — is a SkippedItemError: the result names
// it, and the walk goes on.

import { gunzipSync } from "node:zlib";
import { GetObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import {
  CursorExpiredError,
  SkippedItemError,
  type CollectPage,
  type CollectPageRequest,
} from "../collectTypes.js";
import { errorName, sendAws, awsReason, type AwsCollectClients } from "./awsCollectTypes.js";
import type { TrailDiscovery, TrailRoot } from "./awsTrailDiscovery.js";

/** How far past the window's end a delivered file is still looked for (disclosed in the result). */
export const CLOUDTRAIL_DELIVERY_HORIZON_MS = 24 * 60 * 60_000;
const MINUTE_MS = 60_000;
/** A trail object is small (CloudTrail rolls files every ~5 min); counting its records stops here. */
const COUNT_MAX_BYTES = 256 * 1024 * 1024;
const DAY_MS = 86_400_000;
const LISTING_CACHE = 8;

interface Cell {
  bucket: string;
  root: string;
  region: string;
  day: string;
}

interface Position {
  cell: number;
  after?: string;
}

interface S3Token {
  b: string;
  p: string;
  r: string;
  d: string;
  k: string;
}

interface Listed {
  Contents?: { Key?: string; Size?: number }[];
  IsTruncated?: boolean;
}

const dayOf = (ms: number): string => new Date(ms).toISOString().slice(0, 10).replace(/-/g, "/");

/** The newest delivery minute a file of the window is taken from: end + horizon, never past now. */
function lastDelivery(window: { end: string }, nowMs: number): number {
  return Math.min(Date.parse(window.end) + CLOUDTRAIL_DELIVERY_HORIZON_MS, nowMs);
}

/** The UTC days `[start, min(end + horizon, now)]` touches, as `YYYY/MM/DD`. Pure. */
export function trailDays(window: { start: string; end: string }, nowMs: number = Date.now()): string[] {
  const start = Date.parse(window.start);
  const last = Math.max(start, lastDelivery(window, nowMs));
  const days: string[] = [];
  for (let d = Math.floor(start / DAY_MS) * DAY_MS; d <= last; d += DAY_MS) days.push(dayOf(d));
  return days;
}

/** The delivery time in a CloudTrail object name (`…_20261001T1005Z_…`), or null. Pure. */
export function deliveredAt(key: string): number | null {
  const m = /_(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})Z[_.]/.exec(key.slice(key.lastIndexOf("/") + 1));
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]) : null;
}

function inWindow(key: string, window: { start: string; end: string }): boolean {
  if (!/\.json(\.gz)?$/.test(key)) return false;
  const at = deliveredAt(key); // minute resolution
  if (at === null) return true; // no time in the name: the day folder is the only bound
  const first = Math.floor(Date.parse(window.start) / MINUTE_MS) * MINUTE_MS;
  return at >= first && at <= Date.parse(window.end) + CLOUDTRAIL_DELIVERY_HORIZON_MS;
}

export function trailCells(roots: readonly TrailRoot[], days: readonly string[], region?: string): Cell[] {
  return roots.flatMap((r) =>
    r.regions
      .filter((reg) => !region || reg === region)
      .flatMap((reg) => days.map((day) => ({ bucket: r.bucket, root: r.root, region: reg, day }))),
  );
}

const prefixOf = (c: Cell): string => `${c.root}CloudTrail/${c.region}/${c.day}/`;

function encodeToken(c: Cell, key: string): string {
  return JSON.stringify({ b: c.bucket, p: c.root, r: c.region, d: c.day, k: key } satisfies S3Token);
}

function positionOf(cells: readonly Cell[], token?: string): Position {
  if (!token) return { cell: 0 };
  let t: S3Token;
  try {
    t = JSON.parse(token) as S3Token;
  } catch {
    throw new CursorExpiredError("unreadable S3 trail token");
  }
  const cell = cells.findIndex(
    (c) => c.bucket === t.b && c.root === t.p && c.region === t.r && c.day === t.d,
  );
  // The trail's folders changed since the token was made: start the window over (dedup absorbs it).
  if (cell < 0 || typeof t.k !== "string") throw new CursorExpiredError("the trail folders changed");
  return { cell, after: t.k };
}

/** The S3 walk of one session: the listings it has read, so the look-ahead is never listed twice. */
export class TrailObjectWalk {
  private readonly listings = new Map<string, Listed>();

  constructor(private readonly clients: AwsCollectClients) {}

  private async list(c: Cell, after: string | undefined, signal?: AbortSignal): Promise<Listed> {
    const key = `${c.bucket}\n${prefixOf(c)}\n${after ?? ""}`;
    const hit = this.listings.get(key);
    if (hit) return hit;
    const listed = await sendAws<Listed>(
      this.clients.s3,
      new ListObjectsV2Command({
        Bucket: c.bucket,
        Prefix: prefixOf(c),
        ...(after ? { StartAfter: after } : {}),
      }),
      signal,
    );
    if (this.listings.size >= LISTING_CACHE) this.listings.delete(this.listings.keys().next().value!);
    this.listings.set(key, listed);
    return listed;
  }

  /** The next object in the window at or after `from`, or null at the end of the walk. */
  async next(
    cells: readonly Cell[],
    from: Position,
    window: { start: string; end: string },
    signal?: AbortSignal,
  ): Promise<{ cell: number; key: string } | null> {
    for (let i = from.cell; i < cells.length; i++) {
      let after = i === from.cell ? from.after : undefined;
      for (;;) {
        const listed = await this.list(cells[i], after, signal);
        const keys = (listed.Contents ?? []).map((o) => o.Key).filter((k): k is string => !!k);
        const hit = keys.find((k) => (!after || k > after) && inWindow(k, window));
        if (hit) return { cell: i, key: hit };
        if (!listed.IsTruncated || !keys.length) break;
        after = keys[keys.length - 1];
      }
    }
    return null;
  }
}

function countRecords(body: Uint8Array): number {
  try {
    const text =
      body[0] === 0x1f && body[1] === 0x8b
        ? gunzipSync(body, { maxOutputLength: COUNT_MAX_BYTES }).toString("utf8")
        : Buffer.from(body).toString("utf8");
    const doc = JSON.parse(text) as { Records?: unknown };
    return Array.isArray(doc.Records) ? doc.Records.length : 0;
  } catch {
    return 0; // the count is for progress only; the importer reads, and discloses, the file itself
  }
}

/** Why an object read was refused, for the skip line. */
function deniedReason(err: unknown): string {
  const message = String((err as { message?: unknown })?.message ?? "");
  return /kms/i.test(`${errorName(err)} ${message}`)
    ? `${awsReason(err)}: the trail is KMS-encrypted and this identity needs kms:Decrypt on the trail key`
    : `${awsReason(err)}: this identity may not read the object; if the trail is KMS-encrypted it also needs kms:Decrypt on the trail key`;
}

const isDenied = (err: unknown): boolean => /AccessDenied|KMS\./.test(errorName(err));

interface GotObject {
  Body?: { transformToByteArray(): Promise<Uint8Array> };
  VersionId?: string;
  ETag?: string;
  LastModified?: Date;
  $metadata?: { requestId?: string };
}

const SELECTION = `objects delivered from the window start's minute to ${CLOUDTRAIL_DELIVERY_HORIZON_MS / 3_600_000} h after its end`;
/** How many listed prefixes an empty-window page names before it stops (the count is always given). */
const EMPTY_PREFIXES_SHOWN = 50;
export const EMPTY_WINDOW_ADAPTATION =
  "no CloudTrail object in the window; this page is not an S3 object, it closes the empty window";

/** The closing page of a window whose listing found no trail file (#2352): a 0-record Records document. */
function emptyWindowPage(cells: readonly Cell[], discovery: TrailDiscovery): CollectPage {
  const buckets = [...new Set(cells.map((c) => c.bucket))];
  const prefixes = cells.map(prefixOf);
  const shown = prefixes.slice(0, EMPTY_PREFIXES_SHOWN);
  return {
    body: Buffer.from('{"Records":[]}', "utf8"),
    extension: "json",
    recordCount: 0,
    requestParams: {
      api: "s3:ListObjectsV2",
      emptyWindow: "yes",
      bucket: (buckets.length ? buckets : discovery.roots.map((r) => r.bucket)).join(","),
      prefixesListed: String(prefixes.length),
      prefixes: shown.join(",") + (prefixes.length > shown.length ? ",…" : ""),
      selection: SELECTION,
      adaptation: EMPTY_WINDOW_ADAPTATION,
      ...(discovery.regionsNotEnabled.length
        ? { regionsNotEnabled: discovery.regionsNotEnabled.join(",") }
        : {}),
    },
  };
}

/** Fetch the page after `request.pageToken`: one trail object, saved as S3 returned it. */
export async function fetchTrailObject(
  walk: TrailObjectWalk,
  clients: AwsCollectClients,
  discovery: TrailDiscovery,
  request: CollectPageRequest,
): Promise<CollectPage> {
  const { roots, regionsNotEnabled } = discovery;
  const cells = trailCells(roots, trailDays(request.window), request.partition?.region);
  const found = await walk.next(cells, positionOf(cells, request.pageToken), request.window, request.signal);
  if (!found) {
    // A token is only ever handed out when an object follows, so a later page finding nothing is wrong.
    if (request.pageToken) {
      throw new Error(
        `no CloudTrail file in the trail folders for this window (${roots.map((r) => `s3://${r.bucket}/${r.root}`).join(", ")})`,
      );
    }
    return emptyWindowPage(cells, discovery); // the listing worked and found nothing: complete with 0
  }
  const cell = cells[found.cell];
  const ahead = await walk.next(
    cells,
    { cell: found.cell, after: found.key },
    request.window,
    request.signal,
  );
  const nextPageToken = ahead ? encodeToken(cell, found.key) : undefined;
  let got: GotObject;
  try {
    got = await sendAws<GotObject>(
      clients.s3,
      new GetObjectCommand({ Bucket: cell.bucket, Key: found.key }),
      request.signal,
    );
  } catch (err) {
    if (!isDenied(err)) throw err;
    throw new SkippedItemError(`s3://${cell.bucket}/${found.key}`, deniedReason(err), nextPageToken);
  }
  const body = (await got.Body?.transformToByteArray()) ?? new Uint8Array();
  const root = roots.find((r) => r.bucket === cell.bucket && r.root === cell.root);
  return {
    body,
    extension: body[0] === 0x1f && body[1] === 0x8b ? "json.gz" : "json",
    recordCount: countRecords(body),
    ...(nextPageToken ? { nextPageToken } : {}),
    walk: { at: found.cell, of: cells.length },
    ...(got.$metadata?.requestId ? { requestId: got.$metadata.requestId } : {}),
    requestParams: {
      api: "s3:GetObject",
      bucket: cell.bucket,
      key: found.key,
      ...(got.VersionId ? { versionId: got.VersionId } : {}),
      ...(got.ETag ? { etag: got.ETag } : {}),
      ...(got.LastModified ? { lastModified: got.LastModified.toISOString() } : {}),
      region: cell.region,
      day: cell.day,
      trails: root?.trails.join(",") ?? "",
      organizationTrail: root?.organization ? "yes" : "no",
      selection: SELECTION,
      ...(regionsNotEnabled.length ? { regionsNotEnabled: regionsNotEnabled.join(",") } : {}),
    },
  };
}
