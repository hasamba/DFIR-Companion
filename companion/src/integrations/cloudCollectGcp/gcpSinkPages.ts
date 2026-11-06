// Paging a checked GCS log sink, one hourly object per page (#2314). The sink is chosen once per
// session (gcpSink.ts chooseSink); each sub-window's object list is read once and kept for the
// session, and the page token names the last object saved — so a resume re-lists and carries on
// after it. Tokens start "gcs1:" and never expire.

import type { CollectPage, CollectPageRequest, CollectWindow } from "../cloudCollect/collectTypes.js";
import { logsFor } from "./gcpFilter.js";
import { throwForStatus } from "./gcpErrors.js";
import {
  chooseSink,
  lastCompleteBatchEnd,
  listSinkObjects,
  objectMediaUrl,
  type SinkChoice,
  type SinkListing,
} from "./gcpSink.js";
import type { GcpWire } from "./gcpWire.js";

const TOKEN_PREFIX = "gcs1:";
const REASON_MAX = 500;
const BUCKET_NAME = /^[a-z0-9][a-z0-9._-]{1,220}$/;

interface SinkCursor {
  /** bucket, sink name, last object saved */
  b: string;
  s: string;
  a?: string;
}

function encodeToken(c: SinkCursor): string {
  return TOKEN_PREFIX + Buffer.from(JSON.stringify(c), "utf8").toString("base64url");
}

function decodeToken(token: string): SinkCursor {
  try {
    const c = JSON.parse(
      Buffer.from(token.slice(TOKEN_PREFIX.length), "base64url").toString("utf8"),
    ) as SinkCursor;
    if (typeof c.b === "string" && BUCKET_NAME.test(c.b) && typeof c.s === "string") return c;
  } catch {
    /* falls through */
  }
  throw new Error("unreadable sink page token");
}

const countLines = (body: Uint8Array): number =>
  Buffer.from(body)
    .toString("utf8")
    .split("\n")
    .filter((l) => l.trim()).length;

export type SinkRoute = { ok: true } | { ok: false; reason: string };

export interface SinkPager {
  /** True for a token this pager issued. */
  owns(token: string | undefined): boolean;
  /** Whether a NEW sub-window over `window` is the sink's to answer, and why not. */
  route(window: CollectWindow, signal?: AbortSignal): Promise<SinkRoute>;
  page(req: CollectPageRequest): Promise<CollectPage>;
}

export function gcpSinkPager(wire: GcpWire, projectId: string, now: () => number): SinkPager {
  let choice: Promise<SinkChoice> | undefined;
  const listings = new Map<string, Promise<SinkListing>>();

  const chosen = (signal?: AbortSignal) => {
    choice ??= chooseSink(wire, projectId, signal).catch((err: unknown) => {
      choice = undefined;
      throw err;
    });
    return choice;
  };

  const listingFor = (req: CollectPageRequest, bucket: string) => {
    const key = `${req.subWindowId}|${JSON.stringify(req.partition ?? {})}|${bucket}`;
    let listing = listings.get(key);
    if (!listing) {
      listing = listSinkObjects(wire, bucket, req.window, logsFor(req.partition), req.signal);
      listing.catch(() => listings.delete(key));
      listings.set(key, listing);
    }
    return listing;
  };

  async function cursorFor(req: CollectPageRequest): Promise<SinkCursor> {
    if (req.pageToken) return decodeToken(req.pageToken);
    const c = await chosen(req.signal);
    if (!("bucket" in c)) throw new Error("no usable log sink");
    return { b: c.bucket, s: c.sink };
  }

  return {
    owns: (token) => !!token?.startsWith(TOKEN_PREFIX),

    async route(window, signal) {
      const c = await chosen(signal);
      if (!("bucket" in c)) return { ok: false, reason: c.rejected.join("; ").slice(0, REASON_MAX) };
      if (Date.parse(window.start) < Date.parse(c.coveredFrom))
        return {
          ok: false,
          reason: `sink "${c.sink}" holds audit logs from ${c.coveredFrom} only, after this window's start`,
        };
      return { ok: true };
    },

    async page(req) {
      const cursor = await cursorFor(req);
      const listing = await listingFor(req, cursor.b);
      const at = cursor.a ? listing.names.findIndex((n) => n > (cursor.a as string)) : 0;
      const base = { route: "gcs-sink", sink: cursor.s, bucket: cursor.b };
      const acquiredUntil = lastCompleteBatchEnd(now());
      if (at < 0 || listing.names.length === 0)
        return {
          body: listing.lastListing,
          extension: "json",
          recordCount: 0,
          requestParams: { ...base, objects: "0", prefixesListed: String(listing.prefixes) },
          acquiredUntil,
        };
      const name = listing.names[at];
      const res = await wire({
        method: "GET",
        url: objectMediaUrl(cursor.b, name),
        ...(req.signal ? { signal: req.signal } : {}),
      });
      throwForStatus(res, { hadPageToken: false });
      const more = at + 1 < listing.names.length;
      return {
        body: res.body,
        extension: "jsonl",
        recordCount: countLines(res.body),
        ...(more ? { nextPageToken: encodeToken({ ...cursor, a: name }) } : {}),
        requestParams: { ...base, object: name },
        acquiredUntil,
      };
    },
  };
}
