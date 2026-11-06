// The LookupEvents source (#2313): CloudTrail event history, region by region — the fallback when
// no trail delivers to S3. It holds 90 days of MANAGEMENT events only (no data events), which the
// source's notice says in the pre-check and in the result.
//
// THE PAGE BODY IS ADAPTED, and the page says so. LookupEvents returns `{ Events: [{ EventId, …,
// CloudTrailEvent: "<the CloudTrail record as a JSON string>" }] }`; the CloudTrail importer reads
// records, and handed that envelope it finds no eventSource, identity or address in any of them.
// So the page saved is `{"Records":[ <each CloudTrailEvent string, verbatim> ]}` — the record text
// exactly as AWS returned it, joined, never parsed and re-written. A string that does not parse to
// a JSON object is dropped and counted. `requestParams.adaptation` records this on every page.
//
// The token is `{region, NextToken}`. A region with no events is not saved as a page of its own —
// the walk goes on to the next region in the same call (listed in `emptyRegions`) — except at the
// very end, where the last empty page closes the source. A region the account has not enabled
// answers with an auth error: it is skipped and named in the result, the walk goes on.

import { LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import {
  CursorExpiredError,
  SkippedItemError,
  type CollectPage,
  type CollectPageRequest,
} from "../collectTypes.js";
import { awsReason, regionOff, sendAws, type AwsCollectClients } from "./awsCollectTypes.js";

export const LOOKUP_ADAPTATION =
  'LookupEvents Events[].CloudTrailEvent strings joined verbatim into a {"Records":[...]} document';
const PAGE_SIZE = 50;

interface LookupToken {
  r: string;
  n?: string;
}

interface LookupOut {
  Events?: { CloudTrailEvent?: string }[];
  NextToken?: string;
  $metadata?: { requestId?: string };
}

/** The `{"Records":[…]}` body from the events' own record strings. Pure. */
export function adaptLookupEvents(events: readonly { CloudTrailEvent?: string }[]): {
  body: string;
  kept: number;
  dropped: number;
} {
  const kept: string[] = [];
  for (const e of events) {
    const raw = e.CloudTrailEvent;
    if (typeof raw !== "string") continue;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) kept.push(raw.trim());
    } catch {
      /* counted as dropped below */
    }
  }
  return { body: `{"Records":[${kept.join(",")}]}`, kept: kept.length, dropped: events.length - kept.length };
}

function parseToken(regions: readonly string[], token?: string): { index: number; next?: string } {
  if (!token) return { index: 0 };
  let t: LookupToken;
  try {
    t = JSON.parse(token) as LookupToken;
  } catch {
    throw new CursorExpiredError("unreadable LookupEvents token");
  }
  const index = regions.indexOf(t.r);
  if (index < 0) throw new CursorExpiredError("the region list changed");
  return { index, ...(t.n ? { next: t.n } : {}) };
}

const tokenFor = (region: string, next?: string): string =>
  JSON.stringify({ r: region, ...(next ? { n: next } : {}) } satisfies LookupToken);

/** One LookupEvents page, walking on past empty regions. */
export async function fetchLookupPage(
  clients: AwsCollectClients,
  allRegions: readonly string[],
  request: CollectPageRequest,
): Promise<CollectPage> {
  const only = request.partition?.region;
  const regions = only ? [only] : allRegions;
  let { index, next } = parseToken(regions, request.pageToken);
  const empty: string[] = [];
  for (;;) {
    const region = regions[index];
    const following = regions[index + 1];
    let out: LookupOut;
    try {
      out = await sendAws<LookupOut>(
        clients.cloudtrail(region),
        new LookupEventsCommand({
          StartTime: new Date(request.window.start),
          EndTime: new Date(request.window.end),
          MaxResults: PAGE_SIZE,
          ...(next ? { NextToken: next } : {}),
        }),
        request.signal,
      );
    } catch (err) {
      if (!regionOff(err)) throw err;
      const reason = `${awsReason(err)}: the region is not enabled for this account, or not reachable`;
      throw new SkippedItemError(`region ${region}`, reason, following ? tokenFor(following) : undefined);
    }
    const events = out.Events ?? [];
    const pageToken = out.NextToken
      ? tokenFor(region, out.NextToken)
      : following
        ? tokenFor(following)
        : undefined;
    if (!events.length && !out.NextToken && following) {
      empty.push(region);
      index++;
      next = undefined;
      continue;
    }
    const adapted = adaptLookupEvents(events);
    return {
      body: Buffer.from(adapted.body, "utf8"),
      extension: "json",
      recordCount: adapted.kept,
      ...(pageToken ? { nextPageToken: pageToken } : {}),
      ...(out.$metadata?.requestId ? { requestId: out.$metadata.requestId } : {}),
      requestParams: {
        api: "cloudtrail:LookupEvents",
        region,
        startTime: request.window.start,
        endTime: request.window.end,
        maxResults: String(PAGE_SIZE),
        events: String(events.length),
        dropped: String(adapted.dropped),
        adaptation: LOOKUP_ADAPTATION,
        ...(empty.length ? { emptyRegions: empty.join(",") } : {}),
      },
    };
  }
}
