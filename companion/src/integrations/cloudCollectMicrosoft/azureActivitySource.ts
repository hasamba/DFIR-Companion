// The Azure Activity log, per subscription the app can read (#2315).
//
//   subscriptions   GET https://management.azure.com/subscriptions?api-version=2022-12-01
//                   (every subscription the app holds a role on; nextLink followed)
//   activity        GET .../subscriptions/{id}/providers/Microsoft.Insights/eventtypes/management/values
//                     ?api-version=2015-04-01&$filter=eventTimestamp ge '<start>' and eventTimestamp le '<end>'
//
// The requests go through @azure/arm-monitor's MonitorClient pipeline (azureClientOptions: the cloud
// transport) rather than its paged iterator: the iterator hands back deserialized objects (times as
// Date), and a page is evidence only if it is saved exactly as the cloud sent it.
//
// One source walks every subscription: the page token is `{"sub": <id>, "next"?: <nextLink>}`. A
// subscription's pages run out → the next subscription in id order. `le` is the only upper bound the
// API accepts and it is inclusive, so the filter ends 1 ms before the window's end; an event on that
// exact instant is picked up by the next window and the #2301 dedup absorbs any repeat.

import type { CollectPage, CollectPageRequest } from "../cloudCollect/collectTypes.js";
import {
  ACTIVITY_LOG_API_VERSION,
  ARM_BASE,
  ARM_HOST,
  assertLink,
  failure,
  jsonOf,
  listPage,
  requestIdOf,
  SUBSCRIPTIONS_API_VERSION,
  type HttpCall,
} from "./microsoftHttp.js";

export const AZURE_ACTIVITY_SOURCE = "azure-activity";
const SUBSCRIPTION_ID = /^[0-9a-fA-F-]{36}$/;
const MAX_SUBSCRIPTION_PAGES = 50;

export const NO_SUBSCRIPTION =
  "the app can read no Azure subscription: grant it the Reader role on each subscription to collect";

interface ActivityToken {
  sub: string;
  next?: string;
}

function parseToken(token: string): ActivityToken {
  try {
    const t = JSON.parse(token) as Partial<ActivityToken>;
    if (typeof t.sub === "string" && SUBSCRIPTION_ID.test(t.sub))
      return { sub: t.sub, ...(typeof t.next === "string" ? { next: t.next } : {}) };
  } catch {
    // fall through
  }
  throw new Error("the saved Azure Activity page token is unreadable");
}

/** The subscriptions the app can read, sorted by id. */
export async function listSubscriptions(
  arm: HttpCall,
  nowMs: () => number,
  signal?: AbortSignal,
): Promise<string[]> {
  const ids = new Set<string>();
  let url: string | undefined = `${ARM_BASE}/subscriptions?api-version=${SUBSCRIPTIONS_API_VERSION}`;
  for (let page = 0; url && page < MAX_SUBSCRIPTION_PAGES; page++) {
    const answer = await arm({ method: "GET", url, ...(signal ? { signal } : {}) });
    if (answer.status < 200 || answer.status >= 300)
      throw failure(answer, { pageLink: page > 0, nowMs: nowMs() });
    const body = jsonOf(answer);
    for (const s of Array.isArray(body.value) ? body.value : []) {
      const id = (s as { subscriptionId?: unknown })?.subscriptionId;
      if (typeof id === "string" && SUBSCRIPTION_ID.test(id)) ids.add(id.toLowerCase());
    }
    url =
      typeof body.nextLink === "string" && body.nextLink ? assertLink(body.nextLink, ARM_HOST) : undefined;
  }
  return [...ids].sort();
}

function activityFilter(req: CollectPageRequest): string {
  const end = new Date(Date.parse(req.window.end) - 1).toISOString();
  return `eventTimestamp ge '${req.window.start}' and eventTimestamp le '${end}'`;
}

function firstUrl(sub: string, filter: string): string {
  return (
    `${ARM_BASE}/subscriptions/${sub}/providers/Microsoft.Insights/eventtypes/management/values` +
    `?api-version=${ACTIVITY_LOG_API_VERSION}&$filter=${encodeURIComponent(filter)}`
  );
}

/** One page of one subscription's Activity log. `subscriptions` is the sorted list to walk. */
export async function fetchActivityPage(
  arm: HttpCall,
  req: CollectPageRequest,
  subscriptions: readonly string[],
  nowMs: () => number,
): Promise<CollectPage> {
  const token = req.pageToken ? parseToken(req.pageToken) : undefined;
  const sub = token?.sub ?? subscriptions[0];
  if (!sub) throw new Error(NO_SUBSCRIPTION);
  const filter = activityFilter(req);
  const url = token?.next ? assertLink(token.next, ARM_HOST) : firstUrl(sub, filter);
  const answer = await arm({ method: "GET", url, ...(req.signal ? { signal: req.signal } : {}) });
  if (answer.status < 200 || answer.status >= 300) {
    const err = failure(answer, { pageLink: !!token?.next, nowMs: nowMs() });
    err.message = `subscription ${sub}: ${err.message}`;
    throw err;
  }
  const { records, nextLink } = listPage(answer);
  // Next: this subscription's next page, else the first subscription after it in id order.
  const after = subscriptions.find((s) => s > sub);
  const next: ActivityToken | undefined = nextLink
    ? { sub, next: assertLink(nextLink, ARM_HOST) }
    : after
      ? { sub: after }
      : undefined;
  const requestId = requestIdOf(answer);
  return {
    body: answer.body,
    extension: "json",
    recordCount: records,
    ...(next ? { nextPageToken: JSON.stringify(next) } : {}),
    ...(requestId ? { requestId } : {}),
    requestParams: {
      api: `Azure Monitor ${ACTIVITY_LOG_API_VERSION}`,
      endpoint: "eventtypes/management/values",
      subscriptionId: sub,
      filter,
      page: token?.next ? "next" : "first",
    },
  };
}
