// Microsoft Entra directory audits and sign-ins through Microsoft Graph (#2315).
//
//   directory audits   GET /v1.0/auditLogs/directoryAudits
//                        ?$filter=activityDateTime ge <start> and activityDateTime lt <end>
//   sign-ins           GET /beta/auditLogs/signIns
//                        ?$filter=createdDateTime ge <start> and createdDateTime lt <end>
//                         and signInEventTypes/any(t: t eq '<category>')&$top=1000
//
// Sign-ins are collected ONE CATEGORY PER SOURCE, each with its own explicit filter. Without a
// `signInEventTypes` filter Graph returns interactive sign-ins only, and v1.0 has no such filter at
// all — so the sign-in sources are pinned to beta, and which categories were collected is simply
// which of the four sources completed (the collection's result lists each one).

import type { CollectPage, CollectPageRequest } from "../cloudCollect/collectTypes.js";
import {
  assertLink,
  failure,
  GRAPH_BETA,
  GRAPH_HOST,
  GRAPH_V1,
  listPage,
  odataTime,
  requestIdOf,
  type HttpCall,
} from "./microsoftHttp.js";

/** The four sign-in categories, as Graph names them in `signInEventTypes`. */
export const SIGN_IN_CATEGORIES = {
  "entra-signins-interactive": { eventType: "interactiveUser", label: "interactive user" },
  "entra-signins-noninteractive": { eventType: "nonInteractiveUser", label: "non-interactive user" },
  "entra-signins-serviceprincipal": { eventType: "servicePrincipal", label: "service principal" },
  "entra-signins-managedidentity": { eventType: "managedIdentity", label: "managed identity" },
} as const;

export type SignInSource = keyof typeof SIGN_IN_CATEGORIES;
export const DIRECTORY_AUDITS_SOURCE = "entra-directory-audits";

/** Graph's documented maximum sign-in page size. */
const SIGN_IN_PAGE = 1000;

export function isSignInSource(source: string): source is SignInSource {
  return Object.hasOwn(SIGN_IN_CATEGORIES, source);
}

function timeFilter(field: string, req: CollectPageRequest): string {
  return `${field} ge ${odataTime(req.window.start)} and ${field} lt ${odataTime(req.window.end)}`;
}

/** The first request of a sub-window: its URL and the parameters the manifest records. */
export function entraFirstRequest(req: CollectPageRequest): { url: string; params: Record<string, string> } {
  if (req.source === DIRECTORY_AUDITS_SOURCE) {
    const filter = timeFilter("activityDateTime", req);
    return {
      url: `${GRAPH_V1}/auditLogs/directoryAudits?$filter=${encodeURIComponent(filter)}`,
      params: { api: "Microsoft Graph v1.0", endpoint: "auditLogs/directoryAudits", filter },
    };
  }
  if (!isSignInSource(req.source)) throw new Error(`not an Entra source: ${req.source}`);
  const { eventType } = SIGN_IN_CATEGORIES[req.source];
  const filter = `${timeFilter("createdDateTime", req)} and signInEventTypes/any(t: t eq '${eventType}')`;
  return {
    url: `${GRAPH_BETA}/auditLogs/signIns?$filter=${encodeURIComponent(filter)}&$top=${SIGN_IN_PAGE}`,
    params: {
      api: "Microsoft Graph beta",
      endpoint: "auditLogs/signIns",
      filter,
      signInEventType: eventType,
      top: String(SIGN_IN_PAGE),
    },
  };
}

/** One page of directory audits or of one sign-in category. */
export async function fetchEntraPage(
  graph: HttpCall,
  req: CollectPageRequest,
  nowMs: () => number,
): Promise<CollectPage> {
  const first = entraFirstRequest(req);
  const url = req.pageToken ? assertLink(req.pageToken, GRAPH_HOST) : first.url;
  const answer = await graph({ method: "GET", url, ...(req.signal ? { signal: req.signal } : {}) });
  if (answer.status < 200 || answer.status >= 300)
    throw failure(answer, { pageLink: !!req.pageToken, nowMs: nowMs() });
  const { records, nextLink } = listPage(answer);
  const requestId = requestIdOf(answer);
  return {
    body: answer.body,
    extension: "json",
    recordCount: records,
    ...(nextLink ? { nextPageToken: assertLink(nextLink, GRAPH_HOST) } : {}),
    ...(requestId ? { requestId } : {}),
    requestParams: { ...first.params, page: req.pageToken ? "next" : "first" },
  };
}
