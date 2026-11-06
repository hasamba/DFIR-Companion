// A mocked Microsoft tenant for the #2315 collector tests: Graph (audit log queries, directory
// audits, sign-ins) and ARM (subscriptions, Activity log), answering the collector's HttpCall with
// JSON bodies shaped like the documented responses. Synthetic data only: example.com users,
// TEST-NET addresses, all-zero-ish GUIDs. No real Microsoft endpoint is ever reached.

import type {
  HttpAnswer,
  HttpCall,
  HttpRequest,
} from "../../src/integrations/cloudCollectMicrosoft/microsoftHttp.js";

type Row = Record<string, unknown>;

export interface MockTenantOptions {
  /** Graph auditLogRecord objects; `createdDateTime` decides which query window holds them. */
  ual?: Row[];
  /** Statuses the query reports on successive polls before "succeeded". */
  pollStatuses?: string[];
  /** A query whose window holds more than this many records says isRecordCountLimitExceeded. */
  recordCap?: number;
  /** Records per page. */
  pageSize?: number;
  directoryAudits?: Row[];
  /** Sign-ins; `signInEventTypes` and `createdDateTime` decide which filter matches them. */
  signIns?: Row[];
  subscriptions?: string[];
  /** Subscriptions per listing page (default: all on one page); later pages follow nextLink. */
  subscriptionPageSize?: number;
  /** Subscriptions whose Activity log answers 403. */
  deniedSubscriptions?: string[];
  /** Per subscription, the HTTP status its Activity log answers instead (404, 409, 500, …). */
  subscriptionStatus?: Record<string, number>;
  /** Per subscription, Activity log records (`eventTimestamp`). */
  activity?: Record<string, Row[]>;
  /** Answer the next N requests whose URL matches with 429 and this Retry-After (seconds). */
  throttle?: { match: RegExp; times: number; retryAfter?: string };
  /** A query that ends "failed". */
  failQueries?: boolean;
}

export interface MockTenant {
  call: HttpCall;
  requests: HttpRequest[];
  /** Bodies of every query created, in order. */
  created: Row[];
}

const enc = new TextEncoder();

function answer(status: number, body: unknown, headers: Record<string, string> = {}): HttpAnswer {
  return {
    status,
    headers: { "content-type": "application/json", "request-id": `req-${status}`, ...headers },
    body: enc.encode(JSON.stringify(body)),
  };
}

const inWindow = (at: unknown, start: string, end: string, endInclusive = false): boolean => {
  const t = Date.parse(String(at));
  return t >= Date.parse(start) && (endInclusive ? t <= Date.parse(end) : t < Date.parse(end));
};

function paged(base: string, rows: Row[], skip: number, size: number, linkKey: string): unknown {
  const page = rows.slice(skip, skip + size);
  const sep = base.includes("?") ? "&" : "?";
  const next = skip + size < rows.length ? `${base}${sep}$skiptoken=${skip + size}` : undefined;
  return { value: page, ...(next ? { [linkKey]: next } : {}) };
}

function skipOf(url: URL): number {
  return Number(url.searchParams.get("$skiptoken") ?? 0);
}

function withoutSkip(url: URL): string {
  const copy = new URL(url.href);
  copy.searchParams.delete("$skiptoken");
  return copy.href;
}

/** `field ge X and field lt Y` out of an OData filter. */
function timeRange(filter: string, field: string): { start: string; end: string } {
  const ge = new RegExp(`${field} ge '?([^' ]+)'?`).exec(filter)?.[1] ?? "";
  const lt = new RegExp(`${field} (?:lt|le) '?([^' )]+)'?`).exec(filter)?.[1] ?? "";
  return { start: ge, end: lt };
}

export function mockTenant(opts: MockTenantOptions): MockTenant {
  const requests: HttpRequest[] = [];
  const created: Row[] = [];
  const queries = new Map<string, { body: Row; polls: number }>();
  let throttleLeft = opts.throttle?.times ?? 0;
  const size = opts.pageSize ?? 50;

  const ualRows = (q: Row): Row[] => {
    const types = (q.recordTypeFilters as string[] | undefined) ?? [];
    return (opts.ual ?? []).filter(
      (r) =>
        inWindow(r.createdDateTime, String(q.filterStartDateTime), String(q.filterEndDateTime)) &&
        (!types.length || types.includes(String(r.auditLogRecordType))),
    );
  };

  const graph = (req: HttpRequest, url: URL): HttpAnswer => {
    const path = url.pathname;
    if (req.method === "POST" && path === "/v1.0/security/auditLog/queries") {
      const body = JSON.parse(req.body ?? "{}") as Row;
      const id = `00000000-0000-4000-9000-${String(created.length + 1).padStart(12, "0")}`;
      created.push(body);
      queries.set(id, { body, polls: 0 });
      return answer(201, { ...body, id, status: "notStarted" });
    }
    const q = /^\/v1\.0\/security\/auditLog\/queries\/([^/]+)(\/records)?$/.exec(path);
    if (q) {
      const query = queries.get(q[1]);
      if (!query) return answer(404, { error: { code: "ResourceNotFound", message: "query not found" } });
      const rows = ualRows(query.body);
      if (q[2]) return answer(200, paged(withoutSkip(url), rows, skipOf(url), size, "@odata.nextLink"));
      const statuses = opts.pollStatuses ?? [];
      const status = opts.failQueries
        ? "failed"
        : query.polls < statuses.length
          ? statuses[query.polls]
          : "succeeded";
      query.polls++;
      const capped = opts.recordCap !== undefined && rows.length > opts.recordCap;
      return answer(200, { ...query.body, id: q[1], status, isRecordCountLimitExceeded: capped });
    }
    const filter = url.searchParams.get("$filter") ?? "";
    if (path === "/v1.0/auditLogs/directoryAudits") {
      const { start, end } = timeRange(filter, "activityDateTime");
      const rows = (opts.directoryAudits ?? []).filter((r) => inWindow(r.activityDateTime, start, end));
      return answer(200, paged(withoutSkip(url), rows, skipOf(url), size, "@odata.nextLink"));
    }
    if (path === "/beta/auditLogs/signIns") {
      const { start, end } = timeRange(filter, "createdDateTime");
      const type = /signInEventTypes\/any\(t: t eq '([A-Za-z]+)'\)/.exec(filter)?.[1];
      if (!type) return answer(200, { value: (opts.signIns ?? []).filter((r) => isInteractive(r)) });
      const rows = (opts.signIns ?? []).filter(
        (r) => inWindow(r.createdDateTime, start, end) && (r.signInEventTypes as string[]).includes(type),
      );
      return answer(200, paged(withoutSkip(url), rows, skipOf(url), size, "@odata.nextLink"));
    }
    return answer(403, {
      error: { code: "Authorization_RequestDenied", message: "Insufficient privileges" },
    });
  };

  const arm = (url: URL): HttpAnswer => {
    if (url.pathname === "/subscriptions") {
      const all = (opts.subscriptions ?? []).map((subscriptionId) => ({ subscriptionId, state: "Enabled" }));
      const per = opts.subscriptionPageSize ?? all.length + 1;
      return answer(200, paged(withoutSkip(url), all, skipOf(url), per, "nextLink"));
    }
    const m =
      /^\/subscriptions\/([^/]+)\/providers\/Microsoft\.Insights\/eventtypes\/management\/values$/.exec(
        url.pathname,
      );
    if (!m) return answer(404, { error: { code: "NotFound", message: "no such path" } });
    if (opts.deniedSubscriptions?.includes(m[1]))
      return answer(403, { error: { code: "AuthorizationFailed", message: "no read access" } });
    const status = opts.subscriptionStatus?.[m[1]];
    if (status) return answer(status, { error: { code: `Status${status}`, message: "refused" } });
    const { start, end } = timeRange(url.searchParams.get("$filter") ?? "", "eventTimestamp");
    const rows = (opts.activity?.[m[1]] ?? []).filter((r) => inWindow(r.eventTimestamp, start, end, true));
    return answer(200, paged(withoutSkip(url), rows, skipOf(url), size, "nextLink"));
  };

  const call: HttpCall = async (req) => {
    requests.push(req);
    const url = new URL(req.url);
    if (throttleLeft > 0 && opts.throttle?.match.test(req.url)) {
      throttleLeft--;
      return answer(
        429,
        { error: { code: "TooManyRequests", message: "slow down" } },
        {
          ...(opts.throttle.retryAfter ? { "retry-after": opts.throttle.retryAfter } : {}),
        },
      );
    }
    if (url.hostname === "graph.microsoft.com") return graph(req, url);
    if (url.hostname === "management.azure.com") return arm(url);
    throw new Error(`mock tenant: unexpected host ${url.hostname}`);
  };
  return { call, requests, created };
}

function isInteractive(r: Row): boolean {
  return (r.signInEventTypes as string[] | undefined)?.includes("interactiveUser") ?? false;
}

// ── Synthetic records ──────────────────────────────────────────────────────────────────────────

/** A legacy UAL record (the AuditData object an MES export or the Management API carries). */
export function legacyUalRecord(i: number, at: string, operation = "New-InboxRule"): Row {
  return {
    CreationTime: at.replace(/\.\d+Z$|Z$/, ""),
    Id: `00000000-0000-4000-a000-${String(i).padStart(12, "0")}`,
    Operation: operation,
    OrganizationId: "00000000-0000-4000-8000-000000000001",
    RecordType: 1,
    ResultStatus: "True",
    UserKey: `user${i}@example.com`,
    UserType: 2,
    Workload: "Exchange",
    ClientIP: "203.0.113.10",
    UserId: `user${i}@example.com`,
    ObjectId: `user${i}@example.com\\fwd`,
    Parameters: [
      { Name: "Name", Value: "fwd" },
      { Name: "ForwardTo", Value: "drop@example.net" },
    ],
  };
}

/** The same record as Graph's AuditLogQuery returns it (security.auditLogRecord). */
export function graphUalRecord(i: number, at: string, operation = "New-InboxRule"): Row {
  return {
    "@odata.type": "#microsoft.graph.security.auditLogRecord",
    id: `00000000-0000-4000-a000-${String(i).padStart(12, "0")}`,
    createdDateTime: at,
    auditLogRecordType: "exchangeAdmin",
    operation,
    organizationId: "00000000-0000-4000-8000-000000000001",
    userType: "admin",
    userId: `user${i}@example.com`,
    service: "Exchange",
    objectId: `user${i}@example.com\\fwd`,
    userPrincipalName: `user${i}@example.com`,
    clientIp: "203.0.113.10",
    administrativeUnits: [],
    auditData: { "@odata.type": "#microsoft.graph.security.auditData", ...legacyUalRecord(i, at, operation) },
  };
}

export function signInRecord(i: number, at: string, eventType: string): Row {
  return {
    id: `00000000-0000-4000-c000-${String(i).padStart(12, "0")}`,
    createdDateTime: at,
    userPrincipalName: eventType.endsWith("User") ? `user${i}@example.com` : "",
    userId: `00000000-0000-4000-d000-${String(i).padStart(12, "0")}`,
    appId: "00000000-0000-4000-e000-000000000001",
    appDisplayName: "Test App",
    servicePrincipalName: eventType.endsWith("User") ? "" : "svc-test",
    ipAddress: "198.51.100.20",
    signInEventTypes: [eventType],
    isInteractive: eventType === "interactiveUser",
    status: { errorCode: 0, failureReason: null },
    location: { city: "Testville", countryOrRegion: "US" },
  };
}

export function directoryAuditRecord(i: number, at: string): Row {
  return {
    id: `Directory_${String(i).padStart(8, "0")}`,
    category: "RoleManagement",
    activityDisplayName: "Add member to role",
    activityDateTime: at,
    loggedByService: "Core Directory",
    result: "success",
    initiatedBy: { user: { userPrincipalName: `admin${i}@example.com`, ipAddress: "198.51.100.30" } },
    targetResources: [{ type: "User", userPrincipalName: `user${i}@example.com`, modifiedProperties: [] }],
  };
}

export function activityRecord(i: number, at: string, subscriptionId: string): Row {
  return {
    eventDataId: `00000000-0000-4000-f000-${String(i).padStart(12, "0")}`,
    correlationId: `00000000-0000-4000-f100-${String(i).padStart(12, "0")}`,
    eventTimestamp: at,
    submissionTimestamp: at,
    caller: `admin${i}@example.com`,
    operationName: {
      value: "Microsoft.Authorization/roleAssignments/write",
      localizedValue: "Create role assignment",
    },
    status: { value: "Succeeded", localizedValue: "Succeeded" },
    resourceId: `/subscriptions/${subscriptionId}/resourceGroups/rg1/providers/Microsoft.Authorization/roleAssignments/r${i}`,
    subscriptionId,
    httpRequest: { clientIpAddress: "198.51.100.40", method: "PUT" },
    level: "Informational",
  };
}
