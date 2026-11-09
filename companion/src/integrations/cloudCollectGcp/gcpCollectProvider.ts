// Live GCP audit log collection (#2314): the provider the collection engine (#2311/#2312) drives.
//
// Two sources, both imported by the existing GCP importer (stream kind "cloud", #2303):
//
//   gcp-audit       the Logging API — POST entries:list with the exact audit-log filter, page size
//                   1000, oldest first, at 60 calls/min. Pages are the API's own JSON answers,
//                   {"entries":[…],"nextPageToken":…}, saved byte for byte.
//   gcp-audit-sink  a GCS log sink bucket, when one passes the checks in gcpSink.ts (filter, history,
//                   permission). Pages are the sink's hourly objects, byte for byte. A sink that
//                   fails a check — or a window older than its history — falls back to the Logging
//                   API, and the first page's request record says why.
//
// A page token decides its own path: sink tokens start "gcs1:", so a sub-window that began on one
// path finishes on it, across a resume too. Logging page tokens expire after 24 h; a rejected token
// is a CursorExpiredError and the engine restarts the sub-window (gcpErrors.ts).
//
// Data Access is a private log: an account without the Private Logs Viewer role gets it silently
// left out of entries:list, not refused (#2450). Before the first request that covers Data Access,
// the session asks Google once whether the account holds the permission; every such page records
// the answer, and a missing permission marks the page unverified with a note saying so.
//
// No @google-cloud/logging: its gRPC and REST-fallback paths bypass the cloud transport (#2310). All
// traffic — the token exchange included — goes over the transport (gcpWire.ts, googleAccountAuth.ts).

import { createRequire } from "node:module";
import type { GcpSecrets, GcpSettings, OpenCloudAccount } from "../cloudAccounts/types.js";
import type {
  CloudCollectProvider,
  CloudCollectSession,
  CollectPage,
  CollectPageRequest,
  CollectSourceInfo,
} from "../cloudCollect/collectTypes.js";
import {
  DEFAULT_OVERLAP_MS,
  GCP_AUDIT_LOG_NAMES,
  MIN_WINDOW_MS,
  PARTITION_KEYS,
  RATE_LIMITS,
  RETENTION,
} from "../cloudCollect/collectDefaults.js";
import type { CloudTransport } from "../cloudTransport/cloudAgent.js";
import { cloudFetch, type CloudFetch } from "../cloudTransport/cloudFetch.js";
import {
  LOGGING_READ_SCOPE,
  STORAGE_READ_SCOPE,
  googleAccountClient,
} from "../cloudTransport/googleAccountAuth.js";
import {
  GCP_ENTRIES_LIST_URL,
  GCP_PAGE_SIZE,
  entriesListBody,
  gcpAuditFilter,
  logsFor,
} from "./gcpFilter.js";
import { GcpHttpError, throwForStatus } from "./gcpErrors.js";
import {
  RESOURCE_MANAGER_READ_SCOPE,
  dataAccessNote,
  looksLikeResourceManagerOff,
  privateLogAccessFrom,
  resourceManagerOffReason,
  testIamPermissionsBody,
  testIamPermissionsUrl,
  unknownAccess,
  type PrivateLogAccess,
} from "../cloudTransport/googlePrivateLogs.js";
import { gcpSinkPager } from "./gcpSinkPages.js";
import { authorizedWire, type GcpHeaderSource, type GcpWire } from "./gcpWire.js";

export const GCP_AUDIT_SOURCE = "gcp-audit";
export const GCP_SINK_SOURCE = "gcp-audit-sink";
/**
 * A Logging API sub-window still paging after this many pages splits (#2312). Page tokens expire
 * after 24 h, and an expired token restarts the whole sub-window — smaller windows lose less. Not on
 * the sink source: its tokens never expire, and a split would re-download the objects already saved.
 */
export const GCP_MAX_PAGES_PER_WINDOW = 1000;
const ADMIN_ACTIVITY_DAYS = 400;

const shared = {
  streamKind: "cloud",
  minWindowMs: MIN_WINDOW_MS.gcp,
  partition: { key: PARTITION_KEYS.gcp, values: GCP_AUDIT_LOG_NAMES },
  rateLimit: RATE_LIMITS.gcpLogging,
  overlapMs: DEFAULT_OVERLAP_MS.gcp,
} as const satisfies Partial<CollectSourceInfo>;

export const GCP_COLLECT_SOURCES: readonly CollectSourceInfo[] = [
  {
    id: GCP_AUDIT_SOURCE,
    label: "GCP audit logs (Admin Activity, Data Access, System Event, Policy)",
    ...shared,
    maxPagesPerWindow: GCP_MAX_PAGES_PER_WINDOW,
    retention: {
      minDays: RETENTION.gcpDataAccess.minDays,
      maxDays: ADMIN_ACTIVITY_DAYS,
      note:
        "Cloud Logging keeps Admin Activity, System Event and Policy audit logs 400 days; " +
        RETENTION.gcpDataAccess.note,
      offByDefault: RETENTION.gcpDataAccess.offByDefault,
    },
  },
  {
    id: GCP_SINK_SOURCE,
    label: "GCP audit logs from a log sink bucket (falls back to the Logging API)",
    ...shared,
  },
];

function sdkVersions(): Record<string, string> {
  let auth = "unknown";
  try {
    auth = (createRequire(import.meta.url)("google-auth-library/package.json") as { version: string })
      .version;
  } catch {
    /* reported as unknown */
  }
  return { "google-auth-library": auth, "logging-api": "v2", "storage-json-api": "v1" };
}

export interface GcpSessionDeps {
  wire: GcpWire;
  settings: GcpSettings;
  /** Milliseconds since the epoch: when a sink page was read (its late-shard cutoff). */
  now?: () => number;
  close?: () => void;
}

function parsePage(body: Uint8Array): { entries: number; next?: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(body).toString("utf8"));
  } catch {
    throw new GcpHttpError(200, undefined, "entries:list returned a body that is not JSON");
  }
  const page = (parsed && typeof parsed === "object" ? parsed : {}) as {
    entries?: unknown;
    nextPageToken?: unknown;
  };
  return {
    entries: Array.isArray(page.entries) ? page.entries.length : 0,
    ...(typeof page.nextPageToken === "string" && page.nextPageToken ? { next: page.nextPageToken } : {}),
  };
}

/** Google's own error text from a failed call's body, when it has one. */
function googleMessage(body: Uint8Array): string {
  try {
    const err = (
      JSON.parse(Buffer.from(body).toString("utf8")) as { error?: { status?: unknown; message?: unknown } }
    ).error;
    const parts = [err?.status, err?.message].filter((v): v is string => typeof v === "string" && v !== "");
    return parts.length ? ` ${parts.join(": ")}` : "";
  } catch {
    return "";
  }
}

/** Asks Google whether the account may read private logs (#2450). Never throws, unless aborted. */
export async function testPrivateLogAccess(
  wire: GcpWire,
  projectId: string,
  signal?: AbortSignal,
): Promise<PrivateLogAccess> {
  try {
    const res = await wire({
      method: "POST",
      url: testIamPermissionsUrl(projectId),
      body: JSON.stringify(testIamPermissionsBody()),
      ...(signal ? { signal } : {}),
    });
    if (res.status < 200 || res.status >= 300) {
      if (looksLikeResourceManagerOff(Buffer.from(res.body).toString("utf8")))
        return unknownAccess(resourceManagerOffReason(projectId));
      return unknownAccess(`the permission test answered HTTP ${res.status}${googleMessage(res.body)}`);
    }
    return privateLogAccessFrom(JSON.parse(Buffer.from(res.body).toString("utf8")));
  } catch (err) {
    if (signal?.aborted) throw err;
    // A transport error can quote the proxy URL, which may hold a password: fixed text only.
    return unknownAccess(
      err instanceof SyntaxError
        ? "the permission test answered with a body that is not JSON"
        : "the permission test got no answer",
    );
  }
}

type AccessProbe = (signal?: AbortSignal) => Promise<PrivateLogAccess>;

async function apiPage(
  deps: GcpSessionDeps,
  req: CollectPageRequest,
  extra: Record<string, string>,
  probe: AccessProbe,
): Promise<CollectPage> {
  const logs = logsFor(req.partition);
  const access = logs.includes("data_access") ? await probe(req.signal) : undefined;
  const filter = gcpAuditFilter(deps.settings.projectId, req.window, logs);
  const res = await deps.wire({
    method: "POST",
    url: GCP_ENTRIES_LIST_URL,
    body: JSON.stringify(entriesListBody(deps.settings.projectId, filter, req.pageToken)),
    ...(req.signal ? { signal: req.signal } : {}),
  });
  throwForStatus(res, { hadPageToken: !!req.pageToken });
  const { entries, next } = parsePage(res.body);
  const note = access ? dataAccessNote(access) : undefined;
  return {
    body: res.body,
    extension: "json",
    recordCount: entries,
    ...(next ? { nextPageToken: next } : {}),
    ...(note ? { note } : {}),
    ...(access?.state === "missing" ? { unverified: true } : {}),
    requestParams: {
      route: "logging-api",
      url: GCP_ENTRIES_LIST_URL,
      resourceNames: `projects/${deps.settings.projectId}`,
      filter,
      orderBy: "timestamp asc",
      pageSize: String(GCP_PAGE_SIZE),
      ...(access ? { privateLogAccess: access.state } : {}),
      ...extra,
    },
  };
}

/** A session over `deps.wire`. Exported for tests; production goes through gcpCollectProvider. */
export function gcpCollectSession(deps: GcpSessionDeps): CloudCollectSession {
  const now = deps.now ?? Date.now;
  const sink = gcpSinkPager(deps.wire, deps.settings.projectId, now);
  // One permission test per session; an aborted one is forgotten so a later request asks again.
  let access: Promise<PrivateLogAccess> | undefined;
  const probe: AccessProbe = (signal) => {
    access ??= testPrivateLogAccess(deps.wire, deps.settings.projectId, signal).catch((err: unknown) => {
      access = undefined;
      throw err;
    });
    return access;
  };
  return {
    identity: async () => ({
      accountRef: deps.settings.projectId,
      caller:
        (deps.settings.authMode === "impersonation"
          ? deps.settings.targetServiceAccount
          : deps.settings.clientEmail) ?? "unknown",
      sdkVersions: sdkVersions(),
    }),
    async fetchPage(req) {
      if (sink.owns(req.pageToken)) return sink.page(req);
      if (req.source === GCP_SINK_SOURCE && !req.pageToken) {
        const route = await sink.route(req.window, req.signal);
        if (route.ok) return sink.page(req);
        const page = await apiPage(deps, req, { sinkRejected: route.reason }, probe);
        const sinkNote = `Log sink not used: ${route.reason}. Collected from the Logging API.`;
        return { ...page, note: page.note ? `${sinkNote} ${page.note}` : sinkNote };
      }
      return apiPage(deps, req, {}, probe);
    },
    close: () => deps.close?.(),
  };
}

export interface GcpProviderOptions {
  /** The cloud transport for one collection run (production: cloudTransportFromEnv). */
  transport: () => CloudTransport;
  /** Test seams: the auth client and the fetch built over the transport. */
  authClient?: (
    settings: GcpSettings,
    secrets: GcpSecrets,
    transport: CloudTransport,
    scopes: string[],
  ) => Promise<GcpHeaderSource>;
  fetchFor?: (transport: CloudTransport) => CloudFetch;
}

const COLLECT_SCOPES = [LOGGING_READ_SCOPE, STORAGE_READ_SCOPE, RESOURCE_MANAGER_READ_SCOPE];

export function gcpCollectProvider(opts: GcpProviderOptions): CloudCollectProvider {
  const authClient = opts.authClient ?? googleAccountClient;
  const fetchFor = opts.fetchFor ?? cloudFetch;
  return {
    provider: "gcp",
    sources: GCP_COLLECT_SOURCES,
    open(account: OpenCloudAccount) {
      if (account.provider !== "gcp") throw new Error("not a GCP account");
      const { settings, secrets } = account;
      // Built on the first request, so a bad CA path or proxy URL fails the sub-windows with its
      // reason rather than the start request.
      let transport: CloudTransport | undefined;
      let fetch: CloudFetch | undefined;
      const wireTransport = () => (transport ??= opts.transport());
      let client: Promise<GcpHeaderSource> | undefined;
      const auth = () => {
        client ??= authClient(settings, secrets, wireTransport(), COLLECT_SCOPES).catch((err: unknown) => {
          client = undefined;
          throw err;
        });
        return client;
      };
      const wire: GcpWire = async (req) => {
        fetch ??= fetchFor(wireTransport());
        return authorizedWire(auth, fetch)(req);
      };
      return gcpCollectSession({ wire, settings, close: () => transport?.close() });
    },
  };
}
