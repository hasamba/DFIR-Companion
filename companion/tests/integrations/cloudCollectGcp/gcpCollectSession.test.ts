import { describe, expect, it } from "vitest";
import {
  GCP_AUDIT_SOURCE,
  GCP_COLLECT_SOURCES,
  GCP_SINK_SOURCE,
  gcpCollectProvider,
  gcpCollectSession,
} from "../../../src/integrations/cloudCollectGcp/gcpCollectProvider.js";
import { GCP_ENTRIES_LIST_URL } from "../../../src/integrations/cloudCollectGcp/gcpFilter.js";
import { lastCompleteBatchEnd } from "../../../src/integrations/cloudCollectGcp/gcpSink.js";
import { authorizedWire } from "../../../src/integrations/cloudCollectGcp/gcpWire.js";
import {
  LOGGING_READ_SCOPE,
  STORAGE_READ_SCOPE,
} from "../../../src/integrations/cloudTransport/googleAccountAuth.js";
import type { OpenCloudAccount } from "../../../src/integrations/cloudAccounts/types.js";
import type { CloudFetch } from "../../../src/integrations/cloudTransport/cloudFetch.js";
import { gcpAuditEntry, googleError, mockWire, PROJECT } from "./gcpCollectMocks.js";

// #2314: one page of one sub-window, by the Logging API or a checked GCS sink.

const WINDOW = { start: "2026-11-01T00:00:00.000Z", end: "2026-11-02T00:00:00.000Z" };
const SETTINGS = {
  projectId: PROJECT,
  authMode: "service-account-key" as const,
  clientEmail: `collector@${PROJECT}.iam.gserviceaccount.com`,
};
const NOW = Date.parse("2026-11-02T10:20:00Z");

describe("the sources the GCP collector declares", () => {
  it("states the #2312 limits: 1 s windows, 60 calls/min, logName partition, 5 min overlap, Data Access note", () => {
    const api = GCP_COLLECT_SOURCES.find((s) => s.id === GCP_AUDIT_SOURCE);
    expect(api).toMatchObject({
      streamKind: "cloud",
      minWindowMs: 1000,
      rateLimit: { requests: 60, perMs: 60_000 },
      partition: { key: "logName", values: ["activity", "data_access", "system_event", "policy"] },
      overlapMs: 300_000,
    });
    expect(api?.retention?.offByDefault).toMatch(/Data Access/);
    const sink = GCP_COLLECT_SOURCES.find((s) => s.id === GCP_SINK_SOURCE);
    expect(sink?.streamKind).toBe("cloud");
    expect(api?.maxPagesPerWindow).toBe(1000);
    // Sink tokens never expire: no page cap, so no split re-downloading saved objects.
    expect(sink?.maxPagesPerWindow).toBeUndefined();
  });
});

describe("the Logging API path", () => {
  it("sends the exact filter, page size 1000, oldest first, and saves the answer byte for byte", async () => {
    // Odd whitespace on purpose: a re-serialised body would differ.
    const raw = `{\n  "entries": [${JSON.stringify(gcpAuditEntry(1))}],\n  "nextPageToken": "tok-1"\n}\n`;
    const { wire, calls } = mockWire(() => ({ body: raw }));
    const session = gcpCollectSession({ wire, settings: SETTINGS, now: () => NOW });
    const page = await session.fetchPage({ source: GCP_AUDIT_SOURCE, subWindowId: "s:0", window: WINDOW });
    expect(calls[0]).toMatchObject({ method: "POST", url: GCP_ENTRIES_LIST_URL });
    expect(calls[0].json).toEqual({
      resourceNames: [`projects/${PROJECT}`],
      filter:
        `logName=("projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Factivity" OR ` +
        `"projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access" OR ` +
        `"projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Fsystem_event" OR ` +
        `"projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Fpolicy") AND ` +
        'timestamp>="2026-11-01T00:00:00.000Z" AND timestamp<"2026-11-02T00:00:00.000Z"',
      orderBy: "timestamp asc",
      pageSize: 1000,
    });
    expect(Buffer.from(page.body).toString("utf8")).toBe(raw);
    expect(page).toMatchObject({ extension: "json", recordCount: 1, nextPageToken: "tok-1" });
    expect(page.requestParams).toMatchObject({
      route: "logging-api",
      pageSize: "1000",
      orderBy: "timestamp asc",
    });
    expect(page.requestParams.filter).toBe(calls[0].json?.filter);
  });

  it("sends the page token it was given, and narrows the filter for a logName partition", async () => {
    const { wire, calls } = mockWire(() => ({ body: { entries: [] } }));
    const session = gcpCollectSession({ wire, settings: SETTINGS });
    const page = await session.fetchPage({
      source: GCP_AUDIT_SOURCE,
      subWindowId: "s:0",
      window: WINDOW,
      pageToken: "tok-9",
      partition: { logName: "data_access" },
    });
    expect(calls[0].json).toMatchObject({ pageToken: "tok-9" });
    expect(calls[0].json?.filter).toBe(
      `logName=("projects/${PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access") AND ` +
        'timestamp>="2026-11-01T00:00:00.000Z" AND timestamp<"2026-11-02T00:00:00.000Z"',
    );
    expect(page.recordCount).toBe(0);
    expect(page.nextPageToken).toBeUndefined();
  });

  it("reports itself without a network call: the project and the identity reading", async () => {
    const { wire, calls } = mockWire(() => ({ body: {} }));
    const id = await gcpCollectSession({ wire, settings: SETTINGS }).identity();
    expect(id.accountRef).toBe(PROJECT);
    expect(id.caller).toBe(SETTINGS.clientEmail);
    expect(id.sdkVersions["google-auth-library"]).toMatch(/^\d+\.\d+/);
    expect(calls).toEqual([]);
    const imp = gcpCollectSession({
      wire,
      settings: {
        projectId: PROJECT,
        authMode: "impersonation",
        targetServiceAccount: "reader@x.iam.gserviceaccount.com",
      },
    });
    expect((await imp.identity()).caller).toBe("reader@x.iam.gserviceaccount.com");
  });
});

const BUCKET = "audit-bucket-01";
const OBJ = (log: string, hh: string) =>
  `cloudaudit.googleapis.com/${log}/2026/11/01/${hh}:00:00_${hh}:59:59_S0.json`;

/** A project with one sink (filter as given); its bucket starts in June and holds hours 15–16 of 1 Nov. */
function sinkProject(filter: string) {
  const objects: Record<string, string> = {
    ["cloudaudit.googleapis.com/activity/2026/06/01/00:00:00_00:59:59_S0.json"]: "",
    [OBJ("activity", "15")]:
      [gcpAuditEntry(1), gcpAuditEntry(2)].map((e) => JSON.stringify(e)).join("\n") + "\n",
    [OBJ("activity", "16")]: JSON.stringify(gcpAuditEntry(3, "SetIamPolicy", "2026-11-01T16:01:00Z")) + "\n",
  };
  return mockWire((req) => {
    const url = new URL(req.url);
    if (url.pathname.endsWith("/sinks"))
      return {
        body: {
          sinks: [
            {
              name: "audit-sink",
              destination: `storage.googleapis.com/${BUCKET}`,
              filter,
              createTime: "2026-01-01T00:00:00Z",
            },
          ],
        },
      };
    if (req.url === GCP_ENTRIES_LIST_URL) return { body: { entries: [gcpAuditEntry(9)] } };
    if (url.searchParams.get("alt") === "media") {
      const name = decodeURIComponent(url.pathname.split("/o/")[1] ?? "");
      return objects[name] !== undefined
        ? { body: objects[name] }
        : { status: 404, body: googleError(404, "NOT_FOUND", "no") };
    }
    const prefix = url.searchParams.get("prefix") ?? "";
    const items = Object.keys(objects)
      .sort()
      .filter((n) => n.startsWith(prefix))
      .map((name) => ({ name }));
    return { body: { kind: "storage#objects", ...(items.length ? { items } : {}) } };
  });
}

describe("the GCS sink path", () => {
  it("collects the sink's hourly objects byte for byte and states the late-shard cutoff on each", async () => {
    const { wire } = sinkProject('logName:"cloudaudit.googleapis.com"');
    const session = gcpCollectSession({ wire, settings: SETTINGS, now: () => NOW });
    const first = await session.fetchPage({ source: GCP_SINK_SOURCE, subWindowId: "k:0", window: WINDOW });
    expect(first.extension).toBe("jsonl");
    expect(first.recordCount).toBe(2);
    expect(first.requestParams).toMatchObject({
      route: "gcs-sink",
      sink: "audit-sink",
      bucket: BUCKET,
      object: OBJ("activity", "15"),
    });
    expect(first.acquiredUntil).toBe(lastCompleteBatchEnd(NOW));
    expect(first.nextPageToken).toMatch(/^gcs1:/);
    const second = await session.fetchPage({
      source: GCP_SINK_SOURCE,
      subWindowId: "k:0",
      window: WINDOW,
      pageToken: first.nextPageToken,
    });
    expect(second.requestParams.object).toBe(OBJ("activity", "16"));
    expect(second.nextPageToken).toBeUndefined();
  });

  it("rejects a sink whose filter misses audit logs, says why, and uses the Logging API", async () => {
    const { wire, calls } = sinkProject('logName:"cloudaudit.googleapis.com%2Factivity"');
    const session = gcpCollectSession({ wire, settings: SETTINGS, now: () => NOW });
    const page = await session.fetchPage({ source: GCP_SINK_SOURCE, subWindowId: "k:0", window: WINDOW });
    expect(page.requestParams.route).toBe("logging-api");
    expect(page.requestParams.sinkRejected).toBe(
      'sink "audit-sink": its filter does not include the data_access, system_event, policy audit logs',
    );
    expect(calls.at(-1)?.url).toBe(GCP_ENTRIES_LIST_URL);
    expect(page.acquiredUntil).toBeUndefined();
  });

  it("uses the Logging API for a window that starts before the sink's history", async () => {
    const { wire } = sinkProject("");
    const session = gcpCollectSession({ wire, settings: SETTINGS, now: () => NOW });
    const old = { start: "2025-12-01T00:00:00.000Z", end: "2025-12-02T00:00:00.000Z" };
    const page = await session.fetchPage({ source: GCP_SINK_SOURCE, subWindowId: "k:0", window: old });
    expect(page.requestParams.route).toBe("logging-api");
    expect(page.requestParams.sinkRejected).toBe(
      'sink "audit-sink" holds audit logs from 2026-06-01T00:00:00.000Z only, after this window\'s start',
    );
  });

  it("saves the bucket listing as the page when the window has no sink object", async () => {
    const { wire } = sinkProject("");
    const session = gcpCollectSession({ wire, settings: SETTINGS, now: () => NOW });
    const empty = { start: "2026-11-01T03:00:00.000Z", end: "2026-11-01T04:00:00.000Z" };
    const page = await session.fetchPage({ source: GCP_SINK_SOURCE, subWindowId: "k:0", window: empty });
    expect(page).toMatchObject({
      extension: "json",
      recordCount: 0,
      requestParams: { route: "gcs-sink", objects: "0" },
    });
    expect(page.nextPageToken).toBeUndefined();
  });
});

describe("gcpCollectProvider.open", () => {
  it("signs in with the Logging and Storage read scopes over the transport, and closes it", async () => {
    const seen: { scopes?: string[]; closed: boolean; urls: string[] } = { closed: false, urls: [] };
    const fetch: CloudFetch = async (url, init) => {
      seen.urls.push(String(url));
      expect(init?.headers?.authorization).toBe("Bearer test-token");
      return new Response('{"entries":[]}', { status: 200 });
    };
    const provider = gcpCollectProvider({
      transport: () => ({ agent: {} as never, close: () => (seen.closed = true) }),
      authClient: async (_settings, _secrets, _t, scopes) => {
        seen.scopes = scopes;
        return { getRequestHeaders: async () => new Headers({ authorization: "Bearer test-token" }) };
      },
      fetchFor: () => fetch,
    });
    const account = {
      id: "a1",
      name: "lab",
      revision: 1,
      createdAt: "",
      updatedAt: "",
      provider: "gcp",
      settings: SETTINGS,
      secrets: {},
    } as OpenCloudAccount;
    const session = provider.open(account);
    await session.fetchPage({ source: GCP_AUDIT_SOURCE, subWindowId: "s:0", window: WINDOW });
    expect(seen.scopes).toEqual([LOGGING_READ_SCOPE, STORAGE_READ_SCOPE]);
    expect(seen.urls).toEqual([GCP_ENTRIES_LIST_URL]);
    await session.close?.();
    expect(seen.closed).toBe(true);
    expect(() => provider.open({ ...account, provider: "aws" } as OpenCloudAccount)).toThrow(
      /not a GCP account/,
    );
  });
});

describe("authorizedWire", () => {
  it("puts the auth client's header on the request and returns the body's bytes untouched", async () => {
    let sent: { headers?: Record<string, string>; body?: unknown; method?: string } = {};
    const wire = authorizedWire(
      async () => ({ getRequestHeaders: async () => new Headers({ authorization: "Bearer t" }) }),
      async (_url, init) => {
        sent = { headers: init?.headers, body: init?.body, method: init?.method };
        return new Response(new Uint8Array([0x7b, 0x20, 0x7d]), { status: 200 });
      },
    );
    const res = await wire({ method: "POST", url: GCP_ENTRIES_LIST_URL, body: '{"a":1}' });
    expect(sent).toMatchObject({ method: "POST", body: '{"a":1}' });
    expect(sent.headers).toMatchObject({ authorization: "Bearer t", "content-type": "application/json" });
    expect([...res.body]).toEqual([0x7b, 0x20, 0x7d]);
  });
});
