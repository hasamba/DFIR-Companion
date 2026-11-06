import { describe, expect, it } from "vitest";
import {
  CursorExpiredError,
  RateLimitedError,
  type CollectPage,
  type CollectPageRequest,
} from "../../src/integrations/cloudCollect/collectTypes.js";
import type { OpenCloudAccount } from "../../src/integrations/cloudAccounts/types.js";
import { microsoftCollectProvider } from "../../src/integrations/cloudCollectMicrosoft/microsoftProvider.js";
import {
  MICROSOFT_SOURCES,
  UAL_SOURCE,
} from "../../src/integrations/cloudCollectMicrosoft/microsoftSources.js";
import { UAL_RECORD_TYPES } from "../../src/integrations/cloudCollectMicrosoft/ualRecordTypes.js";
import { NO_SUBSCRIPTION } from "../../src/integrations/cloudCollectMicrosoft/azureActivitySource.js";
import { rateKey } from "../../src/integrations/cloudCollect/collectRateLimit.js";
import { fakeClock } from "../helpers/cloudCollectDense.js";
import {
  activityRecord,
  directoryAuditRecord,
  graphUalRecord,
  mockTenant,
  signInRecord,
  type MockTenantOptions,
} from "../helpers/microsoftCollectMocks.js";

// #2315: the Microsoft collector against a mocked tenant — never a real Microsoft endpoint.

const TENANT = "00000000-0000-4000-8000-000000000001";
const SUB_A = "11111111-1111-4111-8111-111111111111";
const SUB_B = "22222222-2222-4222-8222-222222222222";
const WINDOW = { start: "2026-10-01T10:00:00.000Z", end: "2026-10-01T11:00:00.000Z" };
const at = (min: number) => new Date(Date.parse(WINDOW.start) + min * 60_000).toISOString();

const account = {
  id: "acct1",
  name: "lab tenant",
  revision: 1,
  createdAt: "",
  updatedAt: "",
  provider: "microsoft",
  settings: { tenantId: TENANT, clientId: "00000000-0000-4000-8000-000000000002", certificateFormat: "pem" },
  secrets: { certificatePem: "unused-by-the-mock" },
} as OpenCloudAccount;

function session(opts: MockTenantOptions) {
  const tenant = mockTenant(opts);
  const clock = fakeClock(Date.parse("2026-10-05T00:00:00Z"));
  const provider = microsoftCollectProvider({
    wire: () => ({ graph: tenant.call, arm: tenant.call }),
    timing: { now: clock.now, sleep: clock.sleep },
  });
  return { tenant, clock, provider, session: provider.open(account) };
}

const req = (source: string, extra: Partial<CollectPageRequest> = {}): CollectPageRequest => ({
  source,
  subWindowId: `${source}-0`,
  window: WINDOW,
  ...extra,
});

const bodyOf = (page: CollectPage) => JSON.parse(new TextDecoder().decode(page.body));

async function drain(s: ReturnType<typeof session>["session"], first: CollectPageRequest) {
  const pages: CollectPage[] = [];
  let token: string | undefined;
  do {
    const page = await s.fetchPage({ ...first, ...(token ? { pageToken: token } : {}) });
    pages.push(page);
    token = page.nextPageToken;
  } while (token);
  return pages;
}

describe("the Microsoft provider", () => {
  it("declares the #2312 hooks: Graph 1-min windows, the shared sign-in rate, quota, overlap, retention", () => {
    const { provider } = session({});
    const ual = MICROSOFT_SOURCES.find((s) => s.id === UAL_SOURCE)!;
    expect(ual).toMatchObject({
      streamKind: "m365",
      minWindowMs: 60_000,
      queryCost: 1,
      overlapMs: 3_600_000,
    });
    expect(ual.partition).toEqual({ key: "recordType", values: UAL_RECORD_TYPES });
    expect(ual.retention).toMatchObject({ minDays: 180, maxDays: 365 });
    for (const id of [
      "entra-directory-audits",
      "entra-signins-interactive",
      "entra-signins-noninteractive",
      "entra-signins-serviceprincipal",
      "entra-signins-managedidentity",
    ]) {
      const s = MICROSOFT_SOURCES.find((x) => x.id === id)!;
      expect(s.rateLimit).toEqual({ requests: 5, perMs: 10_000, group: "graph-identity-reports" });
      expect(s).toMatchObject({
        streamKind: "m365",
        minWindowMs: 60_000,
        retention: { minDays: 7, maxDays: 30 },
      });
      expect(s.queryCost).toBeUndefined();
    }
    expect(MICROSOFT_SOURCES.find((s) => s.id === "azure-activity")).toMatchObject({
      streamKind: "cloud",
      retention: { minDays: 90 },
    });
    expect(provider.quotaScope?.({ tenantId: TENANT.toUpperCase() })).toBe(`microsoft:${TENANT}`);
    expect(provider.notes?.join(" ")).toMatch(/mailbox audit, transport rules and message trace/);
    expect(provider.notes?.join(" ")).toMatch(/Microsoft Extractor Suite \(MES\)/);
    expect(new Set(UAL_RECORD_TYPES).size).toBe(UAL_RECORD_TYPES.length);
    expect(UAL_RECORD_TYPES).toContain("exchangeAdmin");
    expect(UAL_RECORD_TYPES).not.toContain("unknownFutureValue");
  });

  it("puts sign-ins and directory audits on ONE limiter: Graph counts them together", () => {
    const keys = MICROSOFT_SOURCES.filter((s) => s.rateLimit).map((s) => rateKey(s.id, s.rateLimit!));
    expect(keys).toHaveLength(5);
    expect(new Set(keys)).toEqual(new Set(["group:graph-identity-reports"]));
    expect(rateKey("ct", { requests: 2, perMs: 1000 })).toBe("ct"); // no group: per source, as before
  });

  it("names the tenant and app in the identity, with the pinned API version per endpoint", async () => {
    const { session: s, tenant } = session({});
    const id = await s.identity();
    expect(id.accountRef).toBe(TENANT);
    expect(id.sdkVersions).toMatchObject({
      "graph:security/auditLog/queries": "v1.0",
      "graph:auditLogs/directoryAudits": "v1.0",
      "graph:auditLogs/signIns": "beta",
      "arm:Microsoft.Insights/eventtypes/management/values": "2015-04-01",
    });
    expect(tenant.requests).toEqual([]); // the identity costs no call
  });
});

describe("unified audit log: the AuditLogQuery lifecycle", () => {
  it("creates the query, polls it with the status shown, then pages /records — saved byte for byte", async () => {
    const ual = Array.from({ length: 5 }, (_, i) => graphUalRecord(i, at(i * 5)));
    const {
      session: s,
      tenant,
      clock,
    } = session({ ual, pollStatuses: ["notStarted", "running", "running"], pageSize: 2 });
    const statuses: string[] = [];
    const pages = await drain(s, req(UAL_SOURCE, { onStatus: (t) => statuses.push(t) }));
    expect(tenant.requests.map((r) => `${r.method} ${new URL(r.url).pathname}`)).toEqual([
      "POST /v1.0/security/auditLog/queries",
      "GET /v1.0/security/auditLog/queries/00000000-0000-4000-9000-000000000001",
      "GET /v1.0/security/auditLog/queries/00000000-0000-4000-9000-000000000001",
      "GET /v1.0/security/auditLog/queries/00000000-0000-4000-9000-000000000001",
      "GET /v1.0/security/auditLog/queries/00000000-0000-4000-9000-000000000001",
      "GET /v1.0/security/auditLog/queries/00000000-0000-4000-9000-000000000001/records",
      "GET /v1.0/security/auditLog/queries/00000000-0000-4000-9000-000000000001/records",
      "GET /v1.0/security/auditLog/queries/00000000-0000-4000-9000-000000000001/records",
    ]);
    expect(tenant.created).toEqual([
      expect.objectContaining({ filterStartDateTime: WINDOW.start, filterEndDateTime: WINDOW.end }),
    ]);
    expect(tenant.created[0]).not.toHaveProperty("recordTypeFilters");
    expect(statuses[0]).toMatch(/submitted/);
    expect(statuses.some((t) => /audit query running — /.test(t))).toBe(true);
    expect(statuses.some((t) => /audit query notStarted/.test(t))).toBe(true);
    expect(clock.sleeps).toEqual([10_000, 20_000, 40_000]); // backs off between polls
    expect(pages.map((p) => p.recordCount)).toEqual([2, 2, 1]);
    expect(pages.flatMap((p) => bodyOf(p).value.map((r: { id: string }) => r.id))).toHaveLength(5);
    expect(pages[0].requestParams).toMatchObject({ api: "Microsoft Graph v1.0", page: "first" });
    expect(pages[0].capped).toBeUndefined();
    // the saved body is the answer's own bytes
    const last = tenant.requests.at(-1)!;
    expect(last.url).toContain("$skiptoken=4");
  });

  it("marks the first page capped when the POLLED query says isRecordCountLimitExceeded", async () => {
    const ual = Array.from({ length: 4 }, (_, i) => graphUalRecord(i, at(i)));
    const { session: s } = session({ ual, recordCap: 3 });
    const page = await s.fetchPage(req(UAL_SOURCE));
    expect(page.capped).toBe(true);
    expect(page.requestParams.isRecordCountLimitExceeded).toBe("true");
  });

  it("filters a partition child by its record type", async () => {
    const { session: s, tenant } = session({ ual: [graphUalRecord(1, at(1))] });
    await s.fetchPage(req(UAL_SOURCE, { partition: { recordType: "exchangeAdmin" } }));
    expect(tenant.created[0].recordTypeFilters).toEqual(["exchangeAdmin"]);
  });

  it("fails with the reason when the query ends failed, and when it never finishes", async () => {
    const failed = session({ failQueries: true });
    await expect(failed.session.fetchPage(req(UAL_SOURCE))).rejects.toThrow(/ended "failed"/);
    const slow = session({ pollStatuses: Array(200).fill("running") });
    await expect(slow.session.fetchPage(req(UAL_SOURCE))).rejects.toThrow(/still "running" after 6\d min/);
  });

  it("returns a throttled CREATE to the engine as RateLimitedError with its Retry-After", async () => {
    const { session: s } = session({ throttle: { match: /queries$/, times: 1, retryAfter: "7" } });
    const err = await s.fetchPage(req(UAL_SOURCE)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RateLimitedError);
    expect((err as RateLimitedError).retryAfterMs).toBe(7000);
  });

  it("waits out a throttled POLL itself, and reuses a created query after a throttled first page", async () => {
    const polled = session({
      ual: [graphUalRecord(1, at(1))],
      throttle: { match: /queries\/[^/]+$/, times: 1 },
    });
    await polled.session.fetchPage(req(UAL_SOURCE));
    expect(polled.tenant.created).toHaveLength(1);

    const paged = session({ ual: [graphUalRecord(1, at(1))], throttle: { match: /\/records$/, times: 1 } });
    await expect(paged.session.fetchPage(req(UAL_SOURCE))).rejects.toBeInstanceOf(RateLimitedError);
    await paged.session.fetchPage(req(UAL_SOURCE)); // the engine's retry
    expect(paged.tenant.created).toHaveLength(1); // no second submission
  });

  it("turns a next-page link the cloud no longer accepts into CursorExpiredError", async () => {
    const { session: s } = session({});
    const stale = "https://graph.microsoft.com/v1.0/security/auditLog/queries/gone/records?$skiptoken=9";
    await expect(s.fetchPage(req(UAL_SOURCE, { pageToken: stale }))).rejects.toBeInstanceOf(
      CursorExpiredError,
    );
  });

  it("never sends the bearer token outside graph.microsoft.com", async () => {
    const { session: s, tenant } = session({});
    const evil = "https://graph.microsoft.com.example.net/v1.0/x";
    await expect(s.fetchPage(req(UAL_SOURCE, { pageToken: evil }))).rejects.toThrow(
      /outside graph\.microsoft\.com/,
    );
    await expect(
      s.fetchPage(req("entra-signins-interactive", { pageToken: "http://graph.microsoft.com/beta/x" })),
    ).rejects.toThrow(/not followed/);
    expect(tenant.requests).toEqual([]);
  });
});

describe("Entra: directory audits and four explicit sign-in categories", () => {
  const types = ["interactiveUser", "nonInteractiveUser", "servicePrincipal", "managedIdentity"];
  const signIns = types.flatMap((t, k) => [
    signInRecord(k * 10, at(k), t),
    signInRecord(k * 10 + 1, at(k + 30), t),
  ]);

  it("asks each category with its own signInEventTypes filter, on beta, and gets only that category", async () => {
    const { session: s, tenant } = session({ signIns });
    const sources = [
      ["entra-signins-interactive", "interactiveUser"],
      ["entra-signins-noninteractive", "nonInteractiveUser"],
      ["entra-signins-serviceprincipal", "servicePrincipal"],
      ["entra-signins-managedidentity", "managedIdentity"],
    ] as const;
    for (const [source, type] of sources) {
      const page = await s.fetchPage(req(source));
      expect(page.requestParams).toMatchObject({ api: "Microsoft Graph beta", signInEventType: type });
      const got = bodyOf(page).value as Array<{ signInEventTypes: string[] }>;
      expect(got).toHaveLength(2);
      expect(got.every((r) => r.signInEventTypes[0] === type)).toBe(true);
    }
    const filters = tenant.requests.map((r) => new URL(r.url));
    expect(filters.every((u) => u.pathname === "/beta/auditLogs/signIns")).toBe(true);
    expect(filters.map((u) => u.searchParams.get("$filter"))).toEqual(
      types.map(
        (t) =>
          `createdDateTime ge 2026-10-01T10:00:00Z and createdDateTime lt 2026-10-01T11:00:00Z and signInEventTypes/any(t: t eq '${t}')`,
      ),
    );
    expect(filters.every((u) => u.searchParams.get("$top") === "1000")).toBe(true);
  });

  it("reads directory audits on v1.0 with a time filter, following @odata.nextLink", async () => {
    const audits = Array.from({ length: 3 }, (_, i) => directoryAuditRecord(i, at(i * 10)));
    const { session: s, tenant } = session({ directoryAudits: audits, pageSize: 2 });
    const pages = await drain(s, req("entra-directory-audits"));
    expect(pages.map((p) => p.recordCount)).toEqual([2, 1]);
    expect(new URL(tenant.requests[0].url).pathname).toBe("/v1.0/auditLogs/directoryAudits");
    expect(new URL(tenant.requests[0].url).searchParams.get("$filter")).toBe(
      "activityDateTime ge 2026-10-01T10:00:00Z and activityDateTime lt 2026-10-01T11:00:00Z",
    );
  });

  it("returns a 429 as RateLimitedError", async () => {
    const { session: s } = session({ throttle: { match: /signIns/, times: 1, retryAfter: "3" } });
    await expect(s.fetchPage(req("entra-signins-interactive"))).rejects.toMatchObject({ retryAfterMs: 3000 });
  });
});

describe("Azure Activity: every readable subscription", () => {
  it("walks each subscription in id order, then its pages, and names the subscription per page", async () => {
    const activity = {
      [SUB_A]: [
        activityRecord(1, at(1), SUB_A),
        activityRecord(2, at(2), SUB_A),
        activityRecord(3, at(3), SUB_A),
      ],
      [SUB_B]: [activityRecord(4, at(4), SUB_B)],
    };
    const { session: s, tenant } = session({ subscriptions: [SUB_B, SUB_A], activity, pageSize: 2 });
    const pages = await drain(s, req("azure-activity"));
    expect(pages.map((p) => [p.requestParams.subscriptionId, p.recordCount])).toEqual([
      [SUB_A, 2],
      [SUB_A, 1],
      [SUB_B, 1],
    ]);
    const first = new URL(tenant.requests[1].url);
    expect(first.searchParams.get("api-version")).toBe("2015-04-01");
    expect(first.searchParams.get("$filter")).toBe(
      "eventTimestamp ge '2026-10-01T10:00:00.000Z' and eventTimestamp le '2026-10-01T10:59:59.999Z'",
    );
    expect(tenant.requests.filter((r) => new URL(r.url).pathname === "/subscriptions")).toHaveLength(1);
  });

  it("fails with what to grant when the app can read no subscription", async () => {
    const { session: s } = session({ subscriptions: [] });
    await expect(s.fetchPage(req("azure-activity"))).rejects.toThrow(NO_SUBSCRIPTION);
  });
});

describe("a session that cannot open", () => {
  it("answers every call with the fixed reason", async () => {
    const provider = microsoftCollectProvider({
      wire: () => {
        throw new Error(
          "the stored PFX certificate could not be opened (wrong password or unsupported format)",
        );
      },
    });
    const s = provider.open(account);
    await expect(s.identity()).rejects.toThrow(/could not be opened/);
    await expect(s.fetchPage(req(UAL_SOURCE))).rejects.toThrow(/could not be opened/);
  });
});
