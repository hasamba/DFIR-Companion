// #1024: the other providers' dated facts, each of its kind and with its own fixture; per-backend
// outcome envelopes; the service keeping an errored backend's last-known state and retrying it.
import { describe, expect, it } from "vitest";
import { fetchMock, jsonResponse } from "../helpers/fetchMock.js";
import { HuntingChProvider } from "../../src/enrichment/huntingch.js";
import { MispProvider } from "../../src/enrichment/misp.js";
import { OpenCtiProvider } from "../../src/enrichment/opencti.js";
import { enrichIocs } from "../../src/enrichment/enrichService.js";
import type { EnrichmentProvider, EnrichmentResult } from "../../src/enrichment/provider.js";
import { intelTemporal } from "../../src/analysis/intelTemporal.js";
import type { IOC } from "../../src/analysis/stateTypes.js";

const HASH = "00c3e0990cada07e01a3b842cf3d36f36c6ec7dd7d3c1aba430c08d885d66567";
const noSleep = async () => {};

describe("Hunting.ch — per-backend outcomes and dated facts", () => {
  it("each backend reports hit / miss / error / not-queried on its own; a structured failure is an error, never a miss", async () => {
    const fetchFn = fetchMock(async (url) => {
      const host = new URL(url).host;
      if (host === "mb-api.abuse.ch") return jsonResponse({ query_status: "hash_not_found" });
      if (host === "threatfox-api.abuse.ch")
        return jsonResponse({ query_status: "ok", data: { unexpected: "object" } });
      if (host === "urlhaus-api.abuse.ch") return jsonResponse({ query_status: "invalid_sha256_hash" });
      return jsonResponse({ query_status: "no_results" });
    });
    const h = new HuntingChProvider({ apiKey: "k", fetchFn });
    const d = await h.lookupDetailed("hash", HASH);
    expect(d.results).toHaveLength(0);
    expect(Object.fromEntries(d.backends.map((b) => [b.name, b.outcome]))).toEqual({
      MalwareBazaar: "miss",
      ThreatFox: "error",
      URLhaus: "error",
      YARAify: "miss",
    });
    const ip = await h.lookupDetailed("ip", "203.0.113.5");
    expect(
      ip.backends
        .filter((b) => b.outcome === "not-queried")
        .map((b) => b.name)
        .sort(),
    ).toEqual(["MalwareBazaar", "YARAify"]);
  });

  it("ThreatFox: first_seen / last_seen are an observation interval, the ioc id is the record, the six-month API expiry rides as a note", async () => {
    const fetchFn = fetchMock(async (url) => {
      const host = new URL(url).host;
      if (host === "threatfox-api.abuse.ch")
        return jsonResponse({
          query_status: "ok",
          data: [
            {
              id: "1234",
              confidence_level: 75,
              malware_printable: "Cobalt Strike",
              threat_type: "botnet_cc",
              first_seen: "2026-01-10 09:00:00 UTC",
              last_seen: "2026-02-01 12:00:00 UTC",
            },
          ],
        });
      return jsonResponse({ query_status: "no_results" });
    });
    const h = new HuntingChProvider({ apiKey: "k", fetchFn });
    const d = await h.lookupDetailed("ip", "203.0.113.5");
    const tf = d.results.find((r) => r.source === "ThreatFox")!;
    expect(tf).toMatchObject({
      providerRecordId: "1234",
      temporal: { observedFrom: "2026-01-10T09:00:00Z", observedTo: "2026-02-01T12:00:00Z" },
    });
    expect(tf.note).toContain(
      "ThreatFox removes IOCs older than six months from its API; a miss is not a withdrawal",
    );
    const words = intelTemporal(
      { ...tf, fetchedAt: "2026-03-01T00:00:00Z" },
      { basis: "authoritative", from: "2026-01-20T00:00:00Z" },
      "2026-03-01T00:00:00Z",
    ).words;
    expect(words).toContain("observed by the provider 2026-01-10 → 2026-02-01");
    expect(words).toContain("ThreatFox removes IOCs");
  });

  it("URLhaus: a URL's date_added is a dataset date (never infrastructure creation), last_online only when reported; a host's nested list past 100 is truncated", async () => {
    const fetchFn = fetchMock(async (url, init) => {
      const body = String(init?.body ?? "");
      if (body.startsWith("url="))
        return jsonResponse({
          query_status: "ok",
          id: "77",
          url_status: "online",
          date_added: "2026-01-05 08:00:00 UTC",
          last_online: "2026-02-02 10:00:00 UTC",
          threat: "malware_download",
        });
      if (body.startsWith("host="))
        return jsonResponse({
          query_status: "ok",
          url_count: 250,
          firstseen: "2025-12-01 00:00:00 UTC",
          urls: Array.from({ length: 100 }, (_, i) => ({ id: String(i) })),
        });
      return jsonResponse({ query_status: "no_results" });
    });
    const h = new HuntingChProvider({ apiKey: "k", fetchFn });
    const u = (await h.lookupDetailed("url", "http://evil.invalid/x")).results.find(
      (r) => r.source === "URLhaus",
    )!;
    expect(u).toMatchObject({
      providerRecordId: "77",
      temporal: { addedAt: "2026-01-05T08:00:00Z", lastOnlineAt: "2026-02-02T10:00:00Z" },
    });
    const words = intelTemporal(
      { ...u, fetchedAt: "2026-03-01T00:00:00Z" },
      { basis: "none", importedAt: "2026-03-01T00:00:00Z" },
      "2026-03-01T00:00:00Z",
    ).words;
    expect(words).toContain("added to the provider's dataset on 2026-01-05");
    expect(words).toContain("not when the infrastructure came to exist");
    expect(words).not.toMatch(/created|came to exist on/);
    const host = await h.lookupDetailed("domain", "evil.invalid");
    const hu = host.results.find((r) => r.source === "URLhaus")!;
    expect(hu.temporal).toMatchObject({ observedFrom: "2025-12-01T00:00:00Z", truncated: true });
    expect(host.backends.find((b) => b.name === "URLhaus")).toMatchObject({
      outcome: "hit",
      incomplete: true,
    });
  });
});

describe("MISP — pages, deletions, one assertion per attribute", () => {
  const attr = (over: Record<string, unknown>) => ({
    uuid: `u-${String(over.id ?? "1")}`,
    type: "ip-dst",
    value: "203.0.113.5",
    to_ids: true,
    timestamp: "1767225600",
    first_seen: "2026-01-01T00:00:00.000000+00:00",
    last_seen: "2026-01-15T00:00:00.000000+00:00",
    Event: {
      id: "42",
      info: "campaign",
      threat_level_id: "1",
      date: "2025-12-31",
      publish_timestamp: "1767312000",
      Orgc: { id: "2", name: "ACME" },
    },
    ...over,
  });
  it("asks for deleted attributes and pages; a deleted attribute is revoked, kept as history; intervals are kept per attribute", async () => {
    const fetchFn = fetchMock(async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as { page: number; limit: number; deleted: unknown };
      expect(body.deleted).toEqual([0, 1]);
      if (body.page === 1)
        return jsonResponse({
          response: {
            Attribute: Array.from({ length: body.limit }, (_, i) =>
              attr({
                id: String(i),
                first_seen: `2026-01-${String((i % 28) + 1).padStart(2, "0")}T00:00:00+00:00`,
              }),
            ),
          },
        });
      return jsonResponse({ response: { Attribute: [attr({ id: "x", deleted: true })] } });
    });
    const misp = new MispProvider({ baseUrl: "https://misp.example.invalid", apiKey: "k", fetchFn });
    const d = await misp.lookupDetailed("ip", "203.0.113.5");
    expect(fetchFn.mock.calls).toHaveLength(2);
    expect(d.backends[0]).toMatchObject({ name: "MISP", outcome: "hit" });
    expect(d.backends[0].incomplete).toBeUndefined();
    expect(d.results).toHaveLength(32);
    const last = d.results[d.results.length - 1];
    expect(last.score).toContain("+69 more attribute(s) not listed");
    // One assertion per attribute: its own uuid, its own interval — never one span.
    expect(d.results[0].providerRecordId).toBe("u-0");
    expect(d.results[0].temporal?.observedFrom).toBe("2026-01-01T00:00:00+00:00");
    expect(d.results[1].temporal?.observedFrom).toBe("2026-01-02T00:00:00+00:00");
    expect(d.results[0].temporal).toMatchObject({
      recordEditedAt: "2026-01-01T00:00:00.000Z",
      eventDate: "2025-12-31",
      publishedAt: "2026-01-02T00:00:00.000Z",
    });
    const words = intelTemporal(
      { ...d.results[0], fetchedAt: "2026-03-01T00:00:00Z" },
      { basis: "none", importedAt: "2026-03-01T00:00:00Z" },
      "2026-03-01T00:00:00Z",
    ).words;
    expect(words).toContain("the event's stated date 2025-12-31 (as recorded, not an observation)");
    expect(words).toContain("record created or last edited 2026-01-01 (not an observation)");
  });
  it("a deleted attribute on the first page is revoked; a read cut at the page bound is incomplete", async () => {
    const fetchFn = fetchMock(async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as { page: number; limit: number };
      if (body.page === 1)
        return jsonResponse({ response: { Attribute: [attr({ id: "d", deleted: true })] } });
      return jsonResponse({ response: { Attribute: [] } });
    });
    const misp = new MispProvider({ baseUrl: "https://misp.example.invalid", apiKey: "k", fetchFn });
    const d = await misp.lookupDetailed("ip", "203.0.113.5");
    expect(d.results[0]).toMatchObject({ revoked: true });
    expect(d.results[0].score).toContain("deleted on the MISP instance; kept as history");
    const full = fetchMock(async (_url, init) => {
      const body = JSON.parse(String(init?.body)) as { limit: number };
      return jsonResponse({
        response: { Attribute: Array.from({ length: body.limit }, (_, i) => attr({ id: String(i) })) },
      });
    });
    const bounded = await new MispProvider({
      baseUrl: "https://misp.example.invalid",
      apiKey: "k",
      fetchFn: full,
    }).lookupDetailed("ip", "203.0.113.5");
    expect(bounded.backends[0]).toMatchObject({ outcome: "hit", incomplete: true });
    expect(full.mock.calls).toHaveLength(64);
  });
});

describe("OpenCTI — indicators, validity, revocation, pagination", () => {
  const observable = (indicators: Record<string, unknown>[], hasNext = false) => ({
    id: "obs-1",
    observable_value: "203.0.113.5",
    x_opencti_score: 80,
    objectLabel: [],
    indicators: { edges: indicators.map((node) => ({ node })), pageInfo: { hasNextPage: hasNext } },
    createdBy: { name: "ACME" },
  });
  it("an expired indicator beside a live one on the same observable is two assertions, one actionable; a revoked one is marked", async () => {
    const fetchFn = fetchMock(async () =>
      jsonResponse({
        data: {
          stixCyberObservables: {
            edges: [
              {
                node: observable([
                  {
                    id: "ind-live",
                    valid_from: "2026-01-01T00:00:00.000Z",
                    valid_until: "2027-01-01T00:00:00.000Z",
                    revoked: false,
                    x_opencti_score: 90,
                    created: "2025-12-30T00:00:00.000Z",
                  },
                  {
                    id: "ind-old",
                    valid_from: "2025-01-01T00:00:00.000Z",
                    valid_until: "2025-06-01T00:00:00.000Z",
                    revoked: false,
                    x_opencti_score: 90,
                    created: "2024-12-30T00:00:00.000Z",
                  },
                  {
                    id: "ind-rev",
                    valid_from: "2026-01-01T00:00:00.000Z",
                    valid_until: null,
                    revoked: true,
                    x_opencti_score: 90,
                    created: "2025-12-30T00:00:00.000Z",
                  },
                ]),
              },
            ],
            pageInfo: { endCursor: "c1", hasNextPage: false },
          },
        },
      }),
    );
    const octi = new OpenCtiProvider({ baseUrl: "https://opencti.invalid", apiKey: "k", fetchFn });
    const d = await octi.lookupDetailed("ip", "203.0.113.5");
    expect(d.results).toHaveLength(3);
    const byId = new Map(d.results.map((r) => [r.providerRecordId, r]));
    expect(byId.get("ind-live")).toMatchObject({
      validity: { from: "2026-01-01T00:00:00.000Z", until: "2027-01-01T00:00:00.000Z" },
      temporal: { createdAt: "2025-12-30T00:00:00.000Z" },
    });
    expect(byId.get("ind-old")).toMatchObject({ validity: { until: "2025-06-01T00:00:00.000Z" } });
    expect(byId.get("ind-rev")).toMatchObject({ revoked: true });
    expect(byId.get("ind-rev")!.score).toContain("revoked");
    // Through the service: the expired and revoked ones are not live.
    const { iocs } = await enrichIocs(
      [{ id: "i1", type: "ip", value: "203.0.113.5", firstSeen: "2026-03-01T00:00:00Z" }],
      {
        providers: [octi],
        sleep: noSleep,
        now: () => "2026-03-01T00:00:00Z",
      },
    );
    const statuses = Object.fromEntries(iocs[0].enrichments!.map((e) => [e.providerRecordId, e.status]));
    expect(statuses).toEqual({ "ind-live": "live", "ind-old": "expired", "ind-rev": "revoked" });
    const words = intelTemporal(
      { ...byId.get("ind-old")!, fetchedAt: "2026-03-01T00:00:00Z" },
      { basis: "none", importedAt: "2026-03-01T00:00:00Z" },
      "2026-03-01T00:00:00Z",
    ).words;
    expect(words).toContain("valid from 2025-01-01 until 2025-06-01 — the assertion's validity ended");
    expect(words).toContain("object created 2024-12-30 (creation, not publication, not an observation)");
  });
  it("the search is paged until the exact value is found; a bound reached first is an incomplete error, never a miss", async () => {
    let page = 0;
    const fetchFn = fetchMock(async () => {
      page += 1;
      return jsonResponse({
        data: {
          stixCyberObservables: {
            edges: Array.from({ length: 50 }, (_, i) => ({
              node: {
                id: `near-${page}-${i}`,
                observable_value: `203.0.113.${i}x`,
                indicators: { edges: [] },
              },
            })),
            pageInfo: { endCursor: `c${page}`, hasNextPage: true },
          },
        },
      });
    });
    const octi = new OpenCtiProvider({ baseUrl: "https://opencti.invalid", apiKey: "k", fetchFn });
    const d = await octi.lookupDetailed("ip", "203.0.113.5");
    expect(d.results).toHaveLength(0);
    expect(d.backends[0]).toMatchObject({ outcome: "error", incomplete: true });
    expect(page).toBe(8);
    await expect(octi.lookup("ip", "203.0.113.5")).rejects.toThrow(/search bound/);
  });
});

describe("enrichService — backend errors keep the last-known state and are retried", () => {
  const ioc = (over: Partial<IOC> = {}): IOC => ({
    id: "i1",
    type: "hash",
    value: HASH,
    firstSeen: "2026-01-01T00:00:00Z",
    ...over,
  });
  it("ThreatFox errors while the others answer: its assertion stays last-known, the provider is not cached as checked, the next run retries", async () => {
    let tfFails = true;
    const tf = (): EnrichmentResult => ({ source: "ThreatFox", verdict: "malicious", providerRecordId: "9" });
    const provider: EnrichmentProvider = {
      name: "Hunting.ch",
      scope: "external",
      supports: () => true,
      lookup: async () => [],
      lookupDetailed: async () => ({
        results: tfFails ? [] : [tf()],
        backends: [
          { name: "MalwareBazaar", outcome: "miss" },
          {
            name: "ThreatFox",
            outcome: tfFails ? "error" : "hit",
            ...(tfFails ? { detail: "timeout" } : {}),
          },
          { name: "URLhaus", outcome: "miss" },
          { name: "YARAify", outcome: "miss" },
        ],
      }),
    };
    const seeded = ioc({
      enrichments: [
        {
          source: "ThreatFox",
          provider: "Hunting.ch",
          verdict: "malicious",
          fetchedAt: "2026-01-01T00:00:00Z",
          providerRecordId: "9",
          status: "live",
        },
      ],
      enrichedBy: ["Hunting.ch"],
    });
    const first = await enrichIocs([seeded], {
      providers: [provider],
      sleep: noSleep,
      now: () => "2026-02-01T00:00:00Z",
      force: true,
    });
    expect(first.summary.errors).toBe(1);
    expect(first.iocs[0].enrichments![0].status).toBe("errored-last-known");
    expect(first.iocs[0].intelChecks!["Hunting.ch|ThreatFox"]).toMatchObject({
      outcome: "error",
      detail: "timeout",
    });
    // A non-forced run still queries: the provider is not "checked" while a backend's last outcome is an error.
    tfFails = false;
    const second = await enrichIocs(first.iocs, {
      providers: [provider],
      sleep: noSleep,
      now: () => "2026-02-02T00:00:00Z",
    });
    expect(second.summary.queried).toBe(1);
    expect(second.iocs[0].enrichments![0].status).toBe("live");
    const third = await enrichIocs(second.iocs, {
      providers: [provider],
      sleep: noSleep,
      now: () => "2026-02-03T00:00:00Z",
    });
    expect(third.summary.queried).toBe(0);
  });
});
