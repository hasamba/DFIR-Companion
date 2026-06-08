import { describe, it, expect, vi } from "vitest";
import { VirusTotalProvider } from "../../src/enrichment/virustotal.js";
import { HuntingChProvider } from "../../src/enrichment/huntingch.js";
import { AbuseIpdbProvider } from "../../src/enrichment/abuseipdb.js";
import { MispProvider } from "../../src/enrichment/misp.js";
import { RockyRaccoonProvider } from "../../src/enrichment/rockyraccoon.js";
import { YetiProvider } from "../../src/enrichment/yeti.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("VirusTotalProvider", () => {
  it("maps last_analysis_stats to a malicious verdict with detections and a link", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      data: { id: "abc", attributes: {
        last_analysis_stats: { malicious: 52, suspicious: 1, harmless: 10, undetected: 10 },
        popular_threat_classification: { suggested_threat_label: "trojan.mimikatz" },
      } },
    }));
    const vt = new VirusTotalProvider({ apiKey: "k", fetchFn });
    const r = await vt.lookup("hash", "deadbeef");
    expect(r).toMatchObject({ source: "VirusTotal", verdict: "malicious", detections: 52, total: 73 });
    expect(r!.score).toBe("52/73 detections");
    expect(r!.tags).toContain("trojan.mimikatz");
    expect(r!.link).toContain("/gui/file/");
    expect((fetchFn.mock.calls[0][1] as RequestInit).headers).toMatchObject({ "x-apikey": "k" });
  });

  it("returns null on 404 (unknown indicator) and throws on 429 (rate limit)", async () => {
    const nf = new VirusTotalProvider({ apiKey: "k", fetchFn: vi.fn(async () => new Response("", { status: 404 })) });
    expect(await nf.lookup("ip", "1.2.3.4")).toBeNull();
    const rl = new VirusTotalProvider({ apiKey: "k", fetchFn: vi.fn(async () => new Response("", { status: 429 })) });
    await expect(rl.lookup("hash", "x")).rejects.toThrow(/rate limit/i);
  });

  it("addresses a URL by unpadded base64url", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ data: { id: "u", attributes: { last_analysis_stats: { malicious: 0, harmless: 80 } } } }));
    const vt = new VirusTotalProvider({ apiKey: "k", fetchFn });
    await vt.lookup("url", "http://evil.test/x");
    const calledUrl = fetchFn.mock.calls[0][0] as string;
    expect(calledUrl).toContain("/urls/");
    expect(calledUrl).not.toContain("=");           // base64url, no padding
  });
});

describe("HuntingChProvider (abuse.ch unified hunt)", () => {
  // Route an abuse.ch POST by its host to the right per-platform fixture.
  function huntFetch(byHost: Record<string, unknown>, opts: { authFail?: boolean; failHosts?: string[] } = {}) {
    return vi.fn(async (url: string, init?: RequestInit) => {
      // Every back-end must carry the unified Auth-Key.
      expect((init!.headers as Record<string, string>)["Auth-Key"]).toBe("k");
      if (opts.authFail) return new Response("", { status: 403 });
      const host = new URL(url).host;
      if (opts.failHosts?.includes(host)) return new Response("", { status: 500 });
      const body = byHost[host];
      if (body === undefined) throw new Error("unexpected host " + host);
      return jsonResponse(body);
    });
  }

  it("a hash fans out to MalwareBazaar + ThreatFox + URLhaus + YARAify as four separate, clickable results", async () => {
    const fetchFn = huntFetch({
      "mb-api.abuse.ch": { query_status: "ok", data: [{ sha256_hash: "ABCD", signature: "Neshta", tags: ["neshta"], file_type: "exe" }] },
      "threatfox-api.abuse.ch": { query_status: "ok", data: [{ id: "9", threat_type: "payload_delivery", malware_printable: "Neshta", confidence_level: 75 }] },
      "urlhaus-api.abuse.ch": { query_status: "ok", signature: "Neshta", url_count: 3, urlhaus_reference: "https://urlhaus.abuse.ch/browse.php?search=ABCD" },
      "yaraify-api.abuse.ch": { query_status: "ok", data: { metadata: { sha256_hash: "ABCD" }, tasks: [{ static_results: [{ rule_name: "MALWARE_Win_Neshta" }], clamav_results: ["Win.Dropper-1"] }] } },
    });
    const h = new HuntingChProvider({ apiKey: "k", fetchFn });
    const r = await h.lookup("hash", "00c3e0990cada07e01a3b842cf3d36f36c6ec7dd7d3c1aba430c08d885d66567");
    expect(Array.isArray(r)).toBe(true);
    const bySource = Object.fromEntries((r as Array<{ source: string }>).map((e) => [e.source, e]));
    expect(Object.keys(bySource).sort()).toEqual(["MalwareBazaar", "ThreatFox", "URLhaus", "YARAify"]);
    expect(bySource["MalwareBazaar"]).toMatchObject({ verdict: "malicious", link: "https://bazaar.abuse.ch/sample/ABCD/" });
    expect(bySource["YARAify"]).toMatchObject({ verdict: "malicious", link: "https://yaraify.abuse.ch/sample/ABCD/" });
    expect((bySource["YARAify"] as { score: string }).score).toContain("YARA rule");
    expect((bySource["URLhaus"] as { link: string }).link).toContain("urlhaus.abuse.ch");
    expect((bySource["ThreatFox"] as { link: string }).link).toBe("https://threatfox.abuse.ch/ioc/9/");
  });

  it("an IP queries only ThreatFox + URLhaus(host); platforms with no hit are omitted", async () => {
    const fetchFn = huntFetch({
      "threatfox-api.abuse.ch": { query_status: "ok", data: [{ id: "2", threat_type: "botnet_cc", malware_printable: "Cobalt Strike", confidence_level: 100 }] },
      "urlhaus-api.abuse.ch": { query_status: "no_results" },
    });
    const h = new HuntingChProvider({ apiKey: "k", fetchFn });
    const r = (await h.lookup("ip", "139.180.203.104")) as Array<{ source: string }>;
    expect(r.map((e) => e.source)).toEqual(["ThreatFox"]);   // URLhaus had no_results → dropped
    // search_ioc with exact match, never search_hash, for a non-hash indicator.
    const tfBody = JSON.parse((fetchFn.mock.calls.find((c) => String(c[0]).includes("threatfox"))![1] as RequestInit).body as string);
    expect(tfBody).toMatchObject({ query: "search_ioc", search_term: "139.180.203.104", exact_match: true });
    expect(h.supports("process")).toBe(false);
    expect(h.supports("url")).toBe(true);
  });

  it("returns [] (checked, nothing tracked) when no platform has the indicator", async () => {
    const fetchFn = huntFetch({
      "threatfox-api.abuse.ch": { query_status: "no_result", data: "" },
      "urlhaus-api.abuse.ch": { query_status: "no_results" },
    });
    const h = new HuntingChProvider({ apiKey: "k", fetchFn });
    expect(await h.lookup("domain", "evil.test")).toEqual([]);
  });

  it("surfaces an auth error only when NOTHING answered (shared key rejected, no anon hit)", async () => {
    const h = new HuntingChProvider({ apiKey: "k", fetchFn: huntFetch({}, { authFail: true }) });
    await expect(h.lookup("ip", "1.2.3.4")).rejects.toThrow(/auth failed/i);
  });

  it("still returns YARAify (anonymous) even when the key-gated platforms 401", async () => {
    // A missing/expired key 401s MalwareBazaar/ThreatFox/URLhaus, but YARAify needs no key —
    // its hit must NOT be discarded by the others' auth failure.
    const fetchFn = vi.fn(async (url: string) => {
      if (new URL(url).host === "yaraify-api.abuse.ch") {
        return jsonResponse({ query_status: "ok", data: { metadata: { sha256_hash: "ABCD" }, tasks: [{ static_results: [{ rule_name: "MALWARE_Win_X" }] }] } });
      }
      return new Response("", { status: 401 });   // MB / ThreatFox / URLhaus
    });
    const h = new HuntingChProvider({ apiKey: "k", fetchFn });
    const r = (await h.lookup("hash", "7c26003b25a03f34ac2ddd11324d2501506ef7fa694cac3ec9d63717d3071783")) as Array<{ source: string }>;
    expect(r.map((e) => e.source)).toEqual(["YARAify"]);
  });

  it("still returns the platforms that answered when another is transiently down", async () => {
    const fetchFn = huntFetch(
      { "threatfox-api.abuse.ch": { query_status: "ok", data: [{ id: "5", malware_printable: "Qakbot", confidence_level: 80 }] }, "urlhaus-api.abuse.ch": {} },
      { failHosts: ["urlhaus-api.abuse.ch"] },
    );
    const h = new HuntingChProvider({ apiKey: "k", fetchFn });
    const r = (await h.lookup("domain", "bad.test")) as Array<{ source: string }>;
    expect(r.map((e) => e.source)).toEqual(["ThreatFox"]);   // URLhaus 500 swallowed, ThreatFox hit kept
  });
});

describe("AbuseIpdbProvider", () => {
  it("maps a high confidence score to malicious", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ data: { abuseConfidenceScore: 100, totalReports: 42, countryCode: "RU" } }));
    const ab = new AbuseIpdbProvider({ apiKey: "k", fetchFn });
    const r = await ab.lookup("ip", "1.2.3.4");
    expect(r).toMatchObject({ source: "AbuseIPDB", verdict: "malicious", detections: 42 });
    expect(r!.score).toContain("100% abuse");
    expect(r!.tags).toContain("RU");
    expect(ab.supports("hash")).toBe(false);
  });

  it("maps a zero score to harmless", async () => {
    const ab = new AbuseIpdbProvider({ apiKey: "k", fetchFn: vi.fn(async () => jsonResponse({ data: { abuseConfidenceScore: 0 } })) });
    expect((await ab.lookup("ip", "8.8.8.8"))!.verdict).toBe("harmless");
  });
});

describe("MispProvider", () => {
  it("reports a matched attribute (to_ids) as malicious with event tags + link", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      response: { Attribute: [
        { type: "sha256", value: "abcd", to_ids: true, event_id: "42",
          Event: { id: "42", info: "TrickBot campaign", threat_level_id: "1" },
          Tag: [{ name: "tlp:amber" }, { name: "malware:trickbot" }] },
      ] },
    }));
    const misp = new MispProvider({ baseUrl: "https://misp.example.org/", apiKey: "k", fetchFn });
    const r = await misp.lookup("hash", "abcd");
    expect(r).toMatchObject({ source: "MISP", verdict: "malicious", detections: 1 });
    expect(r!.score).toContain("TrickBot campaign");
    expect(r!.tags).toEqual(expect.arrayContaining(["tlp:amber", "malware:trickbot"]));
    expect(r!.link).toBe("https://misp.example.org/events/view/42");
    // Auth header sent, trailing slash on baseUrl normalized.
    const init = fetchFn.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe("k");
    expect(fetchFn.mock.calls[0][0]).toBe("https://misp.example.org/attributes/restSearch");
  });

  it("treats a match without to_ids / high threat level as suspicious", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ response: { Attribute: [{ type: "ip-dst", value: "1.2.3.4", to_ids: false, Event: { id: "7", threat_level_id: "3" } }] } }));
    const misp = new MispProvider({ baseUrl: "https://m", apiKey: "k", fetchFn });
    expect((await misp.lookup("ip", "1.2.3.4"))!.verdict).toBe("suspicious");
  });

  it("returns null when the indicator is not present on the instance, and does not support process names", async () => {
    const misp = new MispProvider({ baseUrl: "https://m", apiKey: "k", fetchFn: vi.fn(async () => jsonResponse({ response: { Attribute: [] } })) });
    expect(await misp.lookup("domain", "evil.test")).toBeNull();
    expect(misp.supports("hash")).toBe(true);
    expect(misp.supports("process")).toBe(false);
  });

  it("probe() hits the version endpoint with auth; resolves when up, throws on 401 / unreachable", async () => {
    const okFetch = vi.fn(async () => jsonResponse({ version: "2.4.190" }));
    const misp = new MispProvider({ baseUrl: "https://misp.example.org/", apiKey: "k", fetchFn: okFetch });
    await expect(misp.probe()).resolves.toBeUndefined();
    expect(okFetch.mock.calls[0][0]).toBe("https://misp.example.org/servers/getVersion");
    expect((okFetch.mock.calls[0][1] as RequestInit).method).toBe("GET");
    expect(((okFetch.mock.calls[0][1] as RequestInit).headers as Record<string, string>).Authorization).toBe("k");

    const auth = new MispProvider({ baseUrl: "https://m", apiKey: "bad", fetchFn: vi.fn(async () => new Response("", { status: 403 })) });
    await expect(auth.probe()).rejects.toThrow(/auth failed/i);

    const dead = new MispProvider({ baseUrl: "https://m", apiKey: "k", fetchFn: vi.fn(async () => { throw new Error("fetch failed"); }) });
    await expect(dead.probe()).rejects.toThrow(/fetch failed/i);
  });
});

describe("RockyRaccoonProvider (process intel)", () => {
  it("only supports process IOCs and flags a LOLBIN as suspicious with context", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      process_name: "powershell.exe",
      classification: { category: "Scripting", is_lolbin: true, risk_level: "high", expected_parent: "explorer.exe" },
      intel: { mitre_techniques: ["T1059.001"] },
      executions: { total: 2847103, confidence: "high" },
    }));
    const rr = new RockyRaccoonProvider({ apiKey: "et_live_x", fetchFn });
    expect(rr.supports("process")).toBe(true);
    expect(rr.supports("hash")).toBe(false);
    const r = await rr.lookup("process", "powershell.exe");
    expect(r).toMatchObject({ source: "RockyRaccoon", verdict: "suspicious" });
    expect(r!.tags).toEqual(expect.arrayContaining(["Scripting", "LOLBIN", "T1059.001"]));
    expect(r!.score).toContain("2.8M executions");
    expect(r!.score).toContain("expected parent explorer.exe");
    // Bearer auth + basename extraction from a path.
    expect((fetchFn.mock.calls[0][1] as RequestInit).headers).toMatchObject({ Authorization: "Bearer et_live_x" });
  });

  it("marks a common low-risk process harmless and an unknown process as 'uncommon'", async () => {
    const low = new RockyRaccoonProvider({ apiKey: "k", fetchFn: vi.fn(async () => jsonResponse({ classification: { risk_level: "low" }, executions: { total: 45821093 } })) });
    expect((await low.lookup("process", "svchost.exe"))!.verdict).toBe("harmless");

    const nf = new RockyRaccoonProvider({ apiKey: "k", fetchFn: vi.fn(async () => new Response("", { status: 404 })) });
    const r = await nf.lookup("process", "weird-thing.exe");
    expect(r).toMatchObject({ verdict: "unknown" });
    expect(r!.score).toContain("uncommon");
  });

  it("extracts the basename when a full path is passed", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ classification: { risk_level: "low" } }));
    const rr = new RockyRaccoonProvider({ apiKey: "k", fetchFn });
    await rr.lookup("process", "C:\\Windows\\System32\\svchost.exe");
    expect(fetchFn.mock.calls[0][0]).toContain("/v1/process/svchost.exe");
  });

  it("checkParentChild reports observed vs anomalous relationships", async () => {
    const seen = new RockyRaccoonProvider({ apiKey: "k", fetchFn: vi.fn(async () => jsonResponse({ observed: true, percentage: 98.7 })) });
    const ok = await seen.checkParentChild("services.exe", "svchost.exe");
    expect(ok).toMatchObject({ observed: true });
    expect(ok!.note).toContain("98.7%");

    const anomalous = new RockyRaccoonProvider({ apiKey: "k", fetchFn: vi.fn(async () => jsonResponse({ observed: false, common_parents: [{ parent: "explorer.exe", percentage: 80 }] })) });
    const bad = await anomalous.checkParentChild("excel.exe", "powershell.exe");
    expect(bad).toMatchObject({ observed: false });
    expect(bad!.note).toContain("NOT observed");
    expect(bad!.note).toContain("explorer.exe");
  });
});

describe("YetiProvider", () => {
  // A fetch mock that routes the two-step auth + search by URL.
  function yetiFetch(searchBody: unknown, searchStatus = 200) {
    return vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/api/v2/auth/api-token")) {
        expect((init!.headers as Record<string, string>)["x-yeti-apikey"]).toBe("apikey123");
        return jsonResponse({ access_token: "jwt-abc" });
      }
      if (url.endsWith("/api/v2/observables/search")) {
        expect((init!.headers as Record<string, string>).authorization).toBe("Bearer jwt-abc");
        return searchStatus === 200 ? jsonResponse(searchBody) : new Response("", { status: searchStatus });
      }
      throw new Error("unexpected url " + url);
    });
  }

  it("exchanges the API key for a JWT then searches; a tracked malware tag is malicious", async () => {
    const fetchFn = yetiFetch({ total: 2, observables: [
      { id: "obs-1", value: "evil.com", type: "hostname", tags: { malware: {}, "tlp:amber": {} }, context: [{ source: "OSINT feed" }] },
    ] });
    const yeti = new YetiProvider({ baseUrl: "https://yeti.example.org/", apiKey: "apikey123", fetchFn });
    const r = await yeti.lookup("domain", "evil.com");
    expect(r).toMatchObject({ source: "YETI", verdict: "malicious" });
    expect(r!.score).toContain("tracked");
    expect(r!.score).toContain("OSINT feed");
    expect(r!.tags).toEqual(expect.arrayContaining(["malware", "tlp:amber"]));
    expect(r!.link).toBe("https://yeti.example.org/observables/obs-1");
  });

  it("a tracked-but-benign-tagged observable is suspicious; unknown → null; not process", async () => {
    const tracked = new YetiProvider({ baseUrl: "https://y", apiKey: "apikey123", fetchFn: yetiFetch({ observables: [{ id: "x", tags: ["watchlist"] }] }) });
    expect((await tracked.lookup("ip", "1.2.3.4"))!.verdict).toBe("suspicious");

    const unknown = new YetiProvider({ baseUrl: "https://y", apiKey: "apikey123", fetchFn: yetiFetch({ observables: [], total: 0 }) });
    expect(await unknown.lookup("ip", "8.8.8.8")).toBeNull();

    expect(tracked.supports("process")).toBe(false);
    expect(tracked.supports("hash")).toBe(true);
  });

  it("parses YETI v2 object-shaped tags (array of { name }) — names extracted, malicious tag escalates", async () => {
    // Real YETI v2 returns tags as objects, not strings/dicts. Verify we read `.name`
    // (so the verdict can escalate and the badge shows real names, not "[object Object]").
    const fetchFn = yetiFetch({ total: 1, observables: [
      { id: "obs-9", value: "1.2.3.4", type: "ip",
        tags: [{ name: "blocklist", fresh: true }, { name: "trojan", fresh: true }] },
    ] });
    const yeti = new YetiProvider({ baseUrl: "https://y", apiKey: "apikey123", fetchFn });
    const r = await yeti.lookup("ip", "1.2.3.4");
    expect(r!.tags).toEqual(expect.arrayContaining(["blocklist", "trojan"]));
    expect(r!.tags).not.toContain("[object Object]");
    expect(r!.verdict).toBe("malicious");          // "trojan" matches the malicious-tag set
  });

  it("object tags with only benign names stay suspicious", async () => {
    const fetchFn = yetiFetch({ total: 1, observables: [{ id: "o", tags: [{ name: "blocklist" }] }] });
    const yeti = new YetiProvider({ baseUrl: "https://y", apiKey: "apikey123", fetchFn });
    const r = await yeti.lookup("ip", "9.9.9.9");
    expect(r!.tags).toEqual(["blocklist"]);
    expect(r!.verdict).toBe("suspicious");
  });

  it("probe() forces a fresh API-token exchange; resolves when up, throws the 405 when down", async () => {
    // Up: the token endpoint returns a JWT → probe resolves.
    const upFetch = vi.fn(async (url: string) => {
      if (url.endsWith("/api/v2/auth/api-token")) return jsonResponse({ access_token: "jwt-abc" });
      throw new Error("unexpected url " + url);
    });
    const up = new YetiProvider({ baseUrl: "https://yeti.example.org/", apiKey: "apikey123", fetchFn: upFetch });
    await expect(up.probe()).resolves.toBeUndefined();
    expect(upFetch.mock.calls[0][0]).toBe("https://yeti.example.org/api/v2/auth/api-token");

    // Down: the instance answers 405 on the auth endpoint (as in the field report) → probe throws.
    const down = new YetiProvider({ baseUrl: "https://y", apiKey: "apikey123", fetchFn: vi.fn(async () => new Response("", { status: 405 })) });
    await expect(down.probe()).rejects.toThrow(/YETI auth HTTP 405/);
  });

  it("refreshes the token once on a 401 from search", async () => {
    let searchCalls = 0;
    const fetchFn = vi.fn(async (url: string) => {
      if (url.endsWith("/auth/api-token")) return jsonResponse({ access_token: "jwt-abc" });
      searchCalls += 1;
      return searchCalls === 1 ? new Response("", { status: 401 }) : jsonResponse({ observables: [{ id: "z", tags: ["malware"] }] });
    });
    const yeti = new YetiProvider({ baseUrl: "https://y", apiKey: "apikey123", fetchFn });
    const r = await yeti.lookup("hash", "abc");
    expect(r!.verdict).toBe("malicious");
    expect(searchCalls).toBe(2);                 // retried after refreshing the token
  });
});
