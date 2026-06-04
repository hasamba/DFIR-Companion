import { describe, it, expect, vi } from "vitest";
import { VirusTotalProvider } from "../../src/enrichment/virustotal.js";
import { MalwareBazaarProvider } from "../../src/enrichment/malwarebazaar.js";
import { AbuseIpdbProvider } from "../../src/enrichment/abuseipdb.js";
import { MispProvider } from "../../src/enrichment/misp.js";

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

describe("MalwareBazaarProvider", () => {
  it("reports a known sample as malicious with its signature", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      query_status: "ok", data: [{ sha256_hash: "ABCD", signature: "TrickBot", tags: ["trickbot", "exe"], file_type: "exe" }],
    }));
    const mb = new MalwareBazaarProvider({ fetchFn });
    const r = await mb.lookup("hash", "abcd");
    expect(r).toMatchObject({ source: "MalwareBazaar", verdict: "malicious" });
    expect(r!.score).toContain("TrickBot");
    expect(r!.tags).toEqual(expect.arrayContaining(["TrickBot", "trickbot"]));
    expect(r!.link).toContain("bazaar.abuse.ch/sample/ABCD");
  });

  it("returns null when the hash is not found, and only supports hashes", async () => {
    const mb = new MalwareBazaarProvider({ fetchFn: vi.fn(async () => jsonResponse({ query_status: "hash_not_found" })) });
    expect(await mb.lookup("hash", "x")).toBeNull();
    expect(mb.supports("ip")).toBe(false);
    expect(mb.supports("hash")).toBe(true);
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

  it("returns null when the indicator is not present on the instance, supports all kinds", async () => {
    const misp = new MispProvider({ baseUrl: "https://m", apiKey: "k", fetchFn: vi.fn(async () => jsonResponse({ response: { Attribute: [] } })) });
    expect(await misp.lookup("domain", "evil.test")).toBeNull();
    expect(misp.supports("hash")).toBe(true);
    expect(misp.supports("url")).toBe(true);
  });
});
