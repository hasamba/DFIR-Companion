import { describe, it, expect, vi } from "vitest";
import { VirusTotalProvider } from "../../src/enrichment/virustotal.js";
import { MalwareBazaarProvider } from "../../src/enrichment/malwarebazaar.js";
import { AbuseIpdbProvider } from "../../src/enrichment/abuseipdb.js";

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
