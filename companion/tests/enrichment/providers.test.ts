import { describe, it, expect, vi } from "vitest";
import { VirusTotalProvider } from "../../src/enrichment/virustotal.js";
import { MalwareBazaarProvider } from "../../src/enrichment/malwarebazaar.js";
import { AbuseIpdbProvider } from "../../src/enrichment/abuseipdb.js";
import { MispProvider } from "../../src/enrichment/misp.js";
import { RockyRaccoonProvider } from "../../src/enrichment/rockyraccoon.js";

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

  it("returns null when the indicator is not present on the instance, and does not support process names", async () => {
    const misp = new MispProvider({ baseUrl: "https://m", apiKey: "k", fetchFn: vi.fn(async () => jsonResponse({ response: { Attribute: [] } })) });
    expect(await misp.lookup("domain", "evil.test")).toBeNull();
    expect(misp.supports("hash")).toBe(true);
    expect(misp.supports("process")).toBe(false);
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
