import { describe, it, expect, vi } from "vitest";
import { OpenCtiProvider } from "../../src/enrichment/opencti.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

// A stixCyberObservables GraphQL response wrapping one observable node.
function observableResponse(node: Record<string, unknown>) {
  return { data: { stixCyberObservables: { edges: [{ node }] } } };
}

describe("OpenCtiProvider", () => {
  it("maps a high x_opencti_score to a malicious verdict with a clickable link", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(observableResponse({
      id: "obs-1", entity_type: "IPv4-Addr", observable_value: "1.2.3.4",
      x_opencti_score: 90,
      objectLabel: [{ value: "tracking" }],
      indicators: { edges: [{ node: { id: "ind-1" } }] },
    })));
    const octi = new OpenCtiProvider({ baseUrl: "https://opencti.test", apiKey: "k", fetchFn });
    const r = await octi.lookup("ip", "1.2.3.4");
    expect(r).toMatchObject({ source: "OpenCTI", verdict: "malicious", detections: 1 });
    expect(r!.score).toContain("score 90/100");
    expect(r!.score).toContain("1 linked indicator");
    expect(r!.link).toBe("https://opencti.test/dashboard/observations/observables/obs-1");
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://opencti.test/graphql");
    expect(init.headers).toMatchObject({ authorization: "Bearer k" });
    expect(String(init.body)).toContain("1.2.3.4");
  });

  it("treats a malicious label as malicious even when the score is low", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(observableResponse({
      id: "obs-2", observable_value: "evil.test", x_opencti_score: 20,
      objectLabel: [{ value: "ransomware" }],
    })));
    const octi = new OpenCtiProvider({ baseUrl: "https://opencti.test/", apiKey: "k", fetchFn });
    const r = await octi.lookup("domain", "evil.test");
    expect(r!.verdict).toBe("malicious");
    expect(r!.tags).toContain("ransomware");
  });

  it("a low-score, non-malicious-label hit is suspicious (present = at least suspicious)", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(observableResponse({
      id: "obs-3", observable_value: "9.9.9.9", x_opencti_score: 30, objectLabel: [{ value: "osint" }],
    })));
    const octi = new OpenCtiProvider({ baseUrl: "https://opencti.test", apiKey: "k", fetchFn });
    const r = await octi.lookup("ip", "9.9.9.9");
    expect(r!.verdict).toBe("suspicious");
  });

  it("returns null when no observable matches (unknown indicator)", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ data: { stixCyberObservables: { edges: [] } } }));
    const octi = new OpenCtiProvider({ baseUrl: "https://opencti.test", apiKey: "k", fetchFn });
    expect(await octi.lookup("hash", "deadbeef")).toBeNull();
  });

  it("respects a custom maliciousScore threshold", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(observableResponse({
      id: "o", observable_value: "5.5.5.5", x_opencti_score: 60,
    })));
    const octi = new OpenCtiProvider({ baseUrl: "https://opencti.test", apiKey: "k", fetchFn, maliciousScore: 50 });
    const r = await octi.lookup("ip", "5.5.5.5");
    expect(r!.verdict).toBe("malicious");   // 60 >= 50
  });

  it("throws an auth error on HTTP 401", async () => {
    const octi = new OpenCtiProvider({ baseUrl: "https://opencti.test", apiKey: "bad", fetchFn: vi.fn(async () => new Response("", { status: 401 })) });
    await expect(octi.lookup("ip", "1.2.3.4")).rejects.toThrow(/DFIR_OPENCTI_KEY/);
  });

  it("throws on a GraphQL errors[] body (HTTP 200)", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ errors: [{ message: "Bad query" }] }));
    const octi = new OpenCtiProvider({ baseUrl: "https://opencti.test", apiKey: "k", fetchFn });
    await expect(octi.lookup("ip", "1.2.3.4")).rejects.toThrow(/OpenCTI GraphQL error: Bad query/);
  });

  it("probe() resolves on a valid me{} response and throws on 401", async () => {
    const ok = new OpenCtiProvider({ baseUrl: "https://opencti.test", apiKey: "k", fetchFn: vi.fn(async () => jsonResponse({ data: { me: { id: "u1", name: "analyst" } } })) });
    await expect(ok.probe()).resolves.toBeUndefined();
    const bad = new OpenCtiProvider({ baseUrl: "https://opencti.test", apiKey: "bad", fetchFn: vi.fn(async () => new Response("", { status: 401 })) });
    await expect(bad.probe()).rejects.toThrow(/auth failed/i);
  });

  it("supports hash/ip/domain/url but not process", () => {
    const octi = new OpenCtiProvider({ baseUrl: "https://opencti.test", apiKey: "k", fetchFn: vi.fn() });
    expect(octi.supports("ip")).toBe(true);
    expect(octi.supports("hash")).toBe(true);
    expect(octi.supports("process")).toBe(false);
  });
});
