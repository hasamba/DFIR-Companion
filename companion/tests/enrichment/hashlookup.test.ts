import { describe, it, expect, vi } from "vitest";
import { HashlookupProvider } from "../../src/enrichment/hashlookup.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

// A real-ish CIRCL hashlookup record (NSRL-derived). Keys keep their wire names
// (`hashlookup:trust`, `SHA-1`) so the parser must read them verbatim.
const KNOWN_GOOD = {
  "FileName": "kernel32.dll",
  "FileSize": "1141248",
  "MD5": "8ED4B4ED952526D89899E723F3488DE4",
  "SHA-1": "FFFFFDAC1B1B4C513896C805C2C698D9688BE69F",
  "SHA-256": "301c9ec7a9aadee4d745e8fd4fa659dafbbcc6b75b9ff491d14cbbdd840814e9",
  "source": "NSRL",
  "db": "nsrl_modern_rds",
  "hashlookup:trust": 100,
};

const MD5 = "8ed4b4ed952526d89899e723f3488de4";                                   // 32 hex
const SHA1 = "fffffdac1b1b4c513896c805c2c698d9688be69f";                          // 40 hex
const SHA256 = "301c9ec7a9aadee4d745e8fd4fa659dafbbcc6b75b9ff491d14cbbdd840814e9"; // 64 hex

describe("HashlookupProvider", () => {
  it("maps a known high-trust file to a harmless verdict with file/source context", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(KNOWN_GOOD));
    const hl = new HashlookupProvider({ fetchFn });
    const r = await hl.lookup("hash", SHA256);
    expect(r).toMatchObject({ source: "Hashlookup", verdict: "harmless" });
    expect(r!.score).toContain("kernel32.dll");
    expect(r!.tags).toContain("NSRL");
    expect(r!.tags!.some((t) => /trust/i.test(t))).toBe(true);
    expect(r!.link).toContain(SHA256);
  });

  it("supports only the hash kind", () => {
    const hl = new HashlookupProvider({ fetchFn: vi.fn() });
    expect(hl.supports("hash")).toBe(true);
    expect(hl.supports("ip")).toBe(false);
    expect(hl.supports("domain")).toBe(false);
    expect(hl.scope).toBe("external");
  });

  it("detects the hash type from length and hits the matching /lookup/<type>/ endpoint", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(KNOWN_GOOD));
    const hl = new HashlookupProvider({ fetchFn });
    await hl.lookup("hash", MD5);
    await hl.lookup("hash", SHA1);
    await hl.lookup("hash", SHA256);
    const urls = fetchFn.mock.calls.map((c) => String(c[0]));
    expect(urls[0]).toContain(`/lookup/md5/${MD5}`);
    expect(urls[1]).toContain(`/lookup/sha1/${SHA1}`);
    expect(urls[2]).toContain(`/lookup/sha256/${SHA256}`);
  });

  it("treats a known file with low/missing trust as unknown (legitimacy not asserted)", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ FileName: "tool.exe", source: "hashlookup", "hashlookup:trust": 20 }));
    const hl = new HashlookupProvider({ fetchFn });
    const r = await hl.lookup("hash", SHA256);
    expect(r).toMatchObject({ source: "Hashlookup", verdict: "unknown" });
    expect(r!.score).toContain("tool.exe");
  });

  it("flags an explicitly known-malicious record as malicious", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ FileName: "evil.dll", source: "hashlookup-blocklist", KnownMalicious: "true", "hashlookup:trust": 0 }));
    const hl = new HashlookupProvider({ fetchFn });
    const r = await hl.lookup("hash", SHA256);
    expect(r).toMatchObject({ source: "Hashlookup", verdict: "malicious" });
  });

  it("returns null when the hash is unknown to hashlookup (404)", async () => {
    const fetchFn = vi.fn(async () => new Response("", { status: 404 }));
    const hl = new HashlookupProvider({ fetchFn });
    expect(await hl.lookup("hash", SHA256)).toBeNull();
  });

  it("returns null on a bad hash format reported by the API (400)", async () => {
    const fetchFn = vi.fn(async () => new Response("", { status: 400 }));
    const hl = new HashlookupProvider({ fetchFn });
    expect(await hl.lookup("hash", SHA256)).toBeNull();
  });

  it("does not call the API for a non-hash kind", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(KNOWN_GOOD));
    const hl = new HashlookupProvider({ fetchFn });
    expect(await hl.lookup("ip", "8.8.8.8")).toBeNull();
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("does not call the API for a value that is not an md5/sha1/sha256 hash", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(KNOWN_GOOD));
    const hl = new HashlookupProvider({ fetchFn });
    expect(await hl.lookup("hash", "not-a-hash")).toBeNull();
    expect(await hl.lookup("hash", "abc123")).toBeNull();         // too short
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("throws on a transient server error so the IOC is retried (not cached as a miss)", async () => {
    const fetchFn = vi.fn(async () => new Response("", { status: 500 }));
    const hl = new HashlookupProvider({ fetchFn });
    await expect(hl.lookup("hash", SHA256)).rejects.toThrow(/Hashlookup HTTP 500/);
  });

  it("honors a custom base URL (air-gapped / self-hosted mirror)", async () => {
    const fetchFn = vi.fn(async () => jsonResponse(KNOWN_GOOD));
    const hl = new HashlookupProvider({ baseUrl: "https://hash.internal.lab/", fetchFn });
    await hl.lookup("hash", SHA256);
    expect(String(fetchFn.mock.calls[0][0])).toBe(`https://hash.internal.lab/lookup/sha256/${SHA256}`);
  });
});
