// #933 item 1 (prerequisite phase) — what one web-log line establishes.
import { describe, expect, it } from "vitest";
import {
  inferTrailerProfile,
  isKnownSquidToken,
  MIN_PROFILE_LINES,
  readSize,
  readSquidTrailer,
  readTarget,
  readTrailer,
  statusWords,
  trailerTokens,
} from "../../src/analysis/webRecordFields.js";

describe("readTarget — the RFC 9112 form, never the deployment's role", () => {
  it("reads origin, absolute, authority, asterisk and invalid forms", () => {
    expect(readTarget("GET", "/api/v4/projects")).toEqual({ form: "origin", host: "", port: "", words: "" });
    expect(readTarget("GET", "https://files.example.invalid/x?a=1")).toMatchObject({
      form: "absolute",
      host: "files.example.invalid",
      words: "absolute-form request target",
    });
    expect(readTarget("GET", "http://files.example.invalid:8080/x")).toMatchObject({
      form: "absolute",
      port: "8080",
    });
    expect(readTarget("CONNECT", "vault.example.invalid:443")).toMatchObject({
      form: "authority",
      host: "vault.example.invalid",
      port: "443",
      words: "tunnel attempt to vault.example.invalid:443 — the requests inside are not in this record",
    });
    expect(readTarget("OPTIONS", "*")).toMatchObject({ form: "asterisk" });
  });
  it("a CONNECT with no port is still a tunnel attempt and says the port is missing", () => {
    const r = readTarget("CONNECT", "vault.example.invalid");
    expect(r.form).toBe("authority");
    expect(r.port).toBe("");
    expect(r.words).toContain("no port in this record");
  });
  it("a malformed target is invalid, never a host", () => {
    expect(readTarget("GET", "api/v4/projects")).toMatchObject({ form: "invalid", host: "" });
    expect(readTarget("CONNECT", "http://x/y")).toMatchObject({ form: "invalid", host: "" });
    expect(readTarget("GET", "")).toMatchObject({ form: "invalid" });
  });
});

describe("readSquidTrailer — the proxy's leg and the next hop, never a transfer", () => {
  it("reads the cache legs: a hit contacted nothing, a miss went upstream, a direct fetch is the origin", () => {
    expect(readSquidTrailer("TCP_HIT:NONE")).toMatchObject({
      result: "TCP_HIT",
      hierarchy: "NONE",
      known: true,
      words: "proxy: served from its cache; upstream: not contacted",
    });
    expect(readSquidTrailer("TCP_MISS:HIER_DIRECT").words).toBe(
      "proxy: cache miss; fetched upstream; upstream: fetched from the origin (direct)",
    );
    expect(readSquidTrailer("TCP_MISS:DEFAULT_PARENT").words).toContain("through a parent proxy");
    expect(readSquidTrailer("TCP_MISS:DEFAULT_PARENT").words).not.toContain("origin");
  });
  it("revalidation is its own fact, and a failed one says the copy was stale", () => {
    expect(readSquidTrailer("TCP_REFRESH_UNMODIFIED:HIER_DIRECT").words).toContain(
      "revalidated upstream and served its cached copy",
    );
    expect(readSquidTrailer("TCP_REFRESH_MODIFIED:HIER_DIRECT").words).toContain("served the new copy");
    expect(readSquidTrailer("TCP_REFRESH_FAIL_OLD:HIER_DIRECT").words).toContain(
      "served the stale cached copy",
    );
    expect(readSquidTrailer("TCP_IMS_HIT:NONE").words).toContain(
      "answered the client's revalidation from its cache",
    );
  });
  it("a denial, a tunnel and an unknown code each say only what they are", () => {
    expect(readSquidTrailer("TCP_DENIED:HIER_NONE").words).toBe(
      "proxy: denied the request; upstream: not contacted",
    );
    expect(readSquidTrailer("TCP_DENIED_REPLY:HIER_DIRECT").words).toContain(
      "denied after an upstream reply",
    );
    expect(readSquidTrailer("TCP_TUNNEL:HIER_DIRECT").words).toContain("tunnelled the connection");
    const unknown = readSquidTrailer("TCP_FOO:BAR_BAZ");
    expect(unknown).toMatchObject({ result: "TCP_FOO", hierarchy: "BAR_BAZ", known: false });
    expect(unknown.words).toBe("proxy: result TCP_FOO; upstream: next hop BAR_BAZ");
    expect(readSquidTrailer("NONE:NONE").words).toBe("upstream: not contacted");
    expect(readSquidTrailer("not a token")).toMatchObject({ result: "", known: false, words: "" });
  });
  it("knows which tokens the table names", () => {
    expect(isKnownSquidToken("tcp_hit:none")).toBe(true);
    expect(isKnownSquidToken("TCP_FOO:BAR")).toBe(false);
    expect(isKnownSquidToken("203.0.113.5")).toBe(false);
    expect(isKnownSquidToken("1234")).toBe(false);
  });
});

describe("trailerTokens / inferTrailerProfile — the file decides, never one line", () => {
  it("splits bare runs and keeps a quoted list as one token", () => {
    expect(trailerTokens(' TCP_MISS:HIER_DIRECT 137 "203.0.113.5, 10.0.0.1"')).toEqual([
      "TCP_MISS:HIER_DIRECT",
      "137",
      "203.0.113.5, 10.0.0.1",
    ]);
    expect(trailerTokens("")).toEqual([]);
    expect(trailerTokens('"-"')).toEqual(["-"]);
  });
  it("infers a profile only from a long enough file where almost every line agrees", () => {
    const squid = (n: number) => Array.from({ length: n }, () => ["TCP_MISS:HIER_DIRECT"]);
    expect(inferTrailerProfile(squid(MIN_PROFILE_LINES))).toEqual({ squidSlot: 0, source: "inferred" });
    // below the floor no inference is possible, however unanimous
    expect(inferTrailerProfile(squid(1))).toBeNull();
    expect(inferTrailerProfile(squid(10))).toBeNull();
    // 19 of 20 agree → still the profile; 18 of 20 → not
    const mostly = [...squid(19), ["203.0.113.9"]];
    expect(inferTrailerProfile(mostly)).toEqual({ squidSlot: 0, source: "inferred" });
    const split = [...squid(18), ["203.0.113.9"], ["203.0.113.8"]];
    expect(inferTrailerProfile(split)).toBeNull();
    // the slot is wherever the file puts it
    const behindTime = Array.from({ length: 20 }, () => ["137", "TCP_HIT:NONE"]);
    expect(inferTrailerProfile(behindTime)).toEqual({ squidSlot: 1, source: "inferred" });
    expect(inferTrailerProfile(Array.from({ length: 30 }, () => []))).toBeNull();
    expect(inferTrailerProfile([])).toBeNull();
  });
});

describe("readTrailer — with no profile nothing is labelled", () => {
  it("labels the profile's slot and keeps every other token verbatim", () => {
    const tokens = ["TCP_MISS:HIER_DIRECT", "137", "203.0.113.5, 10.0.0.1"];
    const withProfile = readTrailer(tokens, { squidSlot: 0, source: "inferred" });
    expect(withProfile.squid?.result).toBe("TCP_MISS");
    expect(withProfile.words[0]).toContain("(squid_combined, inferred from the file)");
    expect(withProfile.words[1]).toBe("trailer: 137 203.0.113.5, 10.0.0.1");
    expect(withProfile.keySegment).toMatch(/^\|squid:tcp_miss:hier_direct\|trailer:[0-9a-f]{16}$/);
    const declared = readTrailer(tokens, { squidSlot: 0, source: "declared" });
    expect(declared.words[0]).toContain("(squid_combined, declared)");
  });
  it("with no profile the Squid-shaped token is just a token: no words, no key, no claim", () => {
    const r = readTrailer(["TCP_MISS:HIER_DIRECT"], null);
    expect(r.squid).toBeNull();
    // the token is not labelled and not in the key as text — but its DIGEST is, so a row that
    // shows it never folds into a row that does not.
    expect(r.keySegment).toMatch(/^\|trailer:[0-9a-f]{16}$/);
    expect(r.keySegment).not.toContain("TCP_MISS");
    expect(readTrailer(["TCP_HIT:NONE"], null).keySegment).not.toBe(r.keySegment);
    expect(r.words).toEqual(["trailer: TCP_MISS:HIER_DIRECT"]);
    expect(r.words.join(" ")).not.toContain("origin");
    expect(readTrailer([], null).words).toEqual([]);
    expect(readTrailer([], null).keySegment).toBe("");
  });
  it("bounds the tokens it shows", () => {
    const r = readTrailer([`${"x".repeat(200)}`, "y".repeat(200)], null);
    expect(r.words[0].length).toBeLessThanOrEqual(89);
  });
});

describe("readSize / statusWords — a count is not a body; a status is not a redirect", () => {
  it("says nothing for an ordinary response and names every bodiless case", () => {
    expect(readSize("GET", 200, "3417")).toBe("");
    expect(readSize("GET", 200, "0")).toBe("");
    expect(readSize("GET", 200, "-")).toBe("");
    expect(readSize("GET", 206, "500")).toBe("");
    expect(readSize("GET", 404, "1275")).toBe("");
    expect(readSize("CONNECT", 200, "123")).toBe("the logged size is the tunnel's, not a response body");
    expect(readSize("CONNECT", 200, "-")).toBe("");
    expect(readSize("HEAD", 200, "0")).toBe("no body by definition (HEAD)");
    expect(readSize("GET", 204, "0")).toBe("no body for this status");
    expect(readSize("GET", 100, "0")).toBe("no body for this status");
    // 304's words come from the status, not the size
    expect(readSize("GET", 304, "-")).toBe("");
  });
  it("names the redirect statuses and never calls a 304 a redirect", () => {
    for (const s of [301, 302, 303, 307, 308])
      expect(statusWords(s), String(s)).toBe("redirect — the Location is not in this format");
    expect(statusWords(304)).toBe("not modified — no body");
    expect(statusWords(304)).not.toContain("redirect");
    expect(statusWords(200)).toBe("");
    expect(statusWords(404)).toBe("");
  });
});
