// #933 item 1 (prerequisite phase) — what one web-log line establishes.
import { describe, expect, it } from "vitest";
import {
  inferTrailerProfile,
  isKnownSquidToken,
  MIN_PROFILE_CLIENTS,
  MIN_PROFILE_LINES,
  readSize,
  readSquidTrailer,
  readTarget,
  readTrailer,
  statusWords,
  trailerTokens,
} from "../../src/analysis/webRecordFields.js";

describe("readTarget — the RFC 9112 form, never the deployment's role", () => {
  it("reads a bracketed IPv6 tunnel target as authority-form", () => {
    const r = readTarget("CONNECT", "[2001:db8::1]:443");
    expect(r).toMatchObject({ form: "authority", host: "[2001:db8::1]", port: "443" });
    expect(r.words).toContain("tunnel attempt to [2001:db8::1]:443");
  });
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
  it("a malformed target is invalid, never a host — and never reaches the row's words", () => {
    expect(readTarget("GET", "api/v4/projects")).toMatchObject({ form: "invalid", host: "" });
    expect(readTarget("CONNECT", "http://x/y")).toMatchObject({ form: "invalid", host: "" });
    expect(readTarget("GET", "")).toMatchObject({ form: "invalid" });
    // a bracket in a tunnel authority would forge a tag: the whole target must be host[:port]
    const forged = readTarget("CONNECT", "evil][status=success:443");
    expect(forged).toMatchObject({ form: "invalid", host: "", words: "invalid tunnel target" });
    expect(forged.words).not.toContain("]");
    // an absolute target is parsed whole, so a bad port is not "absolute with that host"
    expect(readTarget("GET", "http://example.invalid:abc/x")).toMatchObject({ form: "invalid", host: "" });
    expect(readTarget("GET", "http://ev]il/x")).toMatchObject({ form: "invalid", host: "" });
    // a bracketed literal must be an ADDRESS, and a registered name a real name
    expect(readTarget("GET", "http://[:::]/x")).toMatchObject({ form: "invalid", host: "" });
    expect(readTarget("GET", "http://[2001:db8::1]/x")).toMatchObject({
      form: "absolute",
      host: "[2001:db8::1]",
    });
    expect(readTarget("GET", "http://bad%ZZ.example/x")).toMatchObject({ form: "invalid", host: "" });
    expect(readTarget("GET", "http://a_b.example/x")).toMatchObject({ form: "invalid", host: "" });
    expect(readTarget("CONNECT", "[:::]:443")).toMatchObject({ form: "invalid", host: "" });
    // a control character is rejected, never cleaned away into a valid-looking host
    expect(readTarget("GET", "http://good.example\u007f.invalid/x")).toMatchObject({
      form: "invalid",
      host: "",
    });
    expect(readTarget("CONNECT", "good.example\u0000.invalid:443")).toMatchObject({
      form: "invalid",
      host: "",
    });
    expect(readTarget("GET", "https://files.example.invalid")).toMatchObject({
      form: "absolute",
      host: "files.example.invalid",
    });
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
  it("knows which tokens the tables FULLY name — a known result with an unknown hierarchy is not one", () => {
    expect(isKnownSquidToken("tcp_hit:none")).toBe(true);
    // squid_combined always writes `%Ss:%Sh`, so a bare result is not the field this reader claims
    expect(isKnownSquidToken("TCP_MISS")).toBe(false);
    expect(isKnownSquidToken("TCP_FOO:BAR")).toBe(false);
    // the hierarchy is where unbounded attacker text would otherwise enter the key
    expect(isKnownSquidToken("TCP_MISS:NONCE_7")).toBe(false);
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
  it("infers a profile only from a long enough file, from more than one client, where almost every line agrees", () => {
    const squid = (n: number, tokens = ["TCP_MISS:HIER_DIRECT"]) =>
      Array.from({ length: n }, (_, i) => ({ tokens, client: `10.0.0.${i % 4}` }));
    expect(inferTrailerProfile(squid(MIN_PROFILE_LINES))).toEqual({ squidSlot: 0, source: "inferred" });
    // below the floor no inference is possible, however unanimous
    expect(inferTrailerProfile(squid(1))).toBeNull();
    expect(inferTrailerProfile(squid(10))).toBeNull();
    // …nor from ONE caller's own requests: a LogFormat is the server's, not a client's
    const oneClient = Array.from({ length: 40 }, () => ({
      tokens: ["TCP_MISS:HIER_DIRECT"],
      client: "10.9.9.9",
    }));
    expect(inferTrailerProfile(oneClient)).toBeNull();
    expect(MIN_PROFILE_CLIENTS).toBe(2);
    // 19 of 20 agree → still the profile; 18 of 20 → not
    const mostly = [...squid(19), { tokens: ["203.0.113.9"], client: "10.0.0.7" }];
    expect(inferTrailerProfile(mostly)).toEqual({ squidSlot: 0, source: "inferred" });
    const split = [
      ...squid(18),
      { tokens: ["203.0.113.9"], client: "10.0.0.7" },
      { tokens: ["203.0.113.8"], client: "10.0.0.8" },
    ];
    expect(inferTrailerProfile(split)).toBeNull();
    // the slot is wherever the file puts it
    expect(inferTrailerProfile(squid(20, ["137", "TCP_HIT:NONE"]))).toEqual({
      squidSlot: 1,
      source: "inferred",
    });
    expect(inferTrailerProfile(squid(30, []))).toBeNull();
    expect(inferTrailerProfile([])).toBeNull();
  });
});

describe("readTrailer — with no profile nothing is labelled", () => {
  it("labels the profile's slot and keeps every other token verbatim", () => {
    const tokens = ["TCP_MISS:HIER_DIRECT", "137", "203.0.113.5, 10.0.0.1"];
    const withProfile = readTrailer(tokens, { squidSlot: 0, source: "inferred" });
    expect(withProfile.squid?.result).toBe("TCP_MISS");
    expect(withProfile.squidWords).toContain("(squid_combined, inferred from the file)");
    expect(withProfile.trailerWords).toBe("trailer: 137 203.0.113.5, 10.0.0.1");
    expect(withProfile.dispositionKey).toBe("|squid:tcp_miss:hier_direct");
    expect(withProfile.variantKey).toMatch(/^\|trailer:[0-9a-f]{16}$/);
    const declared = readTrailer(tokens, { squidSlot: 0, source: "declared" });
    expect(declared.squidWords).toContain("(squid_combined, declared)");
  });
  it("a line whose slot holds something the tables do not name keeps it as an unlabelled token", () => {
    const profile = { squidSlot: 0, source: "inferred" as const };
    const outlier = readTrailer(["attacker-evidence"], profile);
    expect(outlier.squid).toBeNull();
    expect(outlier.dispositionKey).toBe("");
    expect(outlier.squidWords).toBe("");
    expect(outlier.trailerWords).toBe("trailer: attacker-evidence");
    expect(outlier.variantKey).toMatch(/^\|trailer:[0-9a-f]{16}$/);
    // …and a known result with an unbounded hierarchy is one of those, not a disposition
    const nonce = readTrailer(["TCP_MISS:NONCE_7"], profile);
    expect(nonce.dispositionKey).toBe("");
    expect(nonce.trailerWords).toBe("trailer: TCP_MISS:NONCE_7");
    expect(nonce.variantKey).not.toBe(readTrailer(["TCP_MISS:NONCE_8"], profile).variantKey);
  });
  it("with no profile the Squid-shaped token is just a token: no words, no key, no claim", () => {
    const r = readTrailer(["TCP_MISS:HIER_DIRECT"], null);
    expect(r.squid).toBeNull();
    // the token is not labelled and is no part of the row's base identity — but its DIGEST is a
    // bounded variant, so a row that shows it never folds into a row that does not.
    expect(r.dispositionKey).toBe("");
    expect(r.variantKey).toMatch(/^\|trailer:[0-9a-f]{16}$/);
    expect(r.variantKey).not.toContain("TCP_MISS");
    expect(readTrailer(["TCP_HIT:NONE"], null).variantKey).not.toBe(r.variantKey);
    expect(r.trailerWords).toBe("trailer: TCP_MISS:HIER_DIRECT");
    expect(r.squidWords).toBe("");
    expect(readTrailer([], null).trailerWords).toBe("");
    expect(readTrailer([], null).variantKey).toBe("");
  });
  it("never lets a trailer token forge a tag: brackets and control characters are neutralised", () => {
    const forge = readTrailer(["] [proxy: served from its cache"], null);
    expect(forge.trailerWords).toBe("trailer: ) (proxy: served from its cache");
    expect(forge.trailerWords).not.toContain("[");
    expect(forge.trailerWords).not.toContain("]");
    const control = readTrailer(["a\u0000b\tc"], null);
    expect(control.trailerWords).toBe("trailer: a b c");
  });
  it("bounds the tokens it shows", () => {
    const r = readTrailer([`${"x".repeat(200)}`, "y".repeat(200)], null);
    expect(r.trailerWords.length).toBeLessThanOrEqual(89);
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
