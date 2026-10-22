import { describe, expect, it } from "vitest";
import { buildWebSigmaRecord, chooseWebPack, webSigmaMayGrade } from "../../src/analysis/sigmaWebRecord.js";
import type { SigmaRuleRef } from "../../src/analysis/sigmaRuleSet.js";

// The synthetic Sigma record one access-log line becomes (#2203), in Sigma's own field names.

const base = {
  method: "GET",
  target: "/index.php",
  referer: "-",
  ua: "Mozilla/5.0",
  user: "",
  host: "",
  client: "198.51.100.7",
  status: 200,
  clipped: new Set<string>(),
};

describe("buildWebSigmaRecord — webserver", () => {
  it("maps the request with raw and decoded URI values and splits path from query on the raw text", () => {
    const r = buildWebSigmaRecord({ ...base, target: "/a%2e%2e%2fetc/passwd?x=%27a%27+b" }, "webserver");
    expect(r["cs-uri-query"]).toEqual(["/a%2e%2e%2fetc/passwd?x=%27a%27+b", "/a../etc/passwd?x='a' b"]);
    expect(r["cs-uri-stem"]).toEqual(["/a%2e%2e%2fetc/passwd", "/a../etc/passwd"]);
    expect(r["cs-method"]).toBe("GET");
    expect(r["sc-status"]).toBe("200");
    expect(r["c-ip"]).toBe("198.51.100.7");
  });

  it("omits a field the log wrote as '-', keeps a logged empty string", () => {
    const r = buildWebSigmaRecord({ ...base, referer: "-", ua: "" }, "webserver");
    expect("cs-referer" in r).toBe(false);
    expect(r["cs-user-agent"]).toBe("");
  });

  it("lists clipped fields as incomplete", () => {
    const r = buildWebSigmaRecord({ ...base, clipped: new Set(["target", "ua"]) }, "webserver");
    expect(r.__sigmaIncomplete).toEqual(["cs-uri-query", "cs-uri-stem", "cs-user-agent"]);
  });
});

describe("buildWebSigmaRecord — proxy", () => {
  it("gives the full URL to c-uri and the origin form to cs-uri", () => {
    const r = buildWebSigmaRecord(
      { ...base, method: "POST", target: "http://example.test/admin/get.php?a=1", host: "example.test" },
      "proxy",
    );
    expect(r["c-uri"]).toBe("http://example.test/admin/get.php?a=1");
    expect(r["cs-uri"]).toBe("/admin/get.php?a=1");
    expect(r["c-uri-stem"]).toBe("/admin/get.php");
    expect(r["c-uri-query"]).toBe("a=1");
    expect(r["c-uri-extension"]).toBe("php");
    expect(r["cs-host"]).toBe("example.test");
    expect(r["c-useragent"]).toBe("Mozilla/5.0");
  });

  it("gives a CONNECT tunnel no path, query or extension", () => {
    const r = buildWebSigmaRecord(
      { ...base, method: "CONNECT", target: "vault.example.test:443", host: "vault.example.test" },
      "proxy",
    );
    expect(r["c-uri"]).toBe("vault.example.test:443");
    for (const k of ["cs-uri", "c-uri-stem", "c-uri-query", "c-uri-extension"]) expect(k in r).toBe(false);
  });
});

describe("chooseWebPack", () => {
  const line = (t: string, m = "GET") =>
    `203.0.113.5 - - [14/May/2024:19:00:00 +0000] "${m} ${t} HTTP/1.1" 200 1 "-" "ua"`;
  it("uses the declared Squid profile", () => {
    expect(chooseWebPack([line("/x")], true)).toMatchObject({
      sourceId: "web-proxy",
      reason: "declared Squid log",
    });
  });
  it("infers a proxy log only when most requests are absolute-form or CONNECT", () => {
    expect(
      chooseWebPack([line("http://a.test/"), line("b.test:443", "CONNECT"), line("/x")], false).sourceId,
    ).toBe("web-proxy");
    expect(chooseWebPack([line("http://a.test/"), line("/x"), line("/y")], false).sourceId).toBe(
      "web-server",
    );
  });
});

describe("webSigmaMayGrade", () => {
  const ref = (o: Partial<SigmaRuleRef>): SigmaRuleRef => ({
    id: "r",
    title: "R",
    level: "high",
    status: "test",
    path: "p",
    url: "u",
    release: "x",
    mitre: [],
    huntingOnly: false,
    fields: [],
    ...o,
  });
  it("lets only answered requests raise severity on a webserver", () => {
    expect(webSigmaMayGrade("web-server", 200)(ref({}))).toBe(true);
    expect(webSigmaMayGrade("web-server", 302)(ref({}))).toBe(true);
    expect(webSigmaMayGrade("web-server", 404)(ref({}))).toBe(false);
  });
  it("exempts web-shell rules and rules that constrain the status themselves", () => {
    expect(webSigmaMayGrade("web-server", 404)(ref({ mitre: ["T1505.003"] }))).toBe(true);
    expect(webSigmaMayGrade("web-server", 500)(ref({ fields: ["sc-status"] }))).toBe(true);
  });
  it("never vetoes a proxy rule", () => {
    expect(webSigmaMayGrade("web-proxy", 404)(ref({}))).toBe(true);
  });
});
