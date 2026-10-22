import { describe, expect, it } from "vitest";
import { parseCombinedLog } from "../../src/analysis/combinedLogImport.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";

// Web server and proxy access logs graded by the bundled SigmaHQ web rules (#2203). Synthetic lines
// in the Apache/nginx/Squid combined format; RFC 5737 addresses, .test hosts.

const sigma = createSigmaImportGrader(loadBundledSigmaRuleSet().set).snapshot();
const EMPIRE_UA = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";

const line = (method: string, target: string, status: number, ref = "-", ua = "Mozilla/5.0") =>
  `203.0.113.5 - - [14/May/2024:19:00:00 +0000] "${method} ${target} HTTP/1.1" ${status} 512 "${ref}" "${ua}"`;
const parse = (lines: string[]) => parseCombinedLog(lines.join("\n"), { sigma, aggregate: false });
const event = (lines: string[], i = 0) => parse(lines).events[i];

describe("web server access logs", () => {
  const weblogic = "/console/css/%2e%2e%2fconsole.portal";

  it("raises an exploit request the server answered", () => {
    const e = event([line("GET", weblogic, 200)]);
    expect(e.severity).toBe("High");
    expect(e.description).toMatch(/^Sigma: Oracle WebLogic Exploit CVE-2020-14882/);
  });

  it("only tags the same request when the server did not answer it, and says why", () => {
    const e = event([line("GET", weblogic, 404)]);
    expect(e.severity).not.toBe("High");
    expect(e.description).toMatch(/^Sigma \(high, tag only\): Oracle WebLogic Exploit CVE-2020-14882/);
    expect(e.message).toMatch(/did not answer this request with 2xx\/3xx/);
  });

  it("grades a web-shell rule (ReGeorg) even when the server answered 404, using absent Referer and UA", () => {
    const e = event([line("POST", "/tunnel.jsp?cmd=read", 404, "-", "-")]);
    expect(e.severity).toBe("High");
    expect(e.description).toMatch(/^Sigma: Webshell ReGeorg Detection Via Web Logs/);
  });

  it("does not match ReGeorg when the request carried a User-Agent", () => {
    expect(event([line("POST", "/tunnel.jsp?cmd=read", 200, "-", "curl/8")]).description).not.toMatch(
      /ReGeorg/,
    );
  });

  it("matches a URL-encoded traversal through its decoding", () => {
    const e = event([line("GET", "/a/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", 200)]);
    expect(e.description).toMatch(/^Sigma \(medium, tag only\): .*Path Traversal/i);
  });

  it("reports the pack and the matched rows, and stamps every graded row", () => {
    const r = parse([line("GET", weblogic, 200), line("GET", "/index.html", 200)]);
    expect(r.sigmaPack).toEqual({
      sourceId: "web-server",
      reason: "inferred: 0% of requests absolute-form or CONNECT",
    });
    expect(r.sigmaRowsMatched).toBe(1);
    expect(r.events.every((e) => e.canonical?.producer.ruleVersions?.includes(sigma!.token))).toBe(true);
  });

  it("is the pre-#2203 output without a snapshot", () => {
    const lines = [line("GET", weblogic, 200)].join("\n");
    expect(parseCombinedLog(lines, { aggregate: false }).events[0].description).not.toMatch(/Sigma/);
  });
});

describe("proxy access logs", () => {
  const empire = line("POST", "http://evil.test/admin/get.php", 200, "-", EMPIRE_UA);
  const proxyLines = [
    empire,
    line("GET", "http://example.test/", 200),
    line("CONNECT", "vault.example.test:443", 200),
  ];

  it("grades a proxy log with the proxy rules (Empire exact path through cs-uri)", () => {
    const r = parse(proxyLines);
    expect(r.sigmaPack?.sourceId).toBe("web-proxy");
    const e = r.events.find((x) => x.description.includes("get.php"));
    expect(e?.severity).toBe("High");
    expect(e?.description).toMatch(/^Sigma: .*Empire/);
  });

  it("does not grade the same line with proxy rules inside a web server log", () => {
    const r = parse([empire, line("GET", "/a", 200), line("GET", "/b", 200)]);
    expect(r.sigmaPack?.sourceId).toBe("web-server");
    expect(r.events.some((x) => /Empire/.test(x.description))).toBe(false);
  });

  it("uses a declared Squid log even when most targets are origin-form", () => {
    const r = parseCombinedLog([line("GET", "/a", 200), line("GET", "/b", 200)].join("\n"), {
      sigma,
      trailerProfile: { squidSlot: 0 },
    });
    expect(r.sigmaPack).toEqual({ sourceId: "web-proxy", reason: "declared Squid log" });
  });

  it("tags a logged empty User-Agent", () => {
    const r = parse([line("GET", "http://a.test/x.ps1", 200, "-", ""), ...proxyLines.slice(1)]);
    // Rows come back severity-first, so find the empty-UA request by its target.
    const e = r.events.find((x) => x.description.includes("x.ps1"));
    expect(e?.description).toMatch(/^Sigma \(medium, tag only\): HTTP Request With Empty User Agent/);
  });
});

describe("aggregation with Sigma matches (Codex plan review)", () => {
  it("keeps the rule names on the overflow row once one path has more than 64 distinct payloads", () => {
    const lines = Array.from({ length: 70 }, (_, i) =>
      line("GET", `/console/css/%2e%2e%2fconsole.portal?id=1%27%20UNION%20SELECT%20${i},2--`, 200),
    );
    const r = parseCombinedLog(lines.join("\n"), { sigma });
    const overflow = r.events.find((e) => e.description.includes("[overflow"));
    expect(overflow).toBeDefined();
    expect(overflow?.description).toContain("sigma Oracle WebLogic Exploit CVE-2020-14882");
    expect(overflow?.severity).toBe("High");
  });
});
