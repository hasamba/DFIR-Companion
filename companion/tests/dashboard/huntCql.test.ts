import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { HUNT_PLATFORMS } from "../../src/analysis/huntPlatforms.js";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";

// #2558 — the CrowdStrike Falcon (LogScale / Next-Gen SIEM, CQL) card in the 🔍 hunt modal.
// Deterministic templating off one entity's indicators, like the KQL / SPL / ES|QL cards. The
// values are attacker-controlled, so the escaping cases below are correctness, not polish: an
// unescaped `"` closes the string, and in CQL a bare `*` inside a quoted value is a wildcard that
// CANNOT be escaped — so a value carrying `*` must never reach a quoted filter at all.

interface HuntCtx {
  hashes: string[];
  ips: string[];
  domains: string[];
  urls: string[];
  paths: string[];
  processes: string[];
  parent: string;
  host: string;
  label: string;
}

interface CqlApi {
  huntCql: (c: HuntCtx) => string;
  cqlString: (v: unknown) => string;
  cqlRegexLiteral: (v: unknown) => string;
  cqlMatch: (field: string, values: string[]) => string;
}

// URL is a browser global a vm context lacks; the URL card reads the hostname with it.
const api = loadDashboardModule<CqlApi>("dashboard-hunt-cql.js", ["dashboard-bulk-findings.js"], { URL });

const ctx = (over: Partial<HuntCtx> = {}): HuntCtx => ({
  hashes: [],
  ips: [],
  domains: [],
  urls: [],
  paths: [],
  processes: [],
  parent: "",
  host: "",
  label: "x",
  ...over,
});

describe("huntCql — one query block per indicator type", () => {
  it("returns empty when the entity has nothing to pivot on, so the card is dropped", () => {
    expect(api.huntCql(ctx())).toBe("");
    expect(api.huntCql(ctx({ processes: ["   "], domains: [""] }))).toBe("");
  });

  it("process name → ProcessRollup2 with a suffix match on the full ImageFileName path", () => {
    const q = api.huntCql(ctx({ processes: ["C:\\Windows\\Temp\\evil.exe"] }));
    expect(q).toContain("#event_simpleName=ProcessRollup2");
    expect(q).toContain("ImageFileName=/\\\\(?:evil\\.exe)$/i");
    expect(q).toMatch(/table\(\[[^\]]*CommandLine/);
  });

  it("parent process → children of that parent via ParentBaseFileName", () => {
    const q = api.huntCql(ctx({ parent: "C:\\Windows\\winword.exe" }));
    expect(q).toContain("#event_simpleName=ProcessRollup2");
    expect(q).toContain('in(field=ParentBaseFileName, values=["winword.exe"], ignoreCase=true)');
  });

  it("hashes → SHA256HashData for 64-hex and MD5HashData for 32-hex, lowercased", () => {
    const sha = "A".repeat(64);
    const md5 = "b".repeat(32);
    const q = api.huntCql(ctx({ hashes: [sha, md5] }));
    expect(q).toContain(`in(field=SHA256HashData, values=["${"a".repeat(64)}"], ignoreCase=true)`);
    expect(q).toContain(`in(field=MD5HashData, values=["${md5}"], ignoreCase=true)`);
  });

  it("IP → NetworkConnectIP4 on RemoteAddressIP4", () => {
    const q = api.huntCql(ctx({ ips: ["10.1.2.3", "198.51.100.7"] }));
    expect(q).toContain("#event_simpleName=NetworkConnectIP4");
    expect(q).toContain('in(field=RemoteAddressIP4, values=["10.1.2.3", "198.51.100.7"], ignoreCase=true)');
  });

  it("domain and URL host → DnsRequest on DomainName", () => {
    const q = api.huntCql(ctx({ domains: ["evil.example"], urls: ["https://cdn.bad.example/x?y=1"] }));
    expect(q).toContain("#event_simpleName=DnsRequest");
    expect(q).toContain('in(field=DomainName, values=["evil.example", "cdn.bad.example"], ignoreCase=true)');
  });

  it("file path → *Written events with a suffix match on TargetFileName (Falcon paths are device-style)", () => {
    const q = api.huntCql(ctx({ paths: ["\\\\?\\C:\\Users\\a\\AppData\\drop.ps1"] }));
    expect(q).toContain("#event_simpleName=/Written$/");
    expect(q).toContain("TargetFileName=/\\\\(?:drop\\.ps1)$/i");
  });

  it("never writes the entity label or host into the query (they are free attacker text)", () => {
    const q = api.huntCql(ctx({ label: "LABEL\n| delete", host: "HOST\nX", ips: ["1.2.3.4"] }));
    expect(q).not.toContain("LABEL");
    expect(q).not.toContain("HOST");
  });
});

describe("CQL escaping of attacker-controlled values", () => {
  it("cqlString escapes backslash and double quote so the value cannot close the string", () => {
    expect(api.cqlString('a"b\\c')).toBe('"a\\"b\\\\c"');
  });

  it('cqlMatch keeps a value with `"` and `\\` exact inside in()', () => {
    expect(api.cqlMatch("DomainName", ['a"b\\c'])).toBe(
      'in(field=DomainName, values=["a\\"b\\\\c"], ignoreCase=true)',
    );
  });

  it("a value with `*` goes to an anchored, escaped regex so the wildcard cannot widen the match", () => {
    const m = api.cqlMatch("DomainName", ["evil*.com", "ok.com"]);
    expect(m).toBe("DomainName=/^(?:evil\\*\\.com|ok\\.com)$/i");
    expect(m).not.toContain('"evil*.com"');
  });

  it("a value with a newline goes to the regex form too, since a quoted string cannot span lines", () => {
    const m = api.cqlMatch("DomainName", ["a\nb"]);
    expect(m).not.toMatch(/\n/);
    expect(m).toBe("DomainName=/^(?:a\\x0ab)$/i");
  });

  it("cqlRegexLiteral escapes every regex metacharacter and the / delimiter", () => {
    expect(api.cqlRegexLiteral('a*b.c/d\\e(f)|g[h]{i}+?^$"')).toBe(
      'a\\*b\\.c\\/d\\\\e\\(f\\)\\|g\\[h\\]\\{i\\}\\+\\?\\^\\$"',
    );
  });

  it('an IOC built of `"`, `\\` and `*` cannot break out of the generated query', () => {
    const q = api.huntCql(ctx({ domains: ['x"\\*'], processes: ['C:\\x\\p"*.exe'] }));
    expect(q).toContain('DomainName=/^(?:x"\\\\\\*)$/i');
    expect(q).toContain('ImageFileName=/\\\\(?:p"\\*\\.exe)$/i');
    // no quoted value anywhere holds a bare *
    expect(q).not.toMatch(/"[^"\n]*\*[^"\n]*"/);
  });
});

describe("wiring — the eighth platform reaches the modal and the translator", () => {
  const root = new URL("../../../public/", import.meta.url);
  const html = readFileSync(new URL("dashboard.html", root), "utf8");
  const sigmaHunt = readFileSync(new URL("js/dashboard-sigma-hunt.js", root), "utf8");
  const translator = readFileSync(new URL("js/dashboard-query-translator.js", root), "utf8");
  const bulk = readFileSync(new URL("js/dashboard-bulk-findings.js", root), "utf8");

  it("the page tags the module and the server serves it", () => {
    expect(html).toContain('<script src="/js/dashboard-hunt-cql.js"></script>');
    expect(STATIC_ASSETS["/js/dashboard-hunt-cql.js"]).toMatch(/javascript/);
  });

  it("a blank DFIR_HUNT_PLATFORMS default set on the page holds all eight keys", () => {
    const m = html.match(/let enabledHuntPlatforms = new Set\(\[([^\]]*)\]\)/);
    expect(m).not.toBeNull();
    const keys = [...(m?.[1] ?? "").matchAll(/"([a-z]+)"/g)].map((x) => x[1]);
    expect(keys).toEqual([...HUNT_PLATFORMS]);
    expect(keys).toHaveLength(8);
  });

  it("the hunt modal has a crowdstrike card built by huntCql", () => {
    expect(sigmaHunt).toMatch(/\["crowdstrike",\s*"[^"]*CQL[^"]*",\s*huntCql\(c\)\]/);
  });

  it("the Query Translator lists crowdstrike with a label, and the hunt button tooltip names it", () => {
    expect(translator).toMatch(/crowdstrike:\s*"[^"]*CQL/);
    expect(translator).toMatch(/"suricata",\s*"crowdstrike",/);
    expect(bulk).toMatch(/Suricata, CrowdStrike CQL\)/);
  });
});
