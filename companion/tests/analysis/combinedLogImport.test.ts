import { describe, it, expect } from "vitest";
import {
  looksLikeCombinedLog, parseApacheDate, requestHost, mapCombinedLogLine, parseCombinedLog,
} from "../../src/analysis/combinedLogImport.js";
import type { SiemIoc } from "../../src/analysis/siemImport.js";

const HEALTH = '10.30.20.11 - - [14/May/2024:19:00:00 +0000] "GET /status HTTP/1.1" 200 83 "-" "Prometheus/2.47.0"';
const CONNECT_EXFIL = '10.30.10.14 - arjun.mehta@northpeaklabs.com [15/May/2024:06:42:01 +0000] "CONNECT vault.cloudpear.io:443 HTTP/1.1" 200 163 "-" "Wget/1.21.3"';
const GET_EXFIL = '10.30.10.14 - arjun.mehta@northpeaklabs.com [15/May/2024:06:42:01 +0000] "GET https://vault.cloudpear.io/u/arjun/bk-0514.tgz HTTP/1.1" 200 18376 "-" "Wget/1.21.3"';
const GIT_CLONE = '10.30.10.14 - - [15/May/2024:05:30:58 +0000] "GET /perception-core.git/info/refs?service=git-upload-pack HTTP/1.1" 200 524288000 "-" "git/2.34.1"';
const GIT_DENIED = '10.30.10.14 - - [15/May/2024:05:31:11 +0000] "GET /security/keystore-svc.git/info/refs?service=git-upload-pack HTTP/1.1" 403 1275 "http://git.corp.northpeaklabs.com/" "git/2.34.1"';

describe("looksLikeCombinedLog", () => {
  it("matches by filename", () => {
    expect(looksLikeCombinedLog("web_access.log", "")).toBe(true);
    expect(looksLikeCombinedLog("proxy_access.log", "")).toBe(true);
    expect(looksLikeCombinedLog("access.log", "")).toBe(true);
  });
  it("matches by content signature (no filename hint)", () => {
    expect(looksLikeCombinedLog("dump.txt", [HEALTH, CONNECT_EXFIL].join("\n"))).toBe(true);
  });
  it("does NOT claim an arbitrary log", () => {
    expect(looksLikeCombinedLog("syslog.log", "May 14 12:00:48 host sshd[1]: Failed password")).toBe(false);
    expect(looksLikeCombinedLog("cisco_asa.log", "%ASA-6-302013: Built inbound TCP connection")).toBe(false);
  });
});

describe("parseApacheDate", () => {
  it("parses the bracketed Apache/Squid timestamp with a timezone offset", () => {
    expect(parseApacheDate("15/May/2024:06:42:01 +0000")).toBe("2024-05-15T06:42:01.000Z");
  });
  it("returns \"\" for garbage", () => {
    expect(parseApacheDate("not a date")).toBe("");
  });
});

describe("requestHost", () => {
  it("extracts the host from an absolute-URL request and a CONNECT target", () => {
    expect(requestHost("https://vault.cloudpear.io/u/arjun/bk-0514.tgz")).toBe("vault.cloudpear.io");
    expect(requestHost("vault.cloudpear.io:443")).toBe("vault.cloudpear.io");
  });
  it("returns \"\" for an ordinary relative path", () => {
    expect(requestHost("/api/v4/projects?per_page=100")).toBe("");
  });
});

describe("mapCombinedLogLine", () => {
  it("keeps routine traffic at Info with no IOC for a relative-path request", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapCombinedLogLine(HEALTH, sink)!;
    expect(m.severity).toBe("Info");
    expect(m.timestamp).toBe("2024-05-14T19:00:00.000Z");
    expect(sink.size).toBe(0);
  });

  it("tags a CONNECT tunnel to an external host as a domain IOC, folds in the authenticated user", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapCombinedLogLine(CONNECT_EXFIL, sink)!;
    expect(m.description).toContain("[arjun.mehta@northpeaklabs.com]");
    expect(m.sources).toEqual(["Web Access Log"]);
    const domains = [...sink.values()].filter((i) => i.type === "domain").map((i) => i.value);
    expect(domains).toContain("vault.cloudpear.io");
  });

  it("tags an absolute-URL GET the same way as the CONNECT tunnel", () => {
    const sink = new Map<string, SiemIoc>();
    const m = mapCombinedLogLine(GET_EXFIL, sink)!;
    expect(m.description).toContain("vault.cloudpear.io/u/arjun/bk-0514.tgz");
    expect([...sink.values()].map((i) => i.value)).toContain("vault.cloudpear.io");
  });

  it("tags a git smart-HTTP clone as T1213 without escalating severity", () => {
    const m = mapCombinedLogLine(GIT_CLONE, new Map())!;
    expect(m.severity).toBe("Info");
    expect(m.mitre).toContain("T1213");
  });

  it("tags a git smart-HTTP request that was DENIED (403) as Low + T1213", () => {
    const m = mapCombinedLogLine(GIT_DENIED, new Map())!;
    expect(m.severity).toBe("Low");
    expect(m.mitre).toContain("T1213");
  });

  it("returns null for a non-matching line", () => {
    expect(mapCombinedLogLine("not a log line at all", new Map())).toBeNull();
  });
});

describe("parseCombinedLog", () => {
  it("parses the northpeak exfil sequence end to end", () => {
    const text = [HEALTH, CONNECT_EXFIL, GET_EXFIL, GIT_CLONE, GIT_DENIED].join("\n");
    const r = parseCombinedLog(text);
    expect(r.total).toBe(5);
    expect(r.format).toBe("combined-log");
    const domains = r.iocs.filter((i) => i.type === "domain").map((i) => i.value);
    expect(domains).toContain("vault.cloudpear.io");
    const denied = r.events.find((e) => e.severity === "Low");
    expect(denied?.mitreTechniques).toContain("T1213");
  });

  it("respects a minSeverity floor", () => {
    const r = parseCombinedLog([HEALTH, GIT_DENIED].join("\n"), { minSeverity: "Low" });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("Low");
  });

  it("aggregates repeated identical requests into one counted row", () => {
    const r = parseCombinedLog([HEALTH, HEALTH, HEALTH].join("\n"));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(3);
  });
});
