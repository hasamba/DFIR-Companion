import { describe, it, expect } from "vitest";
import { formatSplunkHec } from "../../src/integrations/audit/splunkHecFormat.js";
import { formatElasticBulk } from "../../src/integrations/audit/elasticBulkFormat.js";
import { formatSyslog } from "../../src/integrations/audit/syslogFormat.js";
import type { AuditEvent } from "../../src/analysis/auditExport.js";

const ev = (over: Partial<AuditEvent> = {}): AuditEvent => ({
  id: "e1",
  timestamp: "2026-09-12T10:00:00.000Z",
  caseId: "case-7",
  category: "triage",
  action: "mark_false_positive",
  detail: "marked finding f3",
  actor: "alice",
  actorVerified: false,
  outcome: "success",
  ...over,
});

describe("formatSplunkHec", () => {
  it("posts to the HEC event endpoint with the Splunk token scheme", () => {
    const r = formatSplunkHec([ev()], { url: "https://splunk:8088", token: "hec-secret" });
    expect(r.url).toBe("https://splunk:8088/services/collector/event");
    expect(r.headers.Authorization).toBe("Splunk hec-secret");
    expect(r.headers["content-type"]).toBe("application/json");
  });

  it("wraps each record in an HEC envelope with epoch-seconds time", () => {
    const r = formatSplunkHec([ev()], { url: "https://splunk:8088", token: "t" });
    const lines = r.body.trim().split("\n");
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]);
    // HEC reads `time` as epoch seconds, not an ISO string. Sending the ISO string makes every
    // record land at index time instead of at the time the action happened.
    expect(parsed.time).toBe(Date.parse("2026-09-12T10:00:00.000Z") / 1000);
    expect(parsed.event.id).toBe("e1");
    expect(parsed.event.caseId).toBe("case-7");
  });

  it("sends the index and sourcetype only when configured", () => {
    const bare = JSON.parse(formatSplunkHec([ev()], { url: "https://s:8088", token: "t" }).body.trim());
    expect("index" in bare).toBe(false);
    const set = JSON.parse(
      formatSplunkHec([ev()], {
        url: "https://s:8088",
        token: "t",
        index: "audit",
        sourcetype: "dfir:activity",
      }).body.trim(),
    );
    expect(set.index).toBe("audit");
    expect(set.sourcetype).toBe("dfir:activity");
  });

  it("one line per record, and a newline in the detail never becomes a second record", () => {
    const r = formatSplunkHec([ev({ detail: "line one\nline two" }), ev({ id: "e2" })], {
      url: "https://s:8088",
      token: "t",
    });
    const lines = r.body.trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).event.detail).toBe("line one\nline two");
  });
});

describe("formatElasticBulk", () => {
  it("posts NDJSON to _bulk and ends the body with a newline", () => {
    const r = formatElasticBulk([ev()], { url: "https://es:9200", index: "dfir-audit" });
    expect(r.url).toBe("https://es:9200/_bulk");
    expect(r.headers["content-type"]).toBe("application/x-ndjson");
    // Elasticsearch rejects a bulk body whose last line is not newline-terminated.
    expect(r.body.endsWith("\n")).toBe(true);
  });

  it("uses create with the entry id so a retried batch cannot duplicate rows", () => {
    const r = formatElasticBulk([ev()], { url: "https://es:9200", index: "dfir-audit" });
    const [action, doc] = r.body.trim().split("\n");
    expect(JSON.parse(action)).toEqual({ create: { _index: "dfir-audit", _id: "e1" } });
    expect(JSON.parse(doc).action).toBe("mark_false_positive");
  });

  it("sends basic auth for a username and password, and ApiKey for a key", () => {
    const basic = formatElasticBulk([ev()], {
      url: "https://es:9200",
      index: "a",
      username: "u",
      password: "p",
    });
    expect(basic.headers.Authorization).toBe(`Basic ${Buffer.from("u:p").toString("base64")}`);
    const key = formatElasticBulk([ev()], { url: "https://es:9200", index: "a", apiKey: "k" });
    expect(key.headers.Authorization).toBe("ApiKey k");
  });

  it("sends no Authorization header for an unauthenticated cluster", () => {
    const r = formatElasticBulk([ev()], { url: "https://es:9200", index: "a" });
    expect("Authorization" in r.headers).toBe(false);
  });

  it("emits two lines per record", () => {
    const r = formatElasticBulk([ev(), ev({ id: "e2" })], { url: "https://es:9200", index: "a" });
    expect(r.body.trim().split("\n")).toHaveLength(4);
  });
});

describe("formatSyslog", () => {
  const cfg = { host: "siem", port: 514, protocol: "udp" as const };

  it("emits one RFC 5424 line per record", () => {
    const lines = formatSyslog([ev()], cfg, "companion-host");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^<\d{1,3}>1 2026-09-12T10:00:00\.000Z companion-host dfir-companion /);
  });

  it("grades a failed action above a successful one", () => {
    // Facility 13 is 'log audit'. Severity 6 (informational) for success, 4 (warning) for a
    // failure, so a SIEM rule can select failures by priority alone.
    const ok = formatSyslog([ev()], cfg, "h")[0];
    const bad = formatSyslog([ev({ outcome: "error" })], cfg, "h")[0];
    expect(ok.startsWith("<110>1 ")).toBe(true);
    expect(bad.startsWith("<108>1 ")).toBe(true);
  });

  it("carries the structured fields a SIEM can filter on", () => {
    const line = formatSyslog([ev({ actorId: "u-9", actorVerified: true })], cfg, "h")[0];
    expect(line).toContain('caseId="case-7"');
    expect(line).toContain('actor="alice"');
    expect(line).toContain('actorVerified="true"');
    expect(line).toContain('entryId="e1"');
    expect(line).toContain('outcome="success"');
  });

  it("uses the configured app name when one is set", () => {
    const line = formatSyslog([ev()], { ...cfg, appName: "dfir-prod" }, "h")[0];
    expect(line).toContain(" dfir-prod ");
  });

  it("escapes the RFC 5424 structured-data metacharacters", () => {
    // A quote, a backslash or a ] inside a param value ends the element early and lets evidence
    // text forge extra fields. Adversary-controlled strings reach `detail` and `targetId`.
    const line = formatSyslog([ev({ targetId: 'a"b\\c]d', detail: "x" })], cfg, "h")[0];
    expect(line).toContain('targetId="a\\"b\\\\c\\]d"');
  });

  it("never lets a newline in the detail split one record into two", () => {
    // A CR or LF in the message is a syslog record separator. Left raw, evidence text could inject
    // a whole fabricated audit line into the SIEM. The injected text is neutralised in place, not
    // deleted: the record stays one line and the reader still sees exactly what the evidence said.
    const lines = formatSyslog([ev({ detail: "real\n<110>1 forged line" })], cfg, "h");
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toMatch(/[\r\n]/);
    expect(lines[0]).toContain("real <110>1 forged line");
    // The forged priority never begins a record — that is the whole point.
    expect(lines[0].indexOf("<110>1")).toBe(0);
    expect(lines[0].lastIndexOf("<110>1")).toBeGreaterThan(0);
  });

  it("caps a single record so one huge detail cannot be silently truncated mid-field", () => {
    const line = formatSyslog([ev({ detail: "x".repeat(9000) })], cfg, "h")[0];
    expect(line.length).toBeLessThanOrEqual(2048);
    expect(line).toContain("…");
  });
});
