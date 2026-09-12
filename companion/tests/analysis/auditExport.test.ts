import { describe, it, expect } from "vitest";
import {
  AUDIT_DESTINATION_TYPES,
  applyDestinationPatch,
  parseDestinationInput,
  redactDestination,
  testAuditEvent,
  toAuditEvent,
  type AuditDestination,
} from "../../src/analysis/auditExport.js";
import type { ActivityLogEntry } from "../../src/analysis/activityLog.js";

const entry = (over: Partial<ActivityLogEntry> = {}): ActivityLogEntry => ({
  id: "e1",
  timestamp: "2026-09-12T10:00:00.000Z",
  actor: "alice",
  category: "triage",
  action: "mark_false_positive",
  detail: "marked finding f3 as a false positive",
  outcome: "success",
  ...over,
});

const dest = (over: Partial<AuditDestination> = {}): AuditDestination => ({
  id: "d1",
  type: "splunk",
  name: "SOC Splunk",
  enabled: true,
  createdAt: "2026-09-12T09:00:00.000Z",
  updatedAt: "2026-09-12T09:00:00.000Z",
  splunk: { url: "https://splunk.example.com:8088", token: "hec-secret" },
  ...over,
});

describe("toAuditEvent", () => {
  it("carries the fields a SIEM needs, including the ones #929 omitted", () => {
    const e = toAuditEvent(entry(), "case-7");
    // #929 proposed timestamp/caseId/category/action/detail only. `id` is what makes a retry
    // idempotent in the SIEM, and `outcome` is what tells an auditor a failed action from a
    // successful one.
    expect(e.id).toBe("e1");
    expect(e.outcome).toBe("success");
    expect(e.caseId).toBe("case-7");
    expect(e.category).toBe("triage");
    expect(e.action).toBe("mark_false_positive");
    expect(e.detail).toBe("marked finding f3 as a false positive");
    expect(e.timestamp).toBe("2026-09-12T10:00:00.000Z");
  });

  it("says whether the actor was verified by the server or asserted by the client", () => {
    // The whole compliance value of the feed rests on this distinction. An entry with an
    // authenticated session carries actorId; one recorded in single-user mode does not.
    const verified = toAuditEvent(
      entry({ actorId: "u-9", actorDisplayName: "Alice Ng", actorKind: "oidc" }),
      "case-7",
    );
    expect(verified.actorVerified).toBe(true);
    expect(verified.actorId).toBe("u-9");
    expect(verified.actorKind).toBe("oidc");

    const asserted = toAuditEvent(entry(), "case-7");
    expect(asserted.actorVerified).toBe(false);
    expect(asserted.actorId).toBeUndefined();
  });

  it("omits absent optional target fields rather than emitting empty strings", () => {
    const e = toAuditEvent(entry(), "case-7");
    expect("targetType" in e).toBe(false);
    expect("targetId" in e).toBe(false);
    const withTarget = toAuditEvent(entry({ targetType: "finding", targetId: "f3" }), "case-7");
    expect(withTarget.targetType).toBe("finding");
    expect(withTarget.targetId).toBe("f3");
  });
});

describe("parseDestinationInput", () => {
  it("accepts each supported type", () => {
    expect(AUDIT_DESTINATION_TYPES).toEqual(["splunk", "elastic", "syslog"]);
  });

  it("requires an http(s) collector URL and a token for splunk", () => {
    expect(parseDestinationInput({ type: "splunk", splunk: { url: "not-a-url", token: "t" } }).ok).toBe(
      false,
    );
    const noToken = parseDestinationInput({
      type: "splunk",
      splunk: { url: "https://splunk.example.com:8088" },
    });
    expect(noToken.ok).toBe(false);
    expect(noToken.error).toMatch(/token/i);
    const ok = parseDestinationInput({
      type: "splunk",
      splunk: { url: "https://splunk.example.com:8088", token: "t" },
    });
    expect(ok.ok).toBe(true);
    expect(ok.draft?.splunk?.url).toBe("https://splunk.example.com:8088");
  });

  it("requires a URL and an index for elastic, and allows an unauthenticated cluster", () => {
    expect(parseDestinationInput({ type: "elastic", elastic: { url: "https://es:9200" } }).ok).toBe(false);
    const ok = parseDestinationInput({
      type: "elastic",
      elastic: { url: "https://es:9200", index: "dfir-audit" },
    });
    expect(ok.ok).toBe(true);
    expect(ok.draft?.elastic?.index).toBe("dfir-audit");
  });

  it("requires a host, a usable port, and a known protocol for syslog", () => {
    expect(parseDestinationInput({ type: "syslog", syslog: { host: "", port: 514 } }).ok).toBe(false);
    expect(parseDestinationInput({ type: "syslog", syslog: { host: "siem", port: 70000 } }).ok).toBe(false);
    expect(
      parseDestinationInput({ type: "syslog", syslog: { host: "siem", port: 514, protocol: "sctp" } }).ok,
    ).toBe(false);
    const ok = parseDestinationInput({
      type: "syslog",
      syslog: { host: "siem", port: 514, protocol: "tcp" },
    });
    expect(ok.ok).toBe(true);
    expect(ok.draft?.syslog?.protocol).toBe("tcp");
  });

  it("defaults the syslog protocol to udp and the port to 514", () => {
    const ok = parseDestinationInput({ type: "syslog", syslog: { host: "siem" } });
    expect(ok.draft?.syslog).toMatchObject({ host: "siem", port: 514, protocol: "udp" });
  });

  it("keeps a saved secret when the edit leaves the redacted field blank", () => {
    const existing = dest();
    const parsed = parseDestinationInput(
      { type: "splunk", splunk: { url: "https://splunk.example.com:8088", token: "" } },
      existing,
    );
    expect(parsed.ok).toBe(true);
    const next = applyDestinationPatch(existing, parsed.draft!, "2026-09-12T11:00:00.000Z");
    expect(next.splunk?.token).toBe("hec-secret");
  });

  it("refuses to inherit the credential when the collector URL changes", () => {
    // The same defect as the type change below, one step subtler: keeping the type but repointing
    // the URL and leaving the redacted token blank would send the old collector's HEC token to a
    // new host. Gating secret inheritance on the type alone is not enough — the endpoint is what
    // the credential is FOR.
    const moved = parseDestinationInput(
      { type: "splunk", splunk: { url: "https://other-splunk.example.com:8088", token: "" } },
      dest(),
    );
    expect(moved.ok).toBe(false);
    expect(moved.error).toMatch(/token/i);

    // The same URL with a blank token still keeps the saved one.
    const same = parseDestinationInput(
      { type: "splunk", splunk: { url: "https://splunk.example.com:8088", token: "" } },
      dest(),
    );
    expect(same.ok).toBe(true);
    expect(applyDestinationPatch(dest(), same.draft!, "x").splunk?.token).toBe("hec-secret");

    // A trailing slash is the same collector, not a new one.
    const slash = parseDestinationInput(
      { type: "splunk", splunk: { url: "https://splunk.example.com:8088/", token: "" } },
      dest(),
    );
    expect(slash.ok).toBe(true);
  });

  it("refuses to inherit an elastic credential when the cluster URL changes", () => {
    const existing = dest({
      type: "elastic",
      splunk: undefined,
      elastic: { url: "https://es.example.com:9200", index: "a", password: "p", apiKey: "k" },
    });
    const moved = parseDestinationInput(
      { type: "elastic", elastic: { url: "https://other-es.example.com:9200", index: "a" } },
      existing,
    );
    // An elastic cluster may legitimately have no credential, so a URL change cannot be refused
    // outright — but it must not carry the old cluster's password or key across.
    expect(moved.ok).toBe(true);
    const next = applyDestinationPatch(existing, moved.draft!, "x");
    expect(next.elastic?.password).toBeUndefined();
    expect(next.elastic?.apiKey).toBeUndefined();
  });

  it("keeps the index and sourcetype across a URL change — they are not credentials", () => {
    const existing = dest({
      splunk: {
        url: "https://splunk.example.com:8088",
        token: "t",
        index: "audit",
        sourcetype: "dfir:activity",
      },
    });
    const moved = parseDestinationInput(
      { type: "splunk", splunk: { url: "https://new.example.com:8088", token: "fresh" } },
      existing,
    );
    expect(moved.ok).toBe(true);
    expect(moved.draft?.splunk).toMatchObject({ index: "audit", sourcetype: "dfir:activity" });
  });

  it("refuses to inherit the old type's secret when the type changes (#683's lesson)", () => {
    // A saved Splunk destination retyped to Elastic with a blank credential must not silently
    // reuse the HEC token as an Elastic password. Posting one system's credential to another is
    // exactly the class of bug #683 fixed for webhook channels.
    const parsed = parseDestinationInput(
      { type: "elastic", elastic: { url: "https://es:9200", index: "dfir-audit", password: "" } },
      dest(),
    );
    expect(parsed.ok).toBe(true);
    const next = applyDestinationPatch(dest(), parsed.draft!, "2026-09-12T11:00:00.000Z");
    expect(next.splunk).toBeUndefined();
    expect(next.elastic?.password).toBeUndefined();
  });
});

describe("redactDestination", () => {
  it("never returns a secret, only whether one is set", () => {
    const r = redactDestination(dest());
    expect(JSON.stringify(r)).not.toContain("hec-secret");
    expect(r.splunk).toMatchObject({ url: "https://splunk.example.com:8088", hasToken: true });
  });

  it("reports elastic password and api key separately", () => {
    const r = redactDestination(
      dest({
        type: "elastic",
        splunk: undefined,
        elastic: { url: "https://es:9200", index: "a", password: "p" },
      }),
    );
    expect(JSON.stringify(r)).not.toContain('"p"');
    expect(r.elastic).toMatchObject({ hasPassword: true, hasApiKey: false });
  });

  it("leaves a syslog destination intact — it carries no secret", () => {
    const r = redactDestination(
      dest({ type: "syslog", splunk: undefined, syslog: { host: "siem", port: 514, protocol: "udp" } }),
    );
    expect(r.syslog).toEqual({ host: "siem", port: 514, protocol: "udp" });
  });
});

describe("testAuditEvent", () => {
  it("is clearly marked as a test so it cannot be mistaken for a real action", () => {
    const e = testAuditEvent("2026-09-12T12:00:00.000Z");
    expect(e.timestamp).toBe("2026-09-12T12:00:00.000Z");
    expect(e.category).toBe("settings");
    expect(e.action).toMatch(/test/i);
    expect(e.actorVerified).toBe(false);
  });
});
