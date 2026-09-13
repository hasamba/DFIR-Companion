import { describe, it, expect, vi } from "vitest";
import { sendAuditBatch } from "../../src/integrations/audit/auditSend.js";
import type { AuditEvent, AuditDestination, SyslogConfig } from "../../src/analysis/auditExport.js";

const ev = (over: Partial<AuditEvent> = {}): AuditEvent => ({
  id: "e1",
  timestamp: "2026-09-12T10:00:00.000Z",
  caseId: "case-7",
  category: "triage",
  action: "a",
  detail: "d",
  actor: "alice",
  actorVerified: false,
  outcome: "success",
  ...over,
});

const dest = (over: Partial<AuditDestination> = {}): AuditDestination => ({
  id: "d1",
  type: "splunk",
  name: "SOC",
  enabled: true,
  createdAt: "",
  updatedAt: "",
  splunk: { url: "https://splunk:8088", token: "t" },
  ...over,
});

// A REAL Response, not a hand-rolled object. sendAuditBatch reads the body through
// readBoundedResponse, which streams res.body — a stub carrying only json()/text() hands it
// nothing to read, and the error message silently comes back empty.
const res = (status: number, body: unknown = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

// A collector that reflects the request it received — a debugging proxy, a misconfigured gateway,
// a typosquatted host. Whatever it answers must not carry the credential we presented (#1000).
const reflecting = (status: number, init: RequestInit, extra: Record<string, unknown> = {}): Response =>
  res(status, { error: "bad request", received: init.headers, ...extra });

const transport = (
  fetchFn: unknown,
  syslogSend = vi.fn(async (_lines: readonly string[], _cfg: SyslogConfig) => {}),
) => ({
  fetchFn: fetchFn as never,
  syslogSend,
  hostname: "companion-host",
});

describe("sendAuditBatch — splunk", () => {
  it("reports success on a 200 and says how many records went", async () => {
    const fetchFn = vi.fn(async (_url: string) => res(200, { text: "Success", code: 0 }));
    const r = await sendAuditBatch(dest(), [ev(), ev({ id: "e2" })], transport(fetchFn));
    expect(r.ok).toBe(true);
    expect(r.sent).toBe(2);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(fetchFn.mock.calls[0]?.[0]).toBe("https://splunk:8088/services/collector/event");
  });

  it("surfaces the collector's own complaint on a rejection", async () => {
    const fetchFn = vi.fn(async () => res(403, { text: "Invalid token", code: 4 }));
    const r = await sendAuditBatch(dest(), [ev()], transport(fetchFn));
    expect(r.ok).toBe(false);
    expect(r.sent).toBe(0);
    expect(r.error).toContain("403");
    expect(r.error).toContain("Invalid token");
  });

  it("treats a network failure as a failure, never as a send", async () => {
    const fetchFn = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    });
    const r = await sendAuditBatch(dest(), [ev()], transport(fetchFn));
    expect(r.ok).toBe(false);
    expect(r.error).toContain("ECONNREFUSED");
  });

  it("never puts the credential in the returned error", async () => {
    const fetchFn = vi.fn(async () => res(401, { text: "unauthorized" }));
    const r = await sendAuditBatch(
      dest({ splunk: { url: "https://splunk:8088", token: "super-secret-token" } }),
      [ev()],
      transport(fetchFn),
    );
    expect(r.error).not.toContain("super-secret-token");
  });

  it("scrubs the token from a collector that echoes the request headers back (#1000)", async () => {
    const fetchFn = vi.fn(async (_url: string, init: RequestInit) => reflecting(400, init));
    const r = await sendAuditBatch(
      dest({ splunk: { url: "https://splunk:8088", token: "super-secret-token" } }),
      [ev()],
      transport(fetchFn),
    );
    expect(r.ok).toBe(false);
    expect(r.error).toContain("HTTP 400");
    expect(r.error).toContain("[redacted]");
    expect(r.error).not.toContain("super-secret-token");
  });
});

describe("sendAuditBatch — elastic", () => {
  const elastic = dest({
    type: "elastic",
    splunk: undefined,
    elastic: { url: "https://es:9200", index: "dfir-audit" },
  });

  it("reports success when the bulk response reports no item errors", async () => {
    const fetchFn = vi.fn(async () => res(200, { errors: false, items: [{ create: { status: 201 } }] }));
    const r = await sendAuditBatch(elastic, [ev()], transport(fetchFn));
    expect(r.ok).toBe(true);
    expect(r.sent).toBe(1);
  });

  it("treats a 409 on create as already-stored, not as a failure", async () => {
    // This is what makes a retry safe. The exporter advances its position only after a send
    // succeeds, so a batch whose response was lost IS re-sent; the cluster answers 409 for the
    // records it already holds. Reading that as an error would stall the feed permanently.
    const fetchFn = vi.fn(async () =>
      res(200, {
        errors: true,
        items: [{ create: { status: 409, error: { type: "version_conflict_engine_exception" } } }],
      }),
    );
    const r = await sendAuditBatch(elastic, [ev()], transport(fetchFn));
    expect(r.ok).toBe(true);
  });

  it("fails when an item fails for any other reason", async () => {
    const fetchFn = vi.fn(async () =>
      res(200, {
        errors: true,
        items: [
          { create: { status: 400, error: { type: "mapper_parsing_exception", reason: "bad field" } } },
        ],
      }),
    );
    const r = await sendAuditBatch(elastic, [ev()], transport(fetchFn));
    expect(r.ok).toBe(false);
    expect(r.error).toContain("mapper_parsing_exception");
  });

  it("fails when a 2xx bulk response cannot be read as a bulk response", async () => {
    // A reverse proxy answering 200 with an HTML error page is the real shape of this. The old
    // code read "no item errors" out of an unparseable body and the caller advanced its durable
    // position, permanently skipping those records. Elasticsearch reports per-document acceptance
    // in the body, so an unreadable body is absence of proof, not proof.
    const html = vi.fn(async () => new Response("<html>gateway</html>", { status: 200 }));
    const r = await sendAuditBatch(elastic, [ev()], transport(html));
    expect(r.ok).toBe(false);
    expect(r.sent).toBe(0);
  });

  it("fails when a 2xx bulk response carries no items array", async () => {
    const empty = vi.fn(async () => res(200, {}));
    const r = await sendAuditBatch(elastic, [ev()], transport(empty));
    expect(r.ok).toBe(false);
  });

  it("fails when the response acknowledges fewer records than were sent", async () => {
    const short = vi.fn(async () => res(200, { errors: false, items: [{ create: { status: 201 } }] }));
    const r = await sendAuditBatch(elastic, [ev(), ev({ id: "e2" })], transport(short));
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/2/);
  });

  it("fails on a non-2xx bulk response", async () => {
    const fetchFn = vi.fn(async () => res(503, { error: "unavailable" }));
    const r = await sendAuditBatch(elastic, [ev()], transport(fetchFn));
    expect(r.ok).toBe(false);
    expect(r.error).toContain("503");
  });

  it("scrubs the API key from a cluster that echoes the request headers back (#1000)", async () => {
    const fetchFn = vi.fn(async (_url: string, init: RequestInit) => reflecting(400, init));
    const withKey = dest({
      type: "elastic",
      elastic: { url: "https://es:9200", index: "i", apiKey: "es-secret-key" },
    });
    const r = await sendAuditBatch(withKey, [ev()], transport(fetchFn));
    expect(r.ok).toBe(false);
    expect(r.error).not.toContain("es-secret-key");
  });

  it("scrubs basic-auth — encoded and decoded — from an item reason on a 2xx (#1000)", async () => {
    // The per-item `reason` is the second body path into the error string, and it travels on a
    // 2xx, so a scrub that only guards the non-2xx branch misses it.
    const fetchFn = vi.fn(async (_url: string, init: RequestInit) => {
      const auth = (init.headers as Record<string, string>).Authorization;
      const decoded = Buffer.from(auth.slice("Basic ".length), "base64").toString();
      return res(200, {
        errors: true,
        items: [
          {
            create: {
              status: 401,
              error: { type: "security_exception", reason: `rejected ${auth} (${decoded})` },
            },
          },
        ],
      });
    });
    const withPassword = dest({
      type: "elastic",
      elastic: { url: "https://es:9200", index: "i", username: "svc", password: "es-secret-pw" },
    });
    const r = await sendAuditBatch(withPassword, [ev()], transport(fetchFn));
    expect(r.ok).toBe(false);
    expect(r.error).toContain("security_exception");
    expect(r.error).not.toContain("es-secret-pw");
    expect(r.error).not.toContain(Buffer.from("svc:es-secret-pw").toString("base64"));
  });

  it("scrubs a password that JSON escaping rewrites — quotes and backslashes (#1000)", async () => {
    // The reflected body is JSON, so a password holding `"` or `\` comes back as `\"` and `\\`.
    // A scrub that matches only the raw password walks straight past it.
    const password = String.raw`pa"ss\wo"rd!`;
    const fetchFn = vi.fn(async (_url: string, init: RequestInit) => {
      const auth = (init.headers as Record<string, string>).Authorization;
      const decoded = Buffer.from(auth.slice("Basic ".length), "base64").toString();
      return reflecting(401, init, { decoded });
    });
    const withPassword = dest({
      type: "elastic",
      elastic: { url: "https://es:9200", index: "i", username: "svc", password },
    });
    const r = await sendAuditBatch(withPassword, [ev()], transport(fetchFn));
    expect(r.ok).toBe(false);
    expect(r.error).not.toContain(JSON.stringify(password).slice(1, -1));
    expect(r.error).not.toContain("ss\\\\wo");
    expect(r.error).toContain("[redacted]");
  });
});

describe("sendAuditBatch — syslog", () => {
  const syslog = dest({
    type: "syslog",
    splunk: undefined,
    syslog: { host: "siem", port: 514, protocol: "udp" },
  });

  it("hands one formatted line per record to the socket, not an HTTP request", async () => {
    const syslogSend = vi.fn(async (_lines: readonly string[], _cfg: SyslogConfig) => {});
    const fetchFn = vi.fn(async () => res(200));
    const r = await sendAuditBatch(syslog, [ev(), ev({ id: "e2" })], transport(fetchFn, syslogSend));
    expect(r.ok).toBe(true);
    expect(r.sent).toBe(2);
    expect(fetchFn).not.toHaveBeenCalled();
    const call = syslogSend.mock.calls[0];
    expect(call).toBeDefined();
    const [lines, cfg] = call;
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('caseId="case-7"');
    expect(cfg.host).toBe("siem");
  });

  it("reports a socket failure as a failed send", async () => {
    const syslogSend = vi.fn(async (_lines: readonly string[], _cfg: SyslogConfig) => {
      throw new Error("EHOSTUNREACH");
    });
    const r = await sendAuditBatch(syslog, [ev()], transport(vi.fn(), syslogSend));
    expect(r.ok).toBe(false);
    expect(r.error).toContain("EHOSTUNREACH");
  });
});

describe("sendAuditBatch — nothing to send", () => {
  it("succeeds without touching the network for an empty batch", async () => {
    const fetchFn = vi.fn(async () => res(200));
    const r = await sendAuditBatch(dest(), [], transport(fetchFn));
    expect(r).toMatchObject({ ok: true, sent: 0 });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("fails a destination whose config block is missing rather than sending nowhere", async () => {
    const broken = dest({ splunk: undefined });
    const r = await sendAuditBatch(broken, [ev()], transport(vi.fn()));
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not configured/i);
  });
});
