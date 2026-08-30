import { describe, it, expect } from "vitest";
import {
  md5Buffer,
  probeAnalysis,
  uploadBuffer,
  checkStatus,
  fetchVerdicts,
} from "../../src/integrations/socrates/socratesApi.js";

// Minimal fetch double: map a URL substring to a JSON body, and record every requested URL.
function mockFetch(routes: Array<[string, unknown]>, seen: string[] = []) {
  return (async (input: unknown) => {
    const url = String(input);
    seen.push(url);
    for (const [needle, body] of routes) {
      if (url.includes(needle)) {
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
    }
    return new Response(JSON.stringify({ error: "not found" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

describe("md5Buffer", () => {
  it("computes the MD5 SO-CRATES keys analyses by", () => {
    // Canonical: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
    expect(md5Buffer(Buffer.from("abc"))).toBe("900150983cd24fb0d6963f7d28e17f72");
  });
});

describe("probeAnalysis", () => {
  it("reports ready for an already-analyzed md5", async () => {
    const f = mockFetch([["/api/status", { status: "ready", meta: { detected_type: "pcap" } }]]);
    const res = await probeAnalysis("http://localhost:8000", "a".repeat(32), f);
    expect(res.status).toBe("ready");
    expect(res.meta?.detected_type).toBe("pcap");
  });
});

describe("uploadBuffer", () => {
  it("posts multipart and returns the md5 and phase", async () => {
    const seen: string[] = [];
    const f = mockFetch(
      [["/api/upload", { status: "processing", md5: "b".repeat(32), phase: "network" }]],
      seen,
    );
    const res = await uploadBuffer("http://localhost:8000", Buffer.from("PK"), "eve.pcap", f);
    expect(res).toEqual({ status: "processing", md5: "b".repeat(32), phase: "network" });
    expect(seen[0]).toContain("/api/upload");
  });
});

describe("checkStatus", () => {
  it("surfaces the error status and message", async () => {
    const f = mockFetch([["/api/check-status", { status: "error", message: "suricata failed" }]]);
    const res = await checkStatus("http://localhost:8000", "c".repeat(32), f);
    expect(res.status).toBe("error");
    expect(res.message).toBe("suricata failed");
  });
});

describe("fetchVerdicts", () => {
  it("pulls only the three verdict feeds, never the unfiltered event list", async () => {
    const seen: string[] = [];
    const f = mockFetch(
      [
        ["type=alert", [{ event_type: "alert", alert: { signature: "ET TROJAN" } }]],
        ["type=filealerts", [{ event_type: "filealerts", filealerts: [{ rule: "evil" }] }]],
        ["/api/sigma-alerts", [{ rule_title: "Suspicious PowerShell", rule_id: "abc-123" }]],
      ],
      seen,
    );

    const res = await fetchVerdicts("http://localhost:8000", "d".repeat(32), f);
    expect(res.alerts).toBe(1);
    expect(res.yara).toBe(1);
    expect(res.sigma).toBe(1);

    // Post-detection principle: an unfiltered /api/events call would drag in whole-capture telemetry.
    const events = seen.filter((u) => u.includes("/api/events"));
    expect(events.length).toBeGreaterThan(0);
    expect(events.every((u) => u.includes("type="))).toBe(true);

    const rows = JSON.parse(res.text) as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(3);
    expect(rows.every((r) => r._Source === "SO-CRATES")).toBe(true);
  });

  it("pages until a short page arrives", async () => {
    const seen: string[] = [];
    const full = Array.from({ length: 1000 }, (_, i) => ({ event_type: "alert", n: i }));
    let alertCall = 0;
    const f = (async (input: unknown) => {
      const url = String(input);
      seen.push(url);
      let body: unknown = [];
      if (url.includes("type=alert")) body = alertCall++ === 0 ? full : [{ event_type: "alert", n: 1000 }];
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    const res = await fetchVerdicts("http://localhost:8000", "e".repeat(32), f);
    expect(res.alerts).toBe(1001);
    expect(seen.filter((u) => u.includes("type=alert") && u.includes("offset=1000"))).toHaveLength(1);
  });
});
