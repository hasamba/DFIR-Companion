import { describe, it, expect } from "vitest";
import { parseNetworkLogs, zeekStreamFromName, inferZeekStream } from "../../src/analysis/networkImport.js";

// ── Suricata eve.json records ───────────────────────────────────────────────
function suricataAlert(): object {
  return {
    timestamp: "2017-12-01T08:00:00.123456+0000",
    event_type: "alert",
    src_ip: "10.0.0.5", src_port: 51000, dest_ip: "203.0.113.9", dest_port: 443, proto: "TCP",
    alert: {
      signature: "ET MALWARE Cobalt Strike Beacon",
      category: "A Network Trojan was detected",
      signature_id: 2027000, severity: 1,
      metadata: { mitre_technique_id: ["T1071.001"], mitre_tactic_id: ["TA0011"] },
    },
  };
}
function suricataDns(): object {
  return {
    timestamp: "2017-12-01T08:00:01+0000",
    event_type: "dns",
    src_ip: "10.0.0.5", dest_ip: "10.0.0.1",
    dns: { type: "query", rrname: "evil-c2.example.com", rrtype: "A" },
  };
}
function suricataFileinfo(): object {
  return {
    timestamp: "2017-12-01T08:00:02+0000",
    event_type: "fileinfo",
    fileinfo: { filename: "/payload.exe", sha256: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", size: 1024 },
  };
}

// ── Zeek JSON records (note the literal dotted keys) ────────────────────────
function zeekNotice(): object {
  return {
    ts: 1512115200,
    _path: "notice",
    note: "Scan::Port_Scan",
    msg: "203.0.113.9 scanned 20 ports of 10.0.0.5",
    src: "203.0.113.9", dst: "10.0.0.5",
  };
}
function zeekDns(): object {
  return { ts: 1512115201, _path: "dns", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.1", query: "bad-domain.test", qtype_name: "A" };
}
function zeekFiles(): object {
  return { ts: 1512115202, _path: "files", mime_type: "application/x-dosexec", filename: "x.exe", sha256: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" };
}

describe("parseNetworkLogs — Suricata eve.json", () => {
  it("turns an alert into a timeline detection with signature, severity, MITRE", () => {
    const r = parseNetworkLogs(JSON.stringify([suricataAlert()]));
    expect(r.format).toBe("suricata");
    expect(r.alerts).toBe(1);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.description).toContain("Suricata alert: ET MALWARE Cobalt Strike Beacon");
    expect(e.description).toContain("10.0.0.5:51000 → 203.0.113.9:443");
    expect(e.severity).toBe("High");              // Suricata priority 1
    expect(e.mitreTechniques).toContain("T1071.001");
    expect(e.sources).toEqual(["Suricata"]);
    expect(e.timestamp).toBe("2017-12-01T08:00:00.123456Z"); // offset → UTC, microseconds preserved
    const ips = r.iocs.filter((i) => i.type === "ip").map((i) => i.value);
    expect(ips).toContain("203.0.113.9");
  });

  it("does NOT create timeline events for telemetry, but extracts its IOCs", () => {
    const r = parseNetworkLogs(JSON.stringify([suricataDns(), suricataFileinfo()]));
    expect(r.events).toHaveLength(0);             // dns + fileinfo are telemetry
    expect(r.alerts).toBe(0);
    expect(r.iocs.find((i) => i.type === "domain")?.value).toBe("evil-c2.example.com");
    expect(r.iocs.some((i) => i.type === "hash")).toBe(true);
    expect(r.iocs.find((i) => i.type === "file")?.value).toBe("/payload.exe");
  });

  it("reads NDJSON (the native eve.json form) and mixes alert + telemetry", () => {
    const text = [suricataAlert(), suricataDns(), suricataFileinfo()].map((o) => JSON.stringify(o)).join("\n");
    const r = parseNetworkLogs(text);
    expect(r.format).toBe("suricata");
    expect(r.events).toHaveLength(1);                       // only the alert
    expect(r.iocs.some((i) => i.type === "domain")).toBe(true);
    expect(r.iocs.some((i) => i.type === "hash")).toBe(true);
  });
});

describe("parseNetworkLogs — Zeek JSON", () => {
  it("turns a notice into a timeline detection and extracts IOCs from telemetry", () => {
    const text = [zeekNotice(), zeekDns(), zeekFiles()].map((o) => JSON.stringify(o)).join("\n");
    const r = parseNetworkLogs(text);
    expect(r.format).toBe("zeek");
    expect(r.events).toHaveLength(1);                       // only the notice
    const e = r.events[0];
    expect(e.description).toContain("Zeek notice: Scan::Port_Scan");
    expect(e.severity).toBe("Medium");
    expect(e.sources).toEqual(["Zeek"]);
    expect(e.timestamp).toBe("2017-12-01T08:00:00.000Z");  // epoch seconds → UTC
    expect(r.iocs.find((i) => i.type === "domain")?.value).toBe("bad-domain.test"); // from dns.log
    expect(r.iocs.some((i) => i.type === "hash")).toBe(true);                       // from files.log
  });
});

describe("parseNetworkLogs — options & edges", () => {
  it("aggregates repeated identical alerts into a counted row", () => {
    const r = parseNetworkLogs([suricataAlert(), suricataAlert()].map((o) => JSON.stringify(o)).join("\n"));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });

  it("severity floor drops low alert events but keeps telemetry IOCs", () => {
    const lowAlert = { ...suricataAlert(), alert: { signature: "ET INFO low", category: "Misc", signature_id: 1, severity: 3 } };
    const text = [lowAlert, suricataDns()].map((o) => JSON.stringify(o)).join("\n");
    const r = parseNetworkLogs(text, { minSeverity: "Medium" });
    expect(r.events).toHaveLength(0);                        // the Low alert dropped
    expect(r.iocs.some((i) => i.type === "domain")).toBe(true); // dns IOC still kept
  });

  it("reports the mixed format when both tools appear", () => {
    const r = parseNetworkLogs([suricataAlert(), zeekNotice()].map((o) => JSON.stringify(o)).join("\n"));
    expect(r.format).toBe("mixed");
    expect(r.events).toHaveLength(2);
  });

  it("reports empty for a non-network file", () => {
    const r = parseNetworkLogs("not json");
    expect(r.format).toBe("empty");
    expect(r.events).toHaveLength(0);
  });
});

// ── Zeek PER-STREAM JSON (no `_path` — the filename names the stream) — #197 ─────────────────
describe("parseNetworkLogs — Zeek per-stream JSON (no _path)", () => {
  const dns = { ts: 1512115201, uid: "C1", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.1", query: "evil-c2.example.com", qtype_name: "A" };
  const http = { ts: 1512115202, uid: "C2", "id.orig_h": "10.0.0.5", method: "GET", host: "download.bad.test", uri: "/x.exe" };
  const files = { ts: 1512115203, fuid: "F1", mime_type: "application/x-dosexec", filename: "x.exe", sha256: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" };
  const x509 = { ts: 1512115204, id: "C3", fingerprint: "ab:cd", "certificate.serial": "01", "san.dns": ["cert.bad.test", "alt.bad.test"] };
  const conn = { ts: 1512115205, uid: "C4", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.9", proto: "tcp", conn_state: "S0" };

  it("extracts the DNS query as a domain IOC using the filename hint, no timeline event", () => {
    const r = parseNetworkLogs(JSON.stringify(dns), { filename: "0004_dns.json" });
    expect(r.format).toBe("zeek");
    expect(r.events).toHaveLength(0);
    expect(r.iocs.find((i) => i.type === "domain")?.value).toBe("evil-c2.example.com");
  });

  it("extracts http host + uri without a filename (field inference)", () => {
    const r = parseNetworkLogs(JSON.stringify(http));
    expect(r.iocs.some((i) => i.type === "domain" && i.value === "download.bad.test")).toBe(true);
    expect(r.iocs.some((i) => i.type === "url" && i.value === "/x.exe")).toBe(false); // uri w/o scheme is not a URL IOC
    expect(r.events).toHaveLength(0);
  });

  it("extracts file hashes from a per-stream files.json", () => {
    const r = parseNetworkLogs(JSON.stringify(files), { filename: "files.json" });
    expect(r.iocs.some((i) => i.type === "hash")).toBe(true);
    expect(r.iocs.some((i) => i.type === "file" && i.value === "x.exe")).toBe(true);
  });

  it("extracts cert SAN DNS names from x509 (san.dns array)", () => {
    const r = parseNetworkLogs(JSON.stringify(x509), { filename: "x509.json" });
    const domains = r.iocs.filter((i) => i.type === "domain").map((i) => i.value);
    expect(domains).toContain("cert.bad.test");
    expect(domains).toContain("alt.bad.test");
  });

  it("treats conn telemetry as IOC-free flow — no events, no noise rows", () => {
    const r = parseNetworkLogs([conn, conn].map((o) => JSON.stringify(o)).join("\n"), { filename: "conn.json" });
    expect(r.format).toBe("zeek");
    expect(r.events).toHaveLength(0);
    expect(r.iocs).toHaveLength(0);
  });

  it("zeekStreamFromName strips seq prefix + extension", () => {
    expect(zeekStreamFromName("0004_conn.json")).toBe("conn");
    expect(zeekStreamFromName("dns.log")).toBe("dns");
    expect(zeekStreamFromName("x509.json")).toBe("x509");
    expect(zeekStreamFromName("random.json")).toBe("");
  });

  it("inferZeekStream classifies records by their fields", () => {
    expect(inferZeekStream(dns)).toBe("dns");
    expect(inferZeekStream(http)).toBe("http");
    expect(inferZeekStream(files)).toBe("files");
    expect(inferZeekStream(x509)).toBe("x509");
    expect(inferZeekStream(conn)).toBe("conn");
  });
});
