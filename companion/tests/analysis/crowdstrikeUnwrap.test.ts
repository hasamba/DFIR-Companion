import { describe, it, expect } from "vitest";
import { splitCrowdstrikeFile, innerRecord } from "../../src/analysis/crowdstrikeUnwrap.js";
import { isCrowdstrikeWrapper } from "../../src/analysis/crowdstrikeImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

// #2592 Part 3 — LogScale / Next-Gen SIEM rows wrapping third-party data. Synthetic only.
const okta = (n: number) => ({
  uuid: `u${n}`,
  published: "2024-11-12T08:00:00.000Z",
  eventType: "user.session.start",
  actor: { alternateId: `user${n}@example.com`, type: "User" },
  outcome: { result: "SUCCESS" },
  client: { ipAddress: "198.51.100.20" },
});
const wrapOkta = (n: number) => ({
  "@timestamp": 1731398400000,
  "@rawstring": JSON.stringify(okta(n)),
  "#repo": "3pi_okta",
  "#type": "okta-sso",
});
const sensor = (n: number) => ({
  "#event_simpleName": "DnsRequest",
  aid: "a",
  ComputerName: "WS-01",
  ContextTimeStamp: "1731399999",
  DomainName: `h${n}.example.com`,
  "@rawstring": "{}",
  "#repo": "base_sensor",
});
const gcpAudit = {
  protoPayload: {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    methodName: "io.k8s.core.v1.configmaps.get",
    serviceName: "k8s.io",
    authenticationInfo: { principalEmail: "svc@example.com" },
  },
  logName: "projects/p/logs/cloudaudit.googleapis.com%2Fdata_access",
  timestamp: "2024-11-12T08:00:00Z",
  resource: { type: "k8s_cluster" },
};
const nd = (...r: unknown[]) => r.map((x) => JSON.stringify(x)).join("\n");

describe("wrapper detection", () => {
  it("claims raw and parsed wrappers, not sensor rows or Vendor without LogScale metadata", () => {
    expect(isCrowdstrikeWrapper(wrapOkta(1))).toBe(true);
    expect(isCrowdstrikeWrapper({ "@timestamp": 1, Vendor: gcpAudit })).toBe(true);
    expect(isCrowdstrikeWrapper({ "#repo": "x", "Vendor.protoPayload.methodName": "m" })).toBe(true);
    expect(isCrowdstrikeWrapper(sensor(1))).toBe(false);
    expect(isCrowdstrikeWrapper({ Vendor: gcpAudit })).toBe(false);
  });
  it("a file of wrapped rows detects as crowdstrike; a plain GCP audit file still detects as before", () => {
    expect(detectImportKind("export.ndjson", nd(wrapOkta(1), wrapOkta(2)))).toBe("crowdstrike");
    const csv = "@timestamp,#repo,Vendor.protoPayload.methodName\n1731398400000,gcp,io.k8s.get\n";
    expect(detectImportKind("export.csv", csv)).toBe("crowdstrike");
    expect(detectImportKind("audit.json", nd(gcpAudit))).not.toBe("crowdstrike");
  });
});

describe("splitCrowdstrikeFile", () => {
  it("routes wrapped Okta JSON to the Okta importer, untouched (AC19)", () => {
    const s = splitCrowdstrikeFile(nd(wrapOkta(1)));
    expect([...s.groups.keys()]).toEqual(["okta"]);
    expect(s.groups.get("okta")![0]).toEqual(okta(1));
  });
  it("a plain syslog line goes to the SIEM importer, timed by @timestamp, with #repo kept (AC20)", () => {
    const s = splitCrowdstrikeFile(
      nd({
        "@timestamp": 1731398400000,
        "@rawstring": "<13>Nov 12 08:00:00 fw01 sshd[1]: Failed password",
        "#repo": "3pi_syslog",
      }),
    );
    const row = s.groups.get("siem")![0];
    expect(row["message"]).toContain("Failed password");
    expect(row["@timestamp"]).toBe("2024-11-12T08:00:00.000Z");
    expect(row["LogScale_repo"]).toBe("3pi_syslog");
  });
  it("splits a mixed file row by row, whatever comes first (AC21)", () => {
    for (const text of [
      nd(sensor(1), wrapOkta(1), sensor(2), wrapOkta(2)),
      nd(wrapOkta(1), wrapOkta(2), sensor(1), sensor(2)),
    ]) {
      const s = splitCrowdstrikeFile(text);
      expect(s.falcon).toHaveLength(2);
      expect(s.groups.get("okta")).toHaveLength(2);
    }
  });
  it("one repo carrying two inner formats is split by each row's own format", () => {
    const syslog = { "@timestamp": 1731398400000, "@rawstring": "plain text line", "#repo": "3pi_okta" };
    const s = splitCrowdstrikeFile(nd(syslog, wrapOkta(1)));
    expect(s.groups.get("okta")).toHaveLength(1);
    expect(s.groups.get("siem")).toHaveLength(1);
  });
  it("parsed GKE audit under Vendor (nested and dotted) goes to the GCP audit importer", () => {
    const nested = { "@timestamp": 1731398400000, "#repo": "3pi_gcp", Vendor: gcpAudit };
    const dotted = {
      "@timestamp": 1731398400000,
      "#repo": "3pi_gcp",
      "Vendor.protoPayload.methodName": "io.k8s.core.v1.configmaps.get",
      "Vendor.protoPayload.serviceName": "k8s.io",
      "Vendor.protoPayload.response.spec.volumes[0].projected.sources[1].configMap.name": "kube-root-ca.crt",
      "Vendor.logName": "projects/p/logs/cloudaudit.googleapis.com%2Fdata_access",
      "Vendor.timestamp": "2024-11-12T08:00:00Z",
    };
    const inner = innerRecord(dotted)!;
    expect((inner["protoPayload"] as Record<string, unknown>)["methodName"]).toBe(
      "io.k8s.core.v1.configmaps.get",
    );
    const volumes = (inner["protoPayload"] as { response: { spec: { volumes: unknown } } }).response.spec
      .volumes;
    expect(Array.isArray(volumes)).toBe(true);
    for (const row of [nested, dotted]) {
      const s = splitCrowdstrikeFile(nd(row));
      const kinds = [...s.groups.keys()];
      expect(kinds).toHaveLength(1);
      expect(["siem", "csv", "log", "unknown"]).not.toContain(kinds[0]);
    }
  });
  it("drops prototype-polluting and oversized dotted paths", () => {
    const inner = innerRecord({
      "#repo": "x",
      "Vendor.__proto__.polluted": "1",
      "Vendor.a[100000].b": "2",
      "Vendor.ok": "3",
    })!;
    expect(inner).toEqual({ ok: "3" });
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });
  it("wrapped GCP flow and app logs sharing top-level keys are each routed by their own content", () => {
    const flow = {
      logName: "projects/p/logs/compute.googleapis.com%2Fvpc_flows",
      timestamp: "2024-11-12T08:00:00Z",
      jsonPayload: {
        connection: { src_ip: "10.0.0.1", dest_ip: "203.0.113.5", src_port: 1, dest_port: 443, protocol: 6 },
        bytes_sent: "10",
        start_time: "2024-11-12T08:00:00Z",
        end_time: "2024-11-12T08:00:05Z",
      },
    };
    const app = {
      logName: "projects/p/logs/myapp",
      timestamp: "2024-11-12T08:00:00Z",
      jsonPayload: { message: "hello" },
    };
    const w = (r: unknown) => ({
      "@timestamp": 1731398400000,
      "#repo": "3pi_gcp",
      "@rawstring": JSON.stringify(r),
    });
    const a = splitCrowdstrikeFile(nd(w(flow), w(app)));
    const b = splitCrowdstrikeFile(nd(w(app), w(flow)));
    const sizes = (s: ReturnType<typeof splitCrowdstrikeFile>) =>
      [...s.groups.entries()].map(([k, v]) => `${k}:${v.length}`).sort();
    expect(sizes(a)).toEqual(sizes(b));
    expect(a.groups.size).toBe(2);
  });
  it("keeps each Falcon row's index in the original file", () => {
    const sensorOnly = { "#event_simpleName": "DnsRequest", aid: "a", DomainName: "x.example.com" };
    const s = splitCrowdstrikeFile(nd(wrapOkta(1), sensorOnly, wrapOkta(2), sensorOnly));
    expect(s.falconIndexes).toEqual([1, 3]);
  });
  it("a plain Falcon file reports no wrapped rows", () => {
    const sensorOnly = { "#event_simpleName": "DnsRequest", aid: "a", DomainName: "x.example.com" };
    expect(splitCrowdstrikeFile(nd(sensorOnly, sensorOnly)).wrapped).toBe(0);
  });
});
