import { describe, it, expect } from "vitest";
import { parseGcpFlowLog, isGcpFlowLogEntry } from "../../src/analysis/gcpFlowLogImport.js";

// Field names and value shapes from Google's own about-flow-logs-records / access-flow-logs pages
// (fetched 2026-09-18). Cloud Logging exports int64 fields as JSON strings, so the fixtures mix
// numbers and digit strings on purpose.
function entry(payload: Record<string, unknown>, overrides: Record<string, unknown> = {}) {
  return {
    insertId: "abc123",
    logName: "projects/my-proj/logs/compute.googleapis.com%2Fvpc_flows",
    resource: {
      type: "gce_subnetwork",
      labels: { project_id: "my-proj", subnetwork_name: "default", location: "us-central1" },
    },
    timestamp: "2024-05-01T10:00:05.000Z",
    receiveTimestamp: "2024-05-01T10:00:09.000Z",
    jsonPayload: {
      connection: {
        src_ip: "10.128.0.2",
        dest_ip: "203.0.113.9",
        src_port: 51234,
        dest_port: 443,
        protocol: 6,
      },
      reporter: "SRC",
      bytes_sent: "8420",
      packets_sent: "12",
      start_time: "2024-05-01T09:59:58.123456Z",
      end_time: "2024-05-01T10:00:03.000000Z",
      src_instance: { project_id: "my-proj", region: "us-central1", zone: "us-central1-a", vm_name: "web-1" },
      src_vpc: { project_id: "my-proj", vpc_name: "prod", subnetwork_name: "default" },
      dest_location: { asn: 64496, country: "usa", continent: "America" },
      ...payload,
    },
    ...overrides,
  };
}
const arr = (entries: unknown[]) => JSON.stringify(entries);

describe("isGcpFlowLogEntry", () => {
  it("claims a compute.googleapis.com vpc_flows entry", () => {
    expect(isGcpFlowLogEntry(entry({}))).toBe(true);
  });
  it("claims a networkmanagement.googleapis.com vpc_flows entry", () => {
    const e = entry(
      {},
      {
        logName: "projects/my-proj/logs/networkmanagement.googleapis.com%2Fvpc_flows",
        resource: { type: "vpc_flow_logs_config", labels: { project_id: "my-proj" } },
      },
    );
    expect(isGcpFlowLogEntry(e)).toBe(true);
  });
  it("does not claim a firewall-rules entry that shares gce_subnetwork and a connection block — logName is the wrapper", () => {
    const fw = entry(
      {},
      {
        logName: "projects/my-proj/logs/compute.googleapis.com%2Ffirewall",
        resource: { type: "gce_subnetwork" },
      },
    );
    expect(isGcpFlowLogEntry(fw)).toBe(false);
    expect(parseGcpFlowLog(arr([fw])).nonFlow).toBe(1);
  });
  it("a vpc_flows entry with no connection block is malformed, not nonFlow", () => {
    const r = parseGcpFlowLog(arr([entry({ connection: undefined })]));
    expect(r.malformed).toBe(1);
    expect(r.nonFlow).toBe(0);
  });
  it("does not claim a GCP audit-log entry (protoPayload) or a bare payload without the wrapper", () => {
    expect(
      isGcpFlowLogEntry({
        logName: "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
        protoPayload: {},
      }),
    ).toBe(false);
    expect(isGcpFlowLogEntry(entry({}).jsonPayload as Record<string, unknown>)).toBe(false);
  });
});

describe("parseGcpFlowLog — a real SRC-reported entry", () => {
  it("maps to a Low network/flow event with the emitting project as the account", () => {
    const r = parseGcpFlowLog(arr([entry({})]));
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Low");
    expect(e.timestamp).toBe("2024-05-01T09:59:58.123Z"); // start_time, first observed packet
    expect(e.srcIp).toBe("10.128.0.2");
    expect(e.dstIp).toBe("203.0.113.9");
    expect(e.port).toBe(443);
    expect(e.canonical?.event).toEqual({ category: "network", type: "flow", action: "observed" });
    expect(e.canonical?.network?.protocol).toBe("tcp");
    expect(e.canonical?.network?.source?.provenance).toBe("edge-observed");
    expect(e.canonical?.cloud).toEqual({
      provider: "gcp",
      accountId: "my-proj",
      region: "us-central1",
      resource: "web-1",
    });
    expect(e.sources).toEqual(["GCP VPC Flow Logs"]);
    expect(e.canonical?.evidence.rawRecords[0]).toEqual({
      source: "gcp-vpc-flow-log",
      locator: "entry:0/insertId:abc123",
    });
  });

  it("the row states reporter, int64-as-string counters as payload bytes, both times, and Google's own annotation", () => {
    const d = parseGcpFlowLog(arr([entry({})])).events[0].description;
    expect(d).toContain("GCP VPC flow (reported by SRC)");
    expect(d).toContain("10.128.0.2:51234 -> 203.0.113.9:443 (tcp) observed");
    expect(d).toContain("12 packet(s), 8420 payload byte(s)");
    expect(d).toContain("2024-05-01T09:59:58.123Z–2024-05-01T10:00:03.000Z");
    expect(d).toContain("src instance web-1 (my-proj/us-central1-a, Google's annotation)");
    expect(d).toContain("dest: no instance annotation");
    expect(d).toContain("src vpc prod");
  });

  it("a DEST-reported entry takes its region/resource from the dest side, account still from the emitting project", () => {
    const e = parseGcpFlowLog(
      arr([
        entry({
          reporter: "DEST",
          src_instance: undefined,
          dest_instance: {
            project_id: "other-proj",
            region: "europe-west1",
            zone: "europe-west1-b",
            vm_name: "db-1",
          },
        }),
      ]),
    ).events[0];
    expect(e.canonical?.cloud).toEqual({
      provider: "gcp",
      accountId: "my-proj",
      region: "europe-west1",
      resource: "db-1",
    });
    expect(e.description).toContain("src: no instance annotation");
    expect(e.description).toContain("dest instance db-1 (other-proj/europe-west1-b, Google's annotation)");
  });

  it("falls back to the logName project when resource.labels has none", () => {
    const e = parseGcpFlowLog(arr([entry({}, { resource: { type: "gce_subnetwork" } })])).events[0];
    expect(e.canonical?.cloud?.accountId).toBe("my-proj");
  });

  it("a DROPPED entry is action dropped, Low, names the reason and prints the dropped counters only", () => {
    const e = parseGcpFlowLog(
      arr([
        entry({
          disposition: "DROPPED",
          drop_reason: "FIREWALL_DENY",
          bytes_sent: undefined,
          packets_sent: undefined,
          bytes_dropped: "60",
          packets_dropped: 1,
        }),
      ]),
    ).events[0];
    expect(e.canonical?.event.action).toBe("dropped");
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("dropped: FIREWALL_DENY");
    expect(e.description).toContain("1 packet(s) dropped, 60 payload byte(s) dropped");
    expect(e.description).not.toContain("payload byte(s),");
  });

  it("tags only the public IPv4 endpoint as an IOC; a v6 endpoint makes a row only", () => {
    const r = parseGcpFlowLog(
      arr([
        entry({}),
        entry({
          connection: {
            src_ip: "10.128.0.2",
            dest_ip: "2001:db8::9",
            src_port: 1,
            dest_port: 443,
            protocol: 6,
          },
        }),
      ]),
    );
    expect(r.events).toHaveLength(2);
    expect(r.iocs.map((i) => i.value)).toEqual(["203.0.113.9"]);
  });

  it("a portless entry (ICMP, ports absent) omits the port fields and prints bare addresses", () => {
    const e = parseGcpFlowLog(
      arr([entry({ connection: { src_ip: "10.128.0.2", dest_ip: "203.0.113.9", protocol: 1 } })]),
    ).events[0];
    expect(e.port).toBeUndefined();
    expect(e.canonical?.network?.source?.port).toBeUndefined();
    expect(e.description).toContain("10.128.0.2 -> 203.0.113.9 (icmp)");
  });

  it("a GKE pod annotation is printed when present", () => {
    const e = parseGcpFlowLog(
      arr([
        entry({
          src_gke_details: {
            cluster: { cluster_name: "c1", cluster_location: "us-central1" },
            pod: { pod_name: "p-1", pod_namespace: "ns" },
          },
        }),
      ]),
    ).events[0];
    expect(e.description).toContain("src gke pod ns/p-1 (cluster c1)");
  });
});

describe("parseGcpFlowLog — refused, malformed and counted", () => {
  it("a non-flow LogEntry in the same export is counted as nonFlow, never malformed", () => {
    const audit = {
      logName: "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
      protoPayload: { methodName: "x" },
    };
    const r = parseGcpFlowLog(arr([entry({}), audit]));
    expect(r.events).toHaveLength(1);
    expect(r.nonFlow).toBe(1);
    expect(r.malformed).toBe(0);
  });
  it("an unknown reporter is malformed", () => {
    expect(parseGcpFlowLog(arr([entry({ reporter: "BOTH" })])).malformed).toBe(1);
  });
  it("a missing or unparseable start_time is malformed", () => {
    expect(parseGcpFlowLog(arr([entry({ start_time: "yesterday" })])).malformed).toBe(1);
    expect(parseGcpFlowLog(arr([entry({ start_time: undefined })])).malformed).toBe(1);
  });
  it("a non-numeric port/protocol/counter is malformed, not coerced", () => {
    expect(
      parseGcpFlowLog(
        arr([
          entry({
            connection: { src_ip: "10.1.1.1", dest_ip: "10.1.1.2", src_port: "x", dest_port: 1, protocol: 6 },
          }),
        ]),
      ).malformed,
    ).toBe(1);
    expect(parseGcpFlowLog(arr([entry({ bytes_sent: "lots" })])).malformed).toBe(1);
  });
  it("a bad IP is malformed", () => {
    expect(
      parseGcpFlowLog(
        arr([
          entry({
            connection: { src_ip: "nope", dest_ip: "10.1.1.2", src_port: 1, dest_port: 1, protocol: 6 },
          }),
        ]),
      ).malformed,
    ).toBe(1);
  });
  it("counts entries with no reporter-side instance annotation", () => {
    const r = parseGcpFlowLog(arr([entry({ src_instance: undefined }), entry({})]));
    expect(r.noReporterInstance).toBe(1);
  });
  it("counts DROPPED records separately", () => {
    const r = parseGcpFlowLog(
      arr([entry({ disposition: "DROPPED", drop_reason: "NO_MATCHING_ROUTE" }), entry({})]),
    );
    expect(r.droppedRecords).toBe(1);
  });
});

describe("parseGcpFlowLog — code-review regressions (#1294)", () => {
  it("a port above 65535 is malformed and never aborts the upload", () => {
    const r = parseGcpFlowLog(
      arr([
        entry({
          connection: { src_ip: "10.1.1.1", dest_ip: "10.1.1.2", src_port: 70000, dest_port: 1, protocol: 6 },
        }),
        entry({}),
      ]),
    );
    expect(r.malformed).toBe(1);
    expect(r.events).toHaveLength(1);
  });
  it("two DROPPED entries with different reasons stay two rows", () => {
    const r = parseGcpFlowLog(
      arr([
        entry({ disposition: "DROPPED", drop_reason: "FIREWALL_DENY" }),
        entry({ disposition: "DROPPED", drop_reason: "NO_MATCHING_ROUTE" }, { insertId: "b" }),
      ]),
    );
    expect(r.events).toHaveLength(2);
  });
  it("multicast/broadcast peers make rows but never IOCs", () => {
    const r = parseGcpFlowLog(
      arr([
        entry({
          connection: {
            src_ip: "10.1.1.1",
            dest_ip: "239.255.255.250",
            src_port: 1,
            dest_port: 1900,
            protocol: 17,
          },
        }),
      ]),
    );
    expect(r.events).toHaveLength(1);
    expect(r.iocs).toHaveLength(0);
  });
  it("a counter above 2^53 (number or string) is malformed, never rounded", () => {
    expect(parseGcpFlowLog(arr([entry({ bytes_sent: "18446744073709551615" })])).malformed).toBe(1);
    expect(parseGcpFlowLog(arr([entry({ bytes_sent: 1e21 })])).malformed).toBe(1);
  });
  it("a start_time before 2001 is malformed; an end_time before start_time is dropped from the row", () => {
    expect(parseGcpFlowLog(arr([entry({ start_time: "1969-07-20T20:17:40Z" })])).malformed).toBe(1);
    const d = parseGcpFlowLog(arr([entry({ end_time: "2024-04-30T00:00:00Z" })])).events[0].description;
    expect(d).toContain("2024-05-01T09:59:58.123Z]");
    expect(d).not.toContain("–");
  });
  it("dropped packets carry the same qualifier as dropped bytes", () => {
    const d = parseGcpFlowLog(
      arr([
        entry({
          disposition: "DROPPED",
          drop_reason: "FIREWALL_DENY",
          packets_dropped: 5,
          bytes_dropped: 100,
        }),
      ]),
    ).events[0].description;
    expect(d).toContain("5 packet(s) dropped, 100 payload byte(s) dropped");
  });
  it("a fully %2F-encoded logName still yields the project when resource.labels has none", () => {
    const e = parseGcpFlowLog(
      arr([
        entry(
          {},
          {
            logName: "projects%2Fmy-proj%2Flogs%2Fcompute.googleapis.com%2Fvpc_flows",
            resource: { type: "gce_subnetwork" },
          },
        ),
      ]),
    ).events[0];
    expect(e.canonical?.cloud?.accountId).toBe("my-proj");
  });
  it("a 500-char drop reason and IPv6 endpoints never evict the counters, times or the per-side annotation brackets", () => {
    const d = parseGcpFlowLog(
      arr([
        entry({
          connection: {
            src_ip: "2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001",
            dest_ip: "2001:db8:aaaa:bbbb:cccc:dddd:eeee:0002",
            src_port: 1,
            dest_port: 2,
            protocol: 6,
          },
          disposition: "DROPPED",
          drop_reason: "R".repeat(500),
          bytes_sent: undefined,
          packets_sent: undefined,
          packets_dropped: 7,
          bytes_dropped: 700,
        }),
      ]),
    ).events[0].description;
    expect(d.length).toBeLessThanOrEqual(600);
    expect(d).toContain("7 packet(s) dropped, 700 payload byte(s) dropped");
    expect(d).toContain("2024-05-01T09:59:58.123Z");
    expect(d).toContain("[src instance web-1");
    expect(d).toContain("[dest: no instance annotation]");
  });
});

describe("parseGcpFlowLog — aggregation keys and input shapes", () => {
  it("two entries for the same 5-tuple with different start_time never merge — each is its own interval", () => {
    const r = parseGcpFlowLog(
      arr([entry({}), entry({ start_time: "2024-05-01T10:04:00Z" }, { insertId: "def" })]),
    );
    expect(r.events).toHaveLength(2);
  });
  it("an exact duplicate entry (same start_time) merges by count", () => {
    const r = parseGcpFlowLog(arr([entry({}), entry({}, { insertId: "dup" })]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });
  it("the same tuple in two different VPCs stays apart", () => {
    const r = parseGcpFlowLog(
      arr([
        entry({}),
        entry({ src_vpc: { project_id: "my-proj", vpc_name: "staging" } }, { insertId: "v2" }),
      ]),
    );
    expect(r.events).toHaveLength(2);
  });
  it("accepts NDJSON as well as an array", () => {
    const r = parseGcpFlowLog(
      JSON.stringify(entry({})) + "\n" + JSON.stringify(entry({ start_time: "2024-05-01T11:00:00Z" })),
    );
    expect(r.events).toHaveLength(2);
    expect(r.total).toBe(2);
    expect(r.format).toBe("gcp-vpc-flow-log");
  });
});
