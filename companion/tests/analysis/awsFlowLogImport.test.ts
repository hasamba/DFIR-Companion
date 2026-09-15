import { describe, it, expect } from "vitest";
import { parseAwsFlowLog, isAwsFlowLogLine } from "../../src/analysis/awsFlowLogImport.js";

// A real default-format (v2) line, from AWS's own documented record examples, with fake-but-
// plausible values.
const OK_LINE =
  "2 123456789010 eni-1235b8ca 172.31.16.139 203.0.113.10 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK";
const NODATA_LINE = "2 123456789010 eni-1235b8ca - - - - - - - 1431280876 1431280933 - NODATA";
const SKIPDATA_LINE = "2 123456789010 eni-1235b8ca - - - - - - - 1431280876 1431280933 - SKIPDATA";

describe("isAwsFlowLogLine", () => {
  it("recognizes a default-format v2 line", () => {
    expect(isAwsFlowLogLine(OK_LINE)).toBe(true);
  });
  it("rejects a non-flow-log line", () => {
    expect(isAwsFlowLogLine("just some random text with fourteen words in it right here ok yes")).toBe(false);
  });
});

describe("parseAwsFlowLog — a real OK record", () => {
  it("maps to a Low-severity network event with both endpoints and the protocol name", () => {
    const r = parseAwsFlowLog(OK_LINE);
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Low");
    expect(e.srcIp).toBe("172.31.16.139");
    expect(e.dstIp).toBe("203.0.113.10");
    expect(e.canonical?.network?.protocol).toBe("tcp");
    expect(e.canonical?.cloud?.accountId).toBe("123456789010");
    expect(e.sources).toEqual(["AWS VPC Flow Logs"]);
  });

  it("tags only the public endpoint as an IOC, never the private one", () => {
    const r = parseAwsFlowLog(OK_LINE);
    const ips = r.iocs.filter((i) => i.type === "ip").map((i) => i.value);
    expect(ips).toContain("203.0.113.10");
    expect(ips).not.toContain("172.31.16.139");
  });

  it("grades REJECT the same as ACCEPT — never auto-suspicious on its own", () => {
    const reject = OK_LINE.replace(" ACCEPT ", " REJECT ");
    const r = parseAwsFlowLog(reject);
    expect(r.events[0].severity).toBe("Low");
  });
});

describe("parseAwsFlowLog — NODATA vs SKIPDATA vs malformed, tracked separately", () => {
  it("counts NODATA and SKIPDATA separately, produces zero events for either", () => {
    const r = parseAwsFlowLog([NODATA_LINE, SKIPDATA_LINE].join("\n"));
    expect(r.events).toHaveLength(0);
    expect(r.nodata).toBe(1);
    expect(r.skipdata).toBe(1);
    expect(r.malformed).toBe(0);
  });

  it("never reads NODATA as zero traffic — it's absence of an event, not a negative-traffic event", () => {
    const r = parseAwsFlowLog(NODATA_LINE);
    expect(r.events).toHaveLength(0);
    expect(r.total).toBe(1);
  });

  it("counts a malformed line (wrong field count) separately from NODATA/SKIPDATA", () => {
    const r = parseAwsFlowLog("2 123456789010 eni-x only-a-few-fields");
    expect(r.malformed).toBe(1);
    expect(r.nodata).toBe(0);
    expect(r.skipdata).toBe(0);
  });

  it("rejects end < start as malformed", () => {
    const bad = OK_LINE.replace("1418530010 1418530070", "1418530070 1418530010");
    const r = parseAwsFlowLog(bad);
    expect(r.malformed).toBe(1);
    expect(r.events).toHaveLength(0);
  });

  it("rejects a non-numeric port/protocol/byte field as malformed, not coerced", () => {
    const bad = OK_LINE.replace(" 6 20 ", " notanumber 20 ");
    const r = parseAwsFlowLog(bad);
    expect(r.malformed).toBe(1);
  });

  it("rejects a non-v2 version", () => {
    const bad = OK_LINE.replace(/^2 /, "5 ");
    const r = parseAwsFlowLog(bad);
    expect(r.malformed).toBe(1);
  });
});

describe("parseAwsFlowLog — aggregation", () => {
  it("collapses repeated identical 5-tuple flows into one counted row (no time in aggKey)", () => {
    const later = OK_LINE.replace("1418530010 1418530070", "1418539010 1418539070");
    const r = parseAwsFlowLog([OK_LINE, later].join("\n"));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });

  it("keeps two different destination ports as two distinct rows", () => {
    const other = OK_LINE.replace(" 22 6 ", " 443 6 ");
    const r = parseAwsFlowLog([OK_LINE, other].join("\n"));
    expect(r.events).toHaveLength(2);
  });
});
