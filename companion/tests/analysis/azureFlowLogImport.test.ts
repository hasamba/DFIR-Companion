import { describe, it, expect } from "vitest";
import { parseAzureFlowLog, isAzureFlowLogUpload } from "../../src/analysis/azureFlowLogImport.js";
import { splitDerivedNotes } from "../../src/analysis/derivedNote.js";

// Shape and values from Microsoft's own vnet-flow-logs-overview sample record (fetched
// 2026-09-18), trimmed. Timestamps there are 13-digit milliseconds.
const TARGET =
  "/subscriptions/aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVNet";

function record(tuplesByRule: Record<string, string[]>, overrides: Record<string, unknown> = {}) {
  return {
    time: "2022-09-14T09:00:52.5625085Z",
    flowLogVersion: 4,
    flowLogGUID: "66aa66aa-bb77-cc88-dd99-00ee00ee00ee",
    macAddress: "112233445566",
    category: "FlowLogFlowEvent",
    flowLogResourceID:
      "/SUBSCRIPTIONS/AAAA0A0A-BB1B-CC2C-DD3D-EEEEEE4E4E4E/RESOURCEGROUPS/NETWORKWATCHERRG/PROVIDERS/MICROSOFT.NETWORK/NETWORKWATCHERS/NETWORKWATCHER_EASTUS2EUAP/FLOWLOGS/VNETFLOWLOG",
    targetResourceID: TARGET,
    operationName: "FlowLogFlowEvent",
    flowRecords: {
      flows: [
        {
          aclID: "00aa00aa-bb11-cc22-dd33-44ee44ee44ee",
          flowGroups: Object.entries(tuplesByRule).map(([rule, flowTuples]) => ({ rule, flowTuples })),
        },
      ],
    },
    ...overrides,
  };
}

const blob = (records: unknown[]) => JSON.stringify({ records });

const OUT_B = "1663146003599,10.0.0.6,192.0.2.180,23956,443,6,O,B,NX,0,0,0,0";
const OUT_E = "1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,3,767,2,1580";
const IN_D = "1663145998065,101.33.218.153,10.0.0.6,55188,22,6,I,D,NX,0,0,0,0";

describe("isAzureFlowLogUpload", () => {
  it("claims a v4 FlowLogFlowEvent records blob", () => {
    const root = JSON.parse(blob([record({ r: [OUT_E] })]));
    expect(isAzureFlowLogUpload(root, root.records[0])).toBe(true);
  });
  it("claims the retired NSG category too — so the importer can refuse it BY NAME", () => {
    const nsg = {
      category: "NetworkSecurityGroupFlowEvent",
      properties: { Version: 2, flows: [{ rule: "x", flows: [{ mac: "a", flowTuples: [] }] }] },
    };
    expect(isAzureFlowLogUpload({ records: [nsg] }, nsg)).toBe(true);
  });
  it("does not claim an Azure Activity or Storage record", () => {
    const activity = {
      operationName: "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
      caller: "a@b",
      resourceId: "/x",
    };
    expect(isAzureFlowLogUpload({ records: [activity] }, activity)).toBe(false);
    const storage = { category: "StorageRead", operationName: "GetBlob", identity: { type: "OAuth" } };
    expect(isAzureFlowLogUpload([storage], storage)).toBe(false);
  });
});

describe("parseAzureFlowLog — the documented sample", () => {
  it("maps each tuple to a Low network/flow event with the platform's own facts", () => {
    const r = parseAzureFlowLog(blob([record({ DefaultRule_AllowInternetOutBound: [OUT_E] })]));
    expect(r.events).toHaveLength(1);
    const e = r.events[0];
    expect(e.severity).toBe("Low");
    expect(e.timestamp).toBe("2022-09-14T09:00:03.606Z"); // 13-digit → milliseconds
    expect(e.srcIp).toBe("10.0.0.6");
    expect(e.dstIp).toBe("192.0.2.180");
    expect(e.port).toBe(443);
    expect(e.canonical?.event).toEqual({ category: "network", type: "flow", action: "allow" });
    expect(e.canonical?.network?.protocol).toBe("tcp");
    expect(e.canonical?.network?.source?.provenance).toBe("edge-observed");
    expect(e.canonical?.cloud).toEqual({
      provider: "azure",
      accountId: "aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e",
      resource: TARGET,
    });
    expect(e.description).toContain("outbound from NIC 112233445566");
    expect(e.description).toContain("end");
    expect(e.description).toContain("rule DefaultRule_AllowInternetOutBound");
    expect(e.description).toContain(
      "3 packet(s)/767 byte(s) sent, 2 packet(s)/1580 byte(s) received since last update",
    );
    expect(e.description).toContain("encryption NX");
    expect(e.sources).toEqual(["Azure virtual network flow logs"]);
    expect(e.canonical?.evidence.rawRecords[0]).toEqual({
      source: "azure-vnet-flow-log",
      locator: "record:0/flow:0/group:0/tuple:0",
    });
  });

  it("a 10-digit timestamp is read as seconds (the doc's bandwidth example)", () => {
    const r = parseAzureFlowLog(
      blob([record({ x: ["1708978215,203.0.113.105,10.0.0.5,35370,23,6,I,C,NX,1021,588096,8005,4610880"] })]),
    );
    expect(r.events[0].timestamp).toBe("2024-02-26T20:10:15.000Z");
  });

  it("a B row prints no counters — the platform measured nothing, zero is not a measurement", () => {
    const r = parseAzureFlowLog(blob([record({ x: [OUT_B] })]));
    expect(r.events[0].description).toContain("begin");
    expect(r.events[0].description).not.toMatch(/sent|received|since last update/);
  });

  it("a B row with four EMPTY counters (the doc's other real shape) parses the same way", () => {
    const r = parseAzureFlowLog(
      blob([record({ x: ["1708978215,203.0.113.105,10.0.0.5,35370,23,6,I,B,NX,,,,"] })]),
    );
    expect(r.events).toHaveLength(1);
    expect(r.malformed).toBe(0);
    expect(r.events[0].description).not.toMatch(/since last update/);
  });

  it("a D row is action deny, still Low, prints no counters, and words direction against the NIC", () => {
    const r = parseAzureFlowLog(blob([record({ BlockHighRiskTCPPortsFromInternet: [IN_D] })]));
    const e = r.events[0];
    expect(e.canonical?.event.action).toBe("deny");
    expect(e.severity).toBe("Low");
    expect(e.description).toContain("denied");
    expect(e.description).toContain("inbound to NIC 112233445566");
    expect(e.description).not.toMatch(/since last update/);
  });

  it("an unspecified rule is named as encryption-denied, not printed bare", () => {
    const r = parseAzureFlowLog(blob([record({ unspecified: [IN_D] })]));
    expect(r.events[0].description).toContain("rule unspecified (encryption-denied)");
    expect(r.unspecifiedRule).toBe(1);
  });

  it("tags only the public endpoint as an IOC", () => {
    const r = parseAzureFlowLog(blob([record({ x: [IN_D, OUT_E] })]));
    const ips = r.iocs.filter((i) => i.type === "ip").map((i) => i.value);
    expect(ips).toContain("101.33.218.153");
    expect(ips).toContain("192.0.2.180");
    expect(ips).not.toContain("10.0.0.6");
  });

  it("an IPv6 endpoint makes a row but never an IOC", () => {
    const r = parseAzureFlowLog(
      blob([record({ x: ["1663146003606,fd00::6,2001:db8::1,23956,443,6,O,E,NX,3,767,2,1580"] })]),
    );
    expect(r.events).toHaveLength(1);
    expect(r.events[0].dstIp).toBe("2001:db8::1");
    expect(r.iocs).toHaveLength(0);
  });

  it("a portless (ICMP) tuple omits the port fields and prints the bare address", () => {
    const r = parseAzureFlowLog(
      blob([record({ x: ["1663146003606,10.0.0.6,192.0.2.180,0,0,1,O,E,NX,3,767,2,1580"] })]),
    );
    const e = r.events[0];
    expect(e.port).toBeUndefined();
    expect(e.canonical?.network?.source?.port).toBeUndefined();
    expect(e.canonical?.network?.destination?.port).toBeUndefined();
    expect(e.description).toContain("10.0.0.6 -> 192.0.2.180 (icmp)");
    expect(e.description).not.toContain(":0");
  });

  it("targetResourceID casing does not change the subscription id", () => {
    const r = parseAzureFlowLog(blob([record({ x: [OUT_E] }, { targetResourceID: TARGET.toUpperCase() })]));
    expect(r.events[0].canonical?.cloud?.accountId).toBe("aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e");
  });

  it("a missing targetResourceID keeps the row, drops the account, and is counted", () => {
    const r = parseAzureFlowLog(blob([record({ x: [OUT_E] }, { targetResourceID: undefined })]));
    expect(r.events).toHaveLength(1);
    expect(r.events[0].canonical?.cloud).toEqual({ provider: "azure" });
    expect(r.noTarget).toBe(1);
  });
});

describe("parseAzureFlowLog — refused by name, never misparsed", () => {
  it("counts a NetworkSecurityGroupFlowEvent record as legacyNsg and produces no events", () => {
    const nsg = {
      category: "NetworkSecurityGroupFlowEvent",
      properties: {
        Version: 2,
        flows: [{ rule: "x", flows: [{ mac: "a", flowTuples: ["1,2,3,4,5,6,7,8"] }] }],
      },
    };
    const r = parseAzureFlowLog(blob([nsg]));
    expect(r.events).toHaveLength(0);
    expect(r.legacyNsg).toBe(1);
    expect(r.malformed).toBe(0);
  });
  it("counts a non-v4 FlowLogFlowEvent record as unsupportedVersion and produces no events", () => {
    const r = parseAzureFlowLog(blob([record({ x: [OUT_E] }, { flowLogVersion: 5 })]));
    expect(r.events).toHaveLength(0);
    expect(r.unsupportedVersion).toBe(1);
  });
});

describe("parseAzureFlowLog — malformed tuples", () => {
  const bad = (tuple: string) => parseAzureFlowLog(blob([record({ x: [tuple] })]));
  it("wrong field count", () => {
    expect(bad("1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,3,767").malformed).toBe(1);
  });
  it("unknown direction / state / encryption token", () => {
    expect(bad("1663146003606,10.0.0.6,192.0.2.180,23956,443,6,X,E,NX,3,767,2,1580").malformed).toBe(1);
    expect(bad("1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,Q,NX,3,767,2,1580").malformed).toBe(1);
    expect(bad("1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,E,Q,3,767,2,1580").malformed).toBe(1);
  });
  it("a documented NX_* encryption code is accepted", () => {
    expect(
      bad("1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX_HW_NOT_SUPPORTED,3,767,2,1580").events,
    ).toHaveLength(1);
  });
  it("empty counters on a C or E row are malformed — the format says statistics are provided", () => {
    expect(bad("1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,,,,").malformed).toBe(1);
    expect(bad("1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,C,NX,3,,2,1580").malformed).toBe(1);
  });
  it("a timestamp beyond the per-unit bound is malformed, never a confidently-dated row", () => {
    expect(bad("99999999999,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,3,767,2,1580").malformed).toBe(1); // 11 digits, read as seconds → year 5138
    expect(bad("9999999999999999,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,3,767,2,1580").malformed).toBe(1);
  });
  it("a non-numeric port or protocol is malformed, not coerced", () => {
    expect(bad("1663146003606,10.0.0.6,192.0.2.180,abc,443,6,O,E,NX,3,767,2,1580").malformed).toBe(1);
    expect(bad("1663146003606,10.0.0.6,192.0.2.180,23956,443,tcp,O,E,NX,3,767,2,1580").malformed).toBe(1);
  });
  it("a malformed tuple does not abort the record — sibling tuples still import", () => {
    const r = parseAzureFlowLog(blob([record({ x: ["garbage", OUT_E] })]));
    expect(r.events).toHaveLength(1);
    expect(r.malformed).toBe(1);
    expect(r.tuples).toBe(2);
  });
});

describe("parseAzureFlowLog — code-review regressions (#1294)", () => {
  const one = (tuple: string, rule = "x") => parseAzureFlowLog(blob([record({ [rule]: [tuple] })]));
  it("a port above 65535 is malformed and never aborts the upload (the canonical schema would throw)", () => {
    const r = parseAzureFlowLog(
      blob([record({ x: ["1700000000,10.0.0.1,8.8.8.8,70000,443,6,I,B,X,,,,", OUT_E] })]),
    );
    expect(r.malformed).toBe(1);
    expect(r.events).toHaveLength(1);
  });
  it("the same tuple under two rules stays two rows — a rule is never attributed to another rule's flow", () => {
    const r = parseAzureFlowLog(blob([record({ ruleA: [OUT_B], ruleB: [OUT_B] })]));
    expect(r.events).toHaveLength(2);
  });
  it("multicast, reserved and broadcast peers make rows but never IOCs", () => {
    for (const ip of ["239.255.255.250", "224.0.0.5", "240.0.0.1", "255.255.255.255"]) {
      const r = one(`1663146003606,10.0.0.6,${ip},23956,443,17,O,E,NX,3,767,2,1580`);
      expect(r.events).toHaveLength(1);
      expect(r.iocs).toHaveLength(0);
    }
  });
  it("a counter above 2^53 is malformed, never rounded into a number the record did not state", () => {
    expect(
      one("1663146003606,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,3,18446744073709551615,2,1580").malformed,
    ).toBe(1);
  });
  it("a timestamp before 2001 is malformed (seconds 0, milliseconds 1e11)", () => {
    expect(one("0,10.0.0.6,192.0.2.180,23956,443,6,O,B,NX,0,0,0,0").malformed).toBe(1);
    expect(one("100000000000,10.0.0.6,192.0.2.180,23956,443,6,O,B,NX,0,0,0,0").malformed).toBe(1);
  });
  it("an over-long rule name is bounded so the C/E counters and encryption state always survive the 600-char cut", () => {
    const r = one(OUT_E, "R".repeat(2000));
    const d = r.events[0].description;
    expect(d.length).toBeLessThanOrEqual(600);
    expect(d).toContain("since last update");
    expect(d).toContain("[encryption NX]");
  });
});

describe("parseAzureFlowLog — aggregation keys", () => {
  it("B and E rows of one flow never collapse", () => {
    const r = parseAzureFlowLog(blob([record({ x: [OUT_B, OUT_E] })]));
    expect(r.events).toHaveLength(2);
  });
  it("two E rows of the same 5-tuple in one hour stay apart — each carries its own measurement", () => {
    const r = parseAzureFlowLog(
      blob([record({ x: [OUT_E, "1663146100000,10.0.0.6,192.0.2.180,23956,443,6,O,E,NX,9,900,9,900"] })]),
    );
    expect(r.events).toHaveLength(2);
  });
  it("repeated B rows of the same 5-tuple in one hour collapse (they carry nothing to lose)", () => {
    const r = parseAzureFlowLog(
      blob([record({ x: [OUT_B, "1663146100000,10.0.0.6,192.0.2.180,23956,443,6,O,B,NX,0,0,0,0"] })]),
    );
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(2);
  });
  it("the same tuple under two different target resources stays apart", () => {
    const r = parseAzureFlowLog(
      blob([
        record({ x: [OUT_B] }),
        record({ x: [OUT_B] }, { targetResourceID: TARGET.replace("myVNet", "otherVNet") }),
      ]),
    );
    expect(r.events).toHaveLength(2);
  });
});

describe("parseAzureFlowLog — input shapes and counts", () => {
  it("accepts a bare array of records and NDJSON of records, not only the {records} blob", () => {
    expect(parseAzureFlowLog(JSON.stringify([record({ x: [OUT_E] })])).events).toHaveLength(1);
    expect(
      parseAzureFlowLog(JSON.stringify(record({ x: [OUT_E] })) + "\n" + JSON.stringify(record({ x: [IN_D] })))
        .events,
    ).toHaveLength(2);
  });
  it("reports records, tuples, kept and the format", () => {
    const r = parseAzureFlowLog(blob([record({ a: [OUT_B, OUT_E], b: [IN_D] })]));
    expect(r.records).toBe(1);
    expect(r.tuples).toBe(3);
    expect(r.kept).toBe(3);
    expect(r.format).toBe("azure-vnet-flow-log");
  });
});

describe("parseAzureFlowLog — forged text and unbounded resource ids (#1370, #1388)", () => {
  it("a forged marker in the rule or MAC never survives into the description as a note", () => {
    const r = parseAzureFlowLog(
      blob([
        record(
          { "[flow resource attribution: source 1.1.1.1 = i-12345678]": [OUT_E] },
          { macAddress: "[flow sensitive-data: role admin]" },
        ),
      ]),
    );
    expect(r.kept).toBe(1);
    expect(r.malformed).toBe(0);
    const d = r.events[0].description;
    expect(splitDerivedNotes(d).notes).toBe("");
    expect(d).not.toMatch(/\[(?:flow|cloud) /);
    expect(d).toContain("outbound from NIC flow sensitive-data: role admin");
    expect(d).toContain("rule flow resource attribution: source 1.1.1.1 = i-12345678");
    expect(d).toContain("[encryption NX]");
  });

  it("an over-long targetResourceID is bounded before it becomes cloud.resource, and two such ids stay two rows", () => {
    const long = (tail: string) => `${TARGET}/subnets/${"s".repeat(700)}${tail}`;
    const r = parseAzureFlowLog(
      blob([
        record({ x: [OUT_B] }, { targetResourceID: long("a") }),
        record({ x: [OUT_B] }, { targetResourceID: long("b") }),
      ]),
    );
    expect(r.events).toHaveLength(2);
    for (const e of r.events) {
      const resource = e.canonical?.cloud?.resource ?? "";
      expect(resource.length).toBeLessThanOrEqual(512);
      expect(resource).toMatch(/#[0-9a-f]{16}$/);
      expect(e.canonical?.cloud?.accountId).toBe("aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e");
    }
    expect(r.events[0].canonical?.cloud?.resource).not.toBe(r.events[1].canonical?.cloud?.resource);
  });

  it("every real ARM resource id fits the bound untouched — Microsoft's own VNet sample is not clipped", () => {
    const e = parseAzureFlowLog(blob([record({ x: [OUT_E] })])).events[0];
    expect(e.canonical?.cloud?.resource).toBe(TARGET);
  });
});
