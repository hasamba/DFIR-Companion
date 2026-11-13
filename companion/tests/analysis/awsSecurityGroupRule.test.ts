// #2605 — AuthorizeSecurityGroupIngress states its protocol, ports and source on its OWN row, for
// both request forms CloudTrail records: the `ipPermissions.items` form and the legacy top-level
// form (`ipProtocol` / `fromPort` / `toPort` / `cidrIp`, with an empty `ipPermissions: {}`). Any
// address is decided on a prefix length of 0, not on the literal "0.0.0.0/0". Record shape copied
// from the Stratus Red Team sample (values replaced with synthetic ones).
import { describe, expect, it } from "vitest";
import {
  ingressPermissions,
  isAnyAddress,
  securityGroupRuleReading,
} from "../../src/analysis/awsSecurityGroupRule.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";

const SG = "sg-0aaa111bbb222ccc3";
const legacy = (cidrIp = "203.0.113.254/0") => ({
  cidrIp,
  fromPort: 22,
  groupId: SG,
  ipPermissions: {},
  ipProtocol: "tcp",
  toPort: 22,
});
const itemsForm = (ranges: string[], v6: string[] = []) => ({
  groupId: SG,
  ipPermissions: {
    items: [
      {
        ipProtocol: "tcp",
        fromPort: 3389,
        toPort: 3390,
        ipRanges: { items: ranges.map((cidrIp) => ({ cidrIp })) },
        ipv6Ranges: { items: v6.map((cidrIpv6) => ({ cidrIpv6 })) },
      },
    ],
  },
});

describe("isAnyAddress (#2605)", () => {
  it("is a prefix length of 0, IPv4 and IPv6", () => {
    for (const v of ["0.0.0.0/0", "203.0.113.254/0", "::/0", "2001:db8::/0", " 0.0.0.0/00 "])
      expect(isAnyAddress(v)).toBe(true);
    for (const v of ["10.0.0.0/8", "203.0.113.0/24", "0.0.0.0/1", "0.0.0.0", "", "/0x"])
      expect(isAnyAddress(v)).toBe(false);
  });
});

describe("isAnyAddress validates the address (#2625)", () => {
  it("garbage before /0 is not any address", () => {
    for (const v of [
      "abcde/0",
      ":::/0",
      "....../0",
      "1.2.3/0",
      "256.1.1.1/0",
      "1.2.3.4.5/0",
      "01.2.3.4/0",
      "fe80::1%eth0/0",
    ])
      expect(isAnyAddress(v), v).toBe(false);
  });
  it("a real address with /0 still is, host bits and IPv4-mapped included; a non-decimal prefix never is", () => {
    for (const v of ["::ffff:192.0.2.1/0", "1.2.3.4/0", "2001:db8::1/0"])
      expect(isAnyAddress(v), v).toBe(true);
    expect(isAnyAddress("0.0.0.0/0e0")).toBe(false);
  });
  it("garbage alone never sets anySource, on any form; a valid /0 beyond the retained list still does", () => {
    const g = ingressPermissions(legacy("abcde/0"), 8);
    expect(g.anySource).toBe(false);
    expect(g.retained[0].source).toBe("abcde/0");
    expect(ingressPermissions(itemsForm(["abcde/0"], [":::/0"]), 8).anySource).toBe(false);
    const mixed = ingressPermissions(itemsForm(["abcde/0", "....../0"], ["::/0"]), 2);
    expect(mixed.retained).toHaveLength(2);
    expect(mixed.anySource).toBe(true);
  });
  it("the row keeps the literal source and makes no any-address claim", () => {
    const text = securityGroupRuleReading(
      "AuthorizeSecurityGroupIngress",
      "ec2.amazonaws.com",
      legacy("abcde/0"),
    );
    expect(text).toContain("from abcde/0");
    expect(text).not.toContain("(any address)");
  });
});

describe("ingressPermissions (#2605)", () => {
  it("reads the legacy top-level form", () => {
    const p = ingressPermissions(legacy(), 8);
    expect(p.total).toBe(1);
    expect(p.anySource).toBe(true);
    expect(p.retained[0]).toEqual({
      protocol: "tcp",
      ports: "22",
      source: "203.0.113.254/0",
      anySource: true,
    });
  });

  it("reads the items form, both families, and the source-group form of the legacy request", () => {
    const p = ingressPermissions(itemsForm(["10.0.0.0/8"], ["::/0"]), 8);
    expect(p.total).toBe(2);
    expect(p.anySource).toBe(true);
    expect(p.retained.map((r) => r.ports)).toEqual(["3389-3390", "3389-3390"]);
    const g = ingressPermissions(
      {
        groupId: SG,
        sourceSecurityGroupName: "web",
        sourceSecurityGroupOwnerId: "444455556666",
      },
      8,
    );
    expect(g.retained[0].source).toBe("group web (owner 444455556666)");
    expect(g.anySource).toBe(false);
  });
});

describe("securityGroupRuleReading (#2605)", () => {
  it("states the group, protocol, port and source, marking any address", () => {
    expect(securityGroupRuleReading("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", legacy())).toBe(
      `opens ${SG} to tcp 22 from 203.0.113.254/0 (any address)`,
    );
    expect(
      securityGroupRuleReading("RevokeSecurityGroupIngress", "ec2.amazonaws.com", itemsForm(["10.0.0.0/8"])),
    ).toBe(`removes from ${SG} tcp 3389-3390 from 10.0.0.0/8`);
  });

  it("bounds a long list and reads nothing for another service or call", () => {
    const many = itemsForm(Array.from({ length: 9 }, (_, i) => `10.0.${i}.0/24`));
    expect(securityGroupRuleReading("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", many)).toMatch(
      /\(\+6 more\)$/,
    );
    expect(securityGroupRuleReading("AuthorizeSecurityGroupIngress", "rds.amazonaws.com", legacy())).toBe("");
    expect(securityGroupRuleReading("DescribeSecurityGroups", "ec2.amazonaws.com", legacy())).toBe("");
    expect(
      securityGroupRuleReading("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", { groupId: SG }),
    ).toBe("");
  });
});

const trail = (requestParameters: unknown, over: Record<string, unknown> = {}) => ({
  eventVersion: "1.08",
  eventTime: "2026-03-01T10:00:00Z",
  eventSource: "ec2.amazonaws.com",
  eventName: "AuthorizeSecurityGroupIngress",
  awsRegion: "us-east-1",
  sourceIPAddress: "198.51.100.7",
  userAgent: "aws-cli/2.15.0",
  userIdentity: {
    type: "IAMUser",
    userName: "alice",
    accountId: "111111111111",
    arn: "arn:aws:iam::111111111111:user/alice",
  },
  recipientAccountId: "111111111111",
  requestParameters,
  responseElements: { _return: true },
  eventID: "00000000-0000-4000-8000-000000000001",
  ...over,
});

describe("AuthorizeSecurityGroupIngress through the importer (#2605)", () => {
  it("the row states the port and source even when no instance in the upload holds the group", () => {
    const res = parseCloudTrail(JSON.stringify({ Records: [trail(legacy())] }), { aggregate: false });
    const row = res.events.find((e) => /^AWS AuthorizeSecurityGroupIngress \(ec2\)/.test(e.description));
    expect(row?.description).toContain(`opens ${SG} to tcp 22 from 203.0.113.254/0 (any address)`);
  });

  it("two rules on different ports by the same caller stay two rows under aggregation", () => {
    const res = parseCloudTrail(
      JSON.stringify({
        Records: [
          trail(legacy()),
          trail(
            { ...legacy(), fromPort: 3389, toPort: 3389 },
            { eventID: "00000000-0000-4000-8000-000000000002" },
          ),
        ],
      }),
      { aggregate: true },
    );
    expect(res.events.filter((e) => /^AWS AuthorizeSecurityGroupIngress/.test(e.description))).toHaveLength(
      2,
    );
  });
});

describe("security-group reading bounds (#2605 review)", () => {
  const import1 = (records: unknown[], aggregate = false) =>
    parseCloudTrail(JSON.stringify({ Records: records }), { aggregate }).events.filter((e) =>
      /^AWS AuthorizeSecurityGroupIngress/.test(e.description),
    );

  it("an any-address source listed last is still shown and marked on the row", () => {
    const [row] = import1([
      trail(itemsForm(["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.4.0/24", "0.0.0.0/0"])),
    ]);
    expect(row.description).toContain("from 0.0.0.0/0 (any address)");
    expect(row.description).toContain("(+2 more)");
  });

  it("the marker and the count survive three long IPv6 sources", () => {
    const v6 = (i: number) => `2001:0db8:85a3:0000:0000:8a2e:0370:${7330 + i}/128`;
    const [row] = import1([trail(itemsForm([], [v6(1), v6(2), v6(3), "::/0"]))]);
    expect(row.description).toContain("(any address)");
  });

  it("two requests with the same first three sources and a different fourth stay two rows", () => {
    const first = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"];
    const rows = import1(
      [
        trail(itemsForm([...first, "10.0.4.0/24"])),
        trail(itemsForm([...first, "10.0.5.0/24"]), { eventID: "00000000-0000-4000-8000-000000000003" }),
      ],
      true,
    );
    expect(rows).toHaveLength(2);
  });
});
