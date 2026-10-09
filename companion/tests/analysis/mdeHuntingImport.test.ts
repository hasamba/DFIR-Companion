import { describe, it, expect } from "vitest";
import {
  parseMdeHunting,
  looksLikeMdeHunting,
  parseAdditionalFields,
} from "../../src/analysis/mdeHuntingImport.js";
import { detectImportKindEx } from "../../src/analysis/importDetect.js";

// #2097: Microsoft 365 Defender / Defender XDR advanced-hunting exports. Synthetic rows modelled on
// the three table shapes an AH export mixes in one NDJSON file: DeviceEvents (LdapSearch),
// IdentityDirectoryEvents (Directory Services replication) and CloudAppEvents.

const DKM_DN = "CN=0000-guid,CN=ADFS,CN=Microsoft,CN=Program Data,DC=example,DC=test";

const ldapDkm = {
  Timestamp: "2026-01-02T13:11:39.7724491Z",
  DeviceName: "adfs01.example.test",
  ActionType: "LdapSearch",
  InitiatingProcessFileName: "powershell.exe",
  InitiatingProcessSHA256: "a".repeat(64),
  InitiatingProcessAccountDomain: "example",
  InitiatingProcessAccountName: "analyst1",
  InitiatingProcessAccountUpn: "analyst1@example.test",
  ReportId_long: 1001,
  AdditionalFields_string: JSON.stringify({
    AttributeList: ["thumbnailphoto"],
    DistinguishedName: DKM_DN,
    ScopeOfSearch: "SubTree",
    SearchFilter: "(&(objectclass=contact)(!name=CryptoPolicy)(ThumbnailPhoto=*))",
  }),
};

const ldapDkm2 = {
  ...ldapDkm,
  Timestamp: "2026-01-02T13:11:53.5836949Z",
  ReportId_long: 1002,
  AdditionalFields_string: JSON.stringify({ DistinguishedName: DKM_DN, SearchFilter: "(name=CryptoPolicy)" }),
};

const ldapDomainAdmins = {
  ...ldapDkm,
  Timestamp: "2026-01-02T13:15:30.513652Z",
  ReportId_long: 1003,
  AdditionalFields_string: JSON.stringify({
    DistinguishedName: "DC=example,DC=test",
    SearchFilter: "(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=Users,DC=example,DC=test))",
  }),
};

const replication = {
  Timestamp: "2026-01-02T13:13:02.057Z",
  ActionType: "Directory Services replication",
  Application: "Active Directory",
  AccountObjectId: "11111111-1111-1111-1111-111111111111",
  AccountDisplayName: "User Two",
  AccountName: "user2",
  AccountDomain: "example.test",
  AccountUpn: "user2@example.test",
  IPAddress: "10.0.0.5",
  ReportId: "r-1",
  AdditionalFields: "{'FROM.DEVICE': 'ADFS01', 'TO.DEVICE': 'DC01', 'IsSomething': False, 'Other': None}",
  DestinationDeviceName: "dc01.example.test",
  DeviceName: "adfs01.example.test",
  Protocol: "Drsr",
};

const mailAccess = {
  Timestamp: "2026-01-02T13:32:07Z",
  ActionType: "MailItemsAccessed",
  Application: "Microsoft Exchange Online",
  AccountObjectId: "22222222-2222-2222-2222-222222222222",
  AccountDisplayName: "SomeApp",
  IPAddress: "203.0.113.9",
  ObjectName: "MailItemsAccessed",
  ReportId: "r-2",
  AdditionalFields: { IsSatelliteProvider: false },
  RawEventData: { Operation: "MailItemsAccessed", UserId: "user2@example.test" },
};

const grant = {
  Timestamp: "2026-01-02T13:27:20Z",
  ActionType: "Add delegated permission grant.",
  Application: "Office 365",
  AccountObjectId: "11111111-1111-1111-1111-111111111111",
  AccountDisplayName: "User Two",
  ReportId: "r-3",
};

const ALL = [ldapDkm, ldapDkm2, ldapDomainAdmins, replication, mailAccess, grant];
const ndjson = (rows: object[]) => rows.map((r) => JSON.stringify(r)).join("\n");

describe("MDE advanced-hunting detection (#2097)", () => {
  for (const [name, first] of [
    ["DeviceEvents", ldapDkm],
    ["IdentityDirectoryEvents", replication],
    ["CloudAppEvents", mailAccess],
  ] as const) {
    it(`claims the file when a ${name} row comes first`, () => {
      const rows = [first, ...ALL.filter((r) => r !== first)];
      expect(detectImportKindEx("Microsoft365DefenderEvents.json", ndjson(rows))).toEqual({
        kind: "mdehunting",
        confident: true,
      });
    });
  }

  it("does not claim a bare Timestamp + ActionType row", () => {
    expect(looksLikeMdeHunting({ Timestamp: "2026-01-02T00:00:00Z", ActionType: "X" })).toBe(false);
    expect(
      detectImportKindEx("x.json", ndjson([{ Timestamp: "2026-01-02T00:00:00Z", ActionType: "X" }])).kind,
    ).not.toBe("mdehunting");
  });

  it("leaves an M365 unified audit log row with m365", () => {
    const ual = { CreationTime: "2026-01-02T00:00:00", Operation: "MailItemsAccessed", AuditData: "{}" };
    expect(detectImportKindEx("ual.json", ndjson([ual])).kind).toBe("m365");
  });

  it("accepts TimeGenerated (Sentinel copy) in place of Timestamp", () => {
    const { Timestamp: _t, ...rest } = ldapDkm;
    expect(looksLikeMdeHunting({ ...rest, TimeGenerated: "2026-01-02T00:00:00Z" })).toBe(true);
  });
});

describe("parseMdeHunting (#2097)", () => {
  const parsed = parseMdeHunting(ndjson(ALL), { aggregate: false });
  const find = (re: RegExp) => parsed.events.find((e) => re.test(e.description));

  it("maps every row to its own event with a timestamp", () => {
    expect(parsed.total).toBe(6);
    expect(parsed.events).toHaveLength(6);
    expect(parsed.format).toBe("mde-advanced-hunting");
    for (const e of parsed.events) expect(e.timestamp).toMatch(/^2026-01-02T/);
  });

  it("keeps distinct LDAP filters apart even with aggregation on", () => {
    const agg = parseMdeHunting(ndjson(ALL));
    expect(agg.events.filter((e) => /LdapSearch/.test(e.description))).toHaveLength(3);
  });

  it("keeps two replication requests at different times as two events, collapses exact duplicates", () => {
    const later = { ...replication, Timestamp: "2026-01-02T13:08:18.374Z" };
    expect(parseMdeHunting(ndjson([replication, later])).events).toHaveLength(2);
    const dup = parseMdeHunting(ndjson([replication, replication]));
    expect(dup.events).toHaveLength(1);
    expect(dup.events[0].count).toBe(2);
  });

  it("sets asset from DeviceName on device rows and none on cloud rows", () => {
    expect(find(/Directory Services replication/)?.asset).toBe("adfs01.example.test");
    expect(find(/ThumbnailPhoto/)?.asset).toBe("adfs01.example.test");
    expect(find(/MailItemsAccessed/)?.asset).toBeUndefined();
  });

  it("names the actor by the documented precedence", () => {
    expect(find(/Directory Services replication/)?.description).toContain("user2@example.test");
    expect(find(/ThumbnailPhoto/)?.description).toContain("analyst1@example.test");
    expect(find(/MailItemsAccessed/)?.description).toContain("SomeApp");
  });

  it("grades replication from a non-destination device High, T1003.006", () => {
    const e = find(/Directory Services replication/);
    expect(e?.severity).toBe("High");
    expect(e?.mitreTechniques).toContain("T1003.006");
    expect(e?.description).toContain("dc01.example.test");
  });

  it("does not grade a replication between the same device up", () => {
    const same = parseMdeHunting(ndjson([{ ...replication, DestinationDeviceName: replication.DeviceName }]));
    expect(same.events[0].severity).toBe("Low");
  });

  it("grades an LDAP read of the ADFS DKM container High, T1552.004, with the filter", () => {
    const e = find(/\(name=CryptoPolicy\)/);
    expect(e?.severity).toBe("High");
    expect(e?.mitreTechniques).toContain("T1552.004");
    expect(e?.description).toContain("(name=CryptoPolicy)");
  });

  it("grades a Domain Admins membership enumeration Medium, T1087.002", () => {
    const e = find(/Domain Admins/);
    expect(e?.severity).toBe("Medium");
    expect(e?.mitreTechniques).toContain("T1087.002");
  });

  it("grades a delegated permission grant Medium (T1098.003) and MailItemsAccessed Low", () => {
    const g = find(/delegated permission grant/);
    expect(g?.severity).toBe("Medium");
    expect(g?.mitreTechniques).toContain("T1098.003");
    expect(find(/MailItemsAccessed/)?.severity).toBe("Low");
  });

  it("collects IP and SHA256 IOCs", () => {
    const values = parsed.iocs.map((i) => i.value);
    expect(values).toContain("10.0.0.5");
    expect(values).toContain("203.0.113.9");
    expect(values).toContain("a".repeat(64));
  });

  it("does not crash on an adversary CSV-formula string in a search filter", () => {
    const evil = {
      ...ldapDkm,
      AdditionalFields_string: JSON.stringify({ SearchFilter: "=cmd|' /C calc'!A0" }),
    };
    const out = parseMdeHunting(ndjson([evil]));
    expect(out.events[0].description).toContain("=cmd|");
  });

  it("returns empty for empty input and skips non-AH rows", () => {
    expect(parseMdeHunting("").format).toBe("empty");
    expect(parseMdeHunting(ndjson([{ foo: 1 }])).events).toHaveLength(0);
  });
});

describe("parseAdditionalFields (#2097)", () => {
  it("accepts an object, a JSON string and a Python-repr string", () => {
    expect(parseAdditionalFields({ a: 1 })).toEqual({ a: 1 });
    expect(parseAdditionalFields('{"a":1}')).toEqual({ a: 1 });
    expect(parseAdditionalFields("{'a': 'x', 'b': False, 'c': None, 'd': True}")).toEqual({
      a: "x",
      b: false,
      c: null,
      d: true,
    });
  });
  it("returns an empty object for malformed input without throwing", () => {
    expect(parseAdditionalFields("{not json")).toEqual({});
    expect(parseAdditionalFields(undefined)).toEqual({});
    expect(parseAdditionalFields(42)).toEqual({});
  });
});
