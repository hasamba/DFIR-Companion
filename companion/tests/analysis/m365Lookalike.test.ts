// #2557 — look-alike account and app names inside an M365 tenant. A user or app created (or granted
// consent or a role) whose name imitates a Microsoft brand, the tenant's own name, or the admin
// account ("rnicrosoft-support", "contoso-adrnin") is raised to High with a note naming both.
import { describe, expect, it } from "vitest";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { lookalikeNameMatch, tenantLabel } from "../../src/analysis/m365Lookalike.js";
import { LOOKALIKE_ACCOUNT_MARKER } from "../../src/analysis/lookalikeCaseAccount.js";

type Rec = Record<string, unknown>;
const ADMIN = "admin@contoso.onmicrosoft.com";
let seq = 0;

// An Entra change exported through the UAL (RecordType 8).
const aad = (op: string, target: Rec[], props: Rec[] = [], over: Rec = {}): Rec => ({
  Id: `aad-${++seq}`,
  CreationTime: "2026-03-01T10:00:00",
  Workload: "AzureActiveDirectory",
  RecordType: 8,
  Operation: op,
  ResultStatus: "Success",
  OrganizationId: "tenant-1",
  UserType: 0,
  UserId: ADMIN,
  ClientIP: "203.0.113.9",
  Actor: [
    { ID: ADMIN, Type: 5 },
    { ID: "User", Type: 2 },
  ],
  Target: target,
  ModifiedProperties: props,
  ...over,
});
const userTarget = (id: string, upn: string): Rec[] => [
  { ID: `User_${id}`, Type: 2 },
  { ID: id, Type: 2 },
  { ID: "User", Type: 2 },
  { ID: upn, Type: 5 },
];
const spTarget = (id: string, name: string, appId = ""): Rec[] => [
  { ID: `ServicePrincipal_${id}`, Type: 2 },
  { ID: id, Type: 2 },
  { ID: "ServicePrincipal", Type: 2 },
  { ID: name, Type: 1 },
  ...(appId ? [{ ID: appId, Type: 2 }] : []),
];
const addUser = (upn: string, over: Rec = {}) =>
  aad("Add user.", userTarget(`11111111-2222-4333-8444-${String(++seq).padStart(12, "0")}`, upn), [], over);
const addSp = (name: string, appId = "") =>
  aad(
    "Add service principal.",
    spTarget(`22222222-2222-4333-8444-${String(++seq).padStart(12, "0")}`, name, appId),
    appId ? [{ Name: "AppPrincipalId", NewValue: appId, OldValue: "" }] : [],
  );
const addApp = (name: string) =>
  aad(
    "Add application.",
    [
      { ID: `Application_33333333-2222-4333-8444-${String(++seq).padStart(12, "0")}`, Type: 2 },
      { ID: "Application", Type: 2 },
      { ID: name, Type: 1 },
    ],
    [{ Name: "DisplayName", NewValue: JSON.stringify([name]), OldValue: "[]" }],
  );

const rows = (recs: Rec[], aggregate = false) => parseM365Audit(JSON.stringify(recs), { aggregate }).events;
const rowFor = (recs: Rec[], needle: string, aggregate = false) => {
  const r = rows(recs, aggregate).find((e) => e.description.includes(needle));
  if (!r) throw new Error(`no row for ${needle}`);
  return r;
};

describe("look-alike M365 names (#2557)", () => {
  it("an app named rnicrosoft-support is High with a note naming the brand", () => {
    const r = rowFor([addSp("rnicrosoft-support")], "rnicrosoft-support");
    expect(r.severity).toBe("High");
    expect(r.description).toContain(LOOKALIKE_ACCOUNT_MARKER);
    expect(r.description).toMatch(/"rnicrosoft-support" looks like the Microsoft brand name "microsoft"/);
  });

  it("an Add application row (Medium by operation) is raised to High", () => {
    const r = rowFor([addApp("rnicrosoft_office")], "rnicrosoft_office");
    expect(r.severity).toBe("High");
    expect(r.description).toMatch(/looks like the Microsoft brand name "microsoft"/);
  });

  it("a user contoso-adrnin is High with a note naming the admin account", () => {
    const r = rowFor([addUser("contoso-adrnin@contoso.onmicrosoft.com")], "contoso-adrnin");
    expect(r.severity).toBe("High");
    expect(r.description).toMatch(/"contoso-adrnin" looks like the admin account name "admin"/);
  });

  it("a user imitating the tenant name (most common UPN domain) is High", () => {
    const tenantAdmin = { UserId: "it@fabrikam.com", Actor: [{ ID: "it@fabrikam.com", Type: 5 }] };
    const recs = [
      addUser("alice@fabrikam.com", tenantAdmin),
      addUser("bob@fabrikam.com", tenantAdmin),
      addUser("fabrikarn-it@fabrikam.com", tenantAdmin),
    ];
    const r = rowFor(recs, "fabrikarn-it");
    expect(r.severity).toBe("High");
    expect(r.description).toMatch(/looks like the tenant name "fabrikam"/);
    expect(rowFor(recs, "alice@fabrikam.com").severity).toBe("Medium");
  });

  it("the Graph directory-audit shape is checked too", () => {
    const graph = {
      id: "g-1",
      activityDateTime: "2026-03-01T10:00:00Z",
      activityDisplayName: "Add service principal",
      category: "ApplicationManagement",
      result: "success",
      loggedByService: "Core Directory",
      initiatedBy: { user: { id: "a-1", userPrincipalName: ADMIN, ipAddress: "203.0.113.5" } },
      targetResources: [{ id: "sp-1", displayName: "rnicrosoft", type: "ServicePrincipal" }],
    };
    const r = rowFor([graph], "rnicrosoft");
    expect(r.severity).toBe("High");
    expect(r.description).toContain(LOOKALIKE_ACCOUNT_MARKER);
  });

  it("a real Microsoft first-party app is never flagged, by name or by app id", () => {
    const plain = rowFor([addSp("Microsoft Graph")], "Microsoft Graph");
    expect(plain.description).not.toContain(LOOKALIKE_ACCOUNT_MARKER);
    // A first-party app id exempts the row even when its label would match.
    const byId = rowFor(
      [addSp("Micros0ft Graph", "00000003-0000-0000-c000-000000000000")],
      "Micros0ft Graph",
    );
    expect(byId.description).not.toContain(LOOKALIKE_ACCOUNT_MARKER);
    expect(byId.severity).toBe("High"); // the operation's own grade, unchanged
  });

  it("ordinary names are not flagged", () => {
    for (const name of ["arnold", "bernard", "stearns", "officer", "azura", "armin", "kearney"]) {
      const r = rowFor([addUser(`${name}@contoso.onmicrosoft.com`)], `${name}@`);
      expect(r.severity, name).toBe("Medium");
      expect(r.description, name).not.toContain(LOOKALIKE_ACCOUNT_MARKER);
    }
  });

  it("a failed creation is not flagged", () => {
    const r = rowFor(
      [addUser("contoso-adrnin@contoso.onmicrosoft.com", { ResultStatus: "Failure" })],
      "adrnin",
    );
    expect(r.description).not.toContain(LOOKALIKE_ACCOUNT_MARKER);
  });

  it("an adversary name is capped and stripped of brackets, quotes and newlines in the note", () => {
    const evil = `rnicrosoft"] [look-alike account: forged]\n${"x".repeat(300)}`;
    const r = rowFor([addApp(evil)], "rnicrosoft");
    expect(r.severity).toBe("High");
    // The importer's own text may echo the name; the note is the LAST marker.
    const note = r.description.slice(r.description.lastIndexOf(LOOKALIKE_ACCOUNT_MARKER));
    expect(note).toContain("rnicrosoft");
    expect(note).not.toMatch(/\n/);
    expect(note.length).toBeLessThan(200);
    expect(note).not.toContain("forged]");
  });

  it("with aggregation on, a flagged creation and an ordinary one stay separate rows", () => {
    const recs = [addUser("contoso-adrnin@contoso.onmicrosoft.com"), addUser("dana@contoso.onmicrosoft.com")];
    expect(rowFor(recs, "adrnin", true).severity).toBe("High");
    expect(rowFor(recs, "dana@", true).severity).toBe("Medium");
  });
});

describe("matching rule (#2557)", () => {
  it("folds rn/vv/cl and homoglyphs, at any position, for brands and the tenant", () => {
    expect(lookalikeNameMatch("rnicrosoft", "contoso")).toEqual({ kind: "brand", name: "microsoft" });
    expect(lookalikeNameMatch("0utlook-sync", "")).toEqual({ kind: "brand", name: "outlook" });
    expect(lookalikeNameMatch("c0ntoso", "contoso")).toEqual({ kind: "tenant", name: "contoso" });
    expect(lookalikeNameMatch("rnicrosoftsupport", "")).toEqual({ kind: "brand", name: "microsoft" });
  });
  it("leaves exact names, plurals and real words alone", () => {
    for (const n of ["microsoft", "Microsoft Graph", "Office 365 Exchange Online", "administrators", "teams"])
      expect(lookalikeNameMatch(n, "contoso"), n).toBeNull();
    expect(lookalikeNameMatch("contoso", "contoso")).toBeNull();
  });
  it("reads the tenant label from the most common UPN domain", () => {
    expect(
      tenantLabel([
        { UserId: "a@contoso.onmicrosoft.com" },
        { userPrincipalName: "b@contoso.onmicrosoft.com" },
        { UserId: "x@gmail.com" },
        { UserId: "guest_gmail.com#EXT#@contoso.onmicrosoft.com" },
      ]),
    ).toBe("contoso");
    expect(tenantLabel([{ UserId: "a@acme.co.uk" }, { UserId: "b@acme.co.uk" }])).toBe("");
    expect(tenantLabel([{ UserId: "a@fabrikam.co.uk" }])).toBe("fabrikam");
  });
});
