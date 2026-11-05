import { describe, it, expect } from "vitest";
import {
  collectionTime,
  decide,
  identityId,
  identityKey,
  stateDiff,
  stateHash,
  stateOf,
  type StoredSnapshotObservation,
} from "../../src/analysis/cloudSnapshotModel.js";
import { snapshotCsvShape, cloudExportCsvKind } from "../../src/analysis/cloudExportDetect.js";
import { parseCloudSnapshot, OBSERVED_WORDING } from "../../src/analysis/cloudSnapshotParse.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";

// #2305 — configuration snapshots as observed state. Fixtures: example.com/example.net, fake ids.

const csv = (header: string[], ...rows: string[][]): string =>
  [header, ...rows].map((r) => r.map((v) => `"${v.replace(/"/g, '""')}"`).join(",")).join("\n");

const INBOX_HEADER = [
  "UserName",
  "RuleName",
  "Enabled",
  "RuleIdentity",
  "MoveToFolder",
  "RedirectTo",
  "ForwardTo",
  "DeleteMessage",
  "WhenChanged",
];
const inbox = (...rows: string[][]): string => csv(INBOX_HEADER, ...rows);
const rule = (o: Partial<Record<string, string>> = {}): string[] =>
  INBOX_HEADER.map(
    (h) =>
      o[h] ??
      {
        UserName: "user1@example.com",
        RuleName: "r1",
        Enabled: "True",
        RuleIdentity: "11",
        DeleteMessage: "False",
      }[h] ??
      "",
  );

const parse = (text: string, label = "InboxRules.csv") =>
  parseCloudSnapshot(text, { label, importedAt: "2026-11-05T12:00:00Z" });

describe("identity and state hash (#2305)", () => {
  it("identity is provider + tenant + object, case-insensitive; the id is a hash, never the raw key", () => {
    const a = identityKey("m365", "", "inbox-rule", "User1@Example.com|11");
    expect(a).toBe(identityKey("M365", "", "INBOX-RULE", "user1@example.com|11"));
    expect(identityId(a)).toMatch(/^[0-9a-f]{24}$/);
    expect(identityId(a)).not.toContain("example");
    expect(identityId(a)).not.toBe(identityId(identityKey("m365", "", "inbox-rule", "user1@example.com|12")));
  });

  it("state hash is order-independent and changes with any state value", () => {
    expect(stateHash({ a: "1", b: "2" })).toBe(stateHash({ b: "2", a: "1" }));
    expect(stateHash({ a: "1", b: "2" })).not.toBe(stateHash({ a: "1", b: "3" }));
  });

  it("history timestamps and identity columns stay out of the state (WhenChanged is detail only)", () => {
    const s = stateOf({ username: "u", ruleidentity: "1", forwardto: "x", whenchanged: "11/1/2026" }, [
      "username",
      "ruleidentity",
    ]);
    expect(s).toEqual({ forwardto: "x" });
  });

  it("the diff compares shared columns only, and is bounded", () => {
    expect(stateDiff({ a: "1", gone: "x" }, { a: "2", added: "y" })).toEqual(['a "1" → "2"']);
    const many = Object.fromEntries("abcdefg".split("").map((k) => [k, "1"]));
    const after = Object.fromEntries("abcdefg".split("").map((k) => [k, "2"]));
    expect(stateDiff(many, after)).toHaveLength(5);
    expect(stateDiff(many, after)[4]).toBe("+3 more");
  });
});

describe("decide — compare by observation time, never import order (#2305)", () => {
  const obs = (observedAt: string, state: Record<string, string>): StoredSnapshotObservation => ({
    id: "i",
    observedAt,
    stateHash: stateHash(state),
    state,
  });
  const T1 = "2026-11-01T10:00:00Z";
  const T2 = "2026-11-03T10:00:00Z";

  it("never observed → new", () => {
    expect(decide([], T1, { f: "" }).kind).toBe("new");
  });
  it("same time and state → duplicate (a re-import)", () => {
    expect(decide([obs(T1, { f: "" })], T1, { f: "" }).kind).toBe("duplicate");
  });
  it("later, same state → unchanged", () => {
    expect(decide([obs(T1, { f: "" })], T2, { f: "" }).kind).toBe("unchanged");
  });
  it("later, different state → changed, with the diff against the latest earlier observation", () => {
    const d = decide([obs(T1, { f: "" })], T2, { f: "x@example.net" });
    expect(d.kind).toBe("changed");
    if (d.kind === "changed") {
      expect(d.previous.observedAt).toBe(T1);
      expect(d.diff).toEqual(['f (empty) → "x@example.net"']);
    }
  });
  it("an OLDER snapshot imported after a newer one → older, never changed", () => {
    expect(decide([obs(T2, { f: "x@example.net" })], T1, { f: "" }).kind).toBe("older");
  });
  it("a hash change on columns only one side has is not a change", () => {
    expect(decide([obs(T1, { f: "" })], T2, { f: "", newcol: "z" }).kind).toBe("unchanged");
  });
});

describe("collection time (#2305)", () => {
  it("reads the MES file-name time behind the stored sequence prefix and says so", () => {
    const t = collectionTime("0007_20261101-100000-MailboxRules.csv", "2026-11-05T00:00:00Z");
    expect(t.observedAt).toBe("2026-11-01T10:00:00Z");
    expect(t.fromFileName).toBe(true);
    expect(t.basis).toMatch(/file name/);
    expect(t.basis).toMatch(/zone is not recorded/);
  });
  it("falls back to the import time, and says the true collection time is unknown", () => {
    const t = collectionTime("0007_InboxRules.csv", "2026-11-05T00:00:00Z");
    expect(t.observedAt).toBe("2026-11-05T00:00:00Z");
    expect(t.basis).toMatch(/^import time/);
    expect(t.basis).toMatch(/unknown/);
  });
  it("rejects an impossible file-name date", () => {
    expect(collectionTime("20261331-250000-MailboxRules.csv", "2026-11-05T00:00:00Z").fromFileName).toBe(
      false,
    );
  });
});

describe("detection — header combinations, never one column (#2305)", () => {
  const h = (...k: string[]): Set<string> => new Set(k);
  it("claims each MES shape, in both column spellings", () => {
    expect(snapshotCsvShape(h("username", "rulename", "ruleidentity", "forwardto"))).toBe("inboxRules");
    expect(snapshotCsvShape(h("mailboxownerid", "name", "ruleidentity", "movetofolder"))).toBe("inboxRules");
    expect(snapshotCsvShape(h("userprincipalname", "rulename", "ruleid", "delete"))).toBe("inboxRules");
    expect(snapshotCsvShape(h("name", "description", "createdby", "whenchanged", "state"))).toBe(
      "transportRules",
    );
    expect(snapshotCsvShape(h("permissiontype", "appid", "permission", "consenttype"))).toBe("oauthGrants");
    expect(snapshotCsvShape(h("user", "mfastatus", "fido2", "softwareoath"))).toBe("mfaState");
  });
  it("does not claim a table that shares only some of the columns", () => {
    expect(snapshotCsvShape(h("name", "state", "description"))).toBeNull();
    expect(snapshotCsvShape(h("username", "rulename", "forwardto"))).toBeNull();
    expect(snapshotCsvShape(h("appid", "permission"))).toBeNull();
    expect(snapshotCsvShape(h("userprincipalname", "mfastatus"))).toBeNull();
    expect(cloudExportCsvKind(h("name", "state", "whenchanged"))).toBeNull();
  });
  it("routes through the real detector to the cloudsnapshot kind", () => {
    expect(detectImportKind("x.csv", inbox(rule()))).toBe("cloudsnapshot");
  });
  it("routes the real MES column spellings too (Graph inbox rules, newer OAuth report, `user` MFA)", () => {
    const row = (n: number) => Array.from({ length: n }, (_, i) => `v${i}`);
    const graph = [
      "UserPrincipalName",
      "RuleName",
      "Sequence",
      "Enabled",
      "ForwardTo",
      "RedirectTo",
      "Delete",
      "MoveToFolder",
      "RuleId",
    ];
    const oauth = [
      "PermissionType",
      "AppId",
      "ClientObjectId",
      "AppDisplayName",
      "ResourceObjectId",
      "ResourceDisplayName",
      "Permission",
      "ConsentType",
      "PrincipalObjectId",
    ];
    const mfa = [
      "user",
      "MFAstatus",
      "email",
      "fido2",
      "app",
      "password",
      "phone",
      "softwareoath",
      "hellobusiness",
    ];
    const transport = ["Name", "Description", "CreatedBy", "WhenChanged", "State", "Priority", "Mode"];
    for (const h of [graph, oauth, mfa, transport])
      expect(detectImportKind("x.csv", csv(h, row(h.length))), h.join(",")).toBe("cloudsnapshot");
  });
  it("a table with only some of the columns stays a generic CSV", () => {
    expect(detectImportKind("x.csv", csv(["Name", "State", "Description"], ["a", "b", "c"]))).toBe("csv");
  });
});

describe("snapshot wording (#2305)", () => {
  it("every event says observed state, never an action", () => {
    const p = parse(inbox(rule({ ForwardTo: "x@example.net" })));
    expect(p.events).toHaveLength(1);
    const d = p.events[0].description;
    expect(d).toContain(OBSERVED_WORDING);
    expect(d).toMatch(/^M365 snapshot: inbox rule on user1@example\.com — /);
    expect(d).not.toMatch(/New-InboxRule|Set-InboxRule|created|added/i);
  });
  it("keeps WhenChanged as detail only, and states the time basis", () => {
    const p = parse(inbox(rule({ WhenChanged: "10/30/2026 8:00:00 AM" })));
    expect(p.events[0].timestamp).toBe("2026-11-05T12:00:00Z");
    expect(p.events[0].message).toMatch(/import time/);
    expect(p.events[0].message).toMatch(/whenchanged 10\/30\/2026 8:00:00 AM \(object history/);
  });
  it("one observation per identity; a repeated row is counted, not doubled", () => {
    const p = parse(inbox(rule(), rule()));
    expect(p.events).toHaveLength(1);
    expect(p.duplicates).toBe(1);
  });
  it("the change diff flattens every control character, as the description does", () => {
    expect(stateDiff({ n: "a" }, { n: "b\u0007\u001bc" })).toEqual(['n "a" → "b c"']);
  });
  it("flattens control characters in adversary-controlled rule names", () => {
    const p = parse(inbox(rule({ RuleName: "a\r\nM365 Exchange: New-InboxRule" })));
    expect(p.events[0].description).not.toMatch(/[\r\n]/);
  });
});
