import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import { parseCloudSnapshot } from "../../src/analysis/cloudSnapshotParse.js";
import { HIGH_RISK_SCOPES } from "../../src/analysis/cloudSnapshotGrants.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #2305 — the observation rules in the SHIPPED tags.yaml, run over the REAL snapshot parser's rows,
// and the importer's own grade beside them: both must agree, so suspicious state stays above Info
// with the tagger off (TAGGER_AUTO=false) and gets its tags with it on.

const YAML = readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8");
const RULES = compileText(YAML);

const csv = (header: string[], ...rows: Record<string, string>[]): string =>
  [
    header.join(","),
    ...rows.map((r) => header.map((h) => `"${(r[h] ?? "").replace(/"/g, '""')}"`).join(",")),
  ].join("\n");

interface Graded {
  description: string;
  severity: string;
  ruleIds: string[];
}

function graded(text: string): Graded[] {
  const parsed = parseCloudSnapshot(text, { label: "snap.csv", importedAt: "2026-11-05T00:00:00Z" });
  return parsed.events.map((e, i) => {
    const event = {
      ...e,
      id: `e${i}`,
      relatedFindingIds: [],
      sourceScreenshots: [],
    } as unknown as ForensicEvent;
    return {
      description: e.description,
      severity: e.severity,
      ruleIds: runTagger([event], RULES).perEvent[0]?.ruleIds ?? [],
    };
  });
}
const one = (text: string): Graded => {
  const g = graded(text);
  expect(g).toHaveLength(1);
  return g[0];
};

const INBOX = [
  "UserName",
  "RuleName",
  "RuleIdentity",
  "Enabled",
  "MoveToFolder",
  "ForwardTo",
  "RedirectTo",
  "DeleteMessage",
];
// A second mailbox makes eu.example.com a tenant domain of the file.
const tenant = {
  UserName: "user9@eu.example.com",
  RuleName: "keep",
  RuleIdentity: "99",
  MoveToFolder: "Receipts",
};
const inbox = (r: Record<string, string>): Graded =>
  graded(csv(INBOX, { UserName: "user1@example.com", RuleName: "r", RuleIdentity: "1", ...r }, tenant))[0];

describe("inbox rules (#2305)", () => {
  it("external forwarding: High + snap_inbox_rule_external_forward", () => {
    const g = inbox({ ForwardTo: '"x@example.net" [SMTP:x@example.net]' });
    expect(g.severity).toBe("High");
    expect(g.ruleIds).toContain("snap_inbox_rule_external_forward");
  });
  it("external redirect: High", () => {
    const g = inbox({ RedirectTo: "x@example.net" });
    expect(g.severity).toBe("High");
    expect(g.ruleIds).toContain("snap_inbox_rule_external_forward");
  });
  it("forwarding to another of the tenant's mailbox domains is not external: Low, no external rule", () => {
    const g = inbox({ ForwardTo: "boss@eu.example.com" });
    expect(g.severity).toBe("Low");
    expect(g.ruleIds).not.toContain("snap_inbox_rule_external_forward");
  });
  it("delete and move-to-RSS-Feeds / Archive: Medium + snap_inbox_rule_hides_mail", () => {
    const variants: Record<string, string>[] = [
      { DeleteMessage: "True" },
      { MoveToFolder: "user1@example.com:\\RSS Feeds" },
      { MoveToFolder: "Archive" },
    ];
    for (const r of variants) {
      const g = inbox(r);
      expect(g.severity, JSON.stringify(r)).toBe("Medium");
      expect(g.ruleIds, JSON.stringify(r)).toContain("snap_inbox_rule_hides_mail");
    }
  });
  it("a plain move to an ordinary folder: Info, no observation rule", () => {
    const g = inbox({ MoveToFolder: "Newsletters", DeleteMessage: "False" });
    expect(g.severity).toBe("Info");
    expect(g.ruleIds.filter((id) => id.startsWith("snap_"))).toEqual([]);
  });
  it("an external recipient in fourth place still grades High and is named in the summary", () => {
    const g = inbox({
      ForwardTo: "a@example.com; b@example.com; c@eu.example.com; attacker@example.net",
    });
    expect(g.severity).toBe("High");
    expect(g.description).toContain("attacker@example.net (outside the tenant");
    expect(g.ruleIds).toContain("snap_inbox_rule_external_forward");
  });
  it("more than three external recipients: the omitted ones are counted as outside", () => {
    const g = inbox({
      ForwardTo: "w@example.net; x@example.net; y@example.net; z@example.net; a@example.com",
    });
    expect(g.description).toMatch(/\(\+2 more, of which 1 z@example\.net \(outside/);
  });
  it("the inbox-rule ACTION rules never fire on observed state", () => {
    const g = inbox({ ForwardTo: "x@example.net" });
    expect(g.ruleIds).not.toContain("ts_m365_inbox_rule");
    expect(g.ruleIds).not.toContain("ts_m365_mailbox_forwarding");
  });
});

const TRANSPORT = ["Name", "Description", "CreatedBy", "WhenChanged", "State", "Priority", "Mode"];
const transport = (r: Record<string, string>): Graded =>
  one(
    csv(TRANSPORT, {
      Name: "t",
      State: "Enabled",
      Mode: "Enforce",
      WhenChanged: "11/1/2026 9:00:00 AM",
      ...r,
    }),
  );

describe("transport rules — MES columns, actions read from Description (#2305)", () => {
  it("redirect outside the tenant (CreatedBy names the tenant's domain): High", () => {
    const g = transport({
      CreatedBy: "admin@example.com",
      Description:
        "If the message:\r\n\tIs sent to 'Inside the organization'\r\nTake the following actions:\r\n\tRedirect the message to 'x@example.net'",
    });
    expect(g.severity).toBe("High");
    expect(g.ruleIds).toContain("snap_transport_rule_external_redirect");
  });
  it("an external redirect recipient in fourth place still grades High", () => {
    const g = transport({
      CreatedBy: "admin@example.com",
      Description:
        "Take the following actions: Redirect the message to 'a@example.com', 'b@example.com', 'c@example.com' and 'attacker@example.net'",
    });
    expect(g.severity).toBe("High");
    expect(g.ruleIds).toContain("snap_transport_rule_external_redirect");
  });
  it("Bcc where the tenant's domains are unknown: Medium, says it cannot decide", () => {
    const g = transport({
      Description: "Take the following actions: Blind carbon copy (Bcc) the message to 'x@example.net'",
    });
    expect(g.severity).toBe("Medium");
    expect(g.description).toMatch(/not decidable from this export/);
    expect(g.ruleIds).toContain("snap_transport_rule_redirect");
    expect(g.ruleIds).not.toContain("snap_transport_rule_external_redirect");
  });
  it("delete without notifying: Medium + snap_transport_rule_deletes", () => {
    const g = transport({
      Description:
        "If the message: Includes these words in the message subject: 'invoice' Take the following actions: Delete the message without notifying anyone",
    });
    expect(g.severity).toBe("Medium");
    expect(g.ruleIds).toContain("snap_transport_rule_deletes");
  });
  it("a disclaimer rule: Info, no observation rule, and no transport ACTION rule", () => {
    const g = transport({ Description: "Take the following actions: Append the disclaimer 'Confidential'" });
    expect(g.severity).toBe("Info");
    expect(g.ruleIds.filter((id) => id.startsWith("snap_") || id === "ts_m365_transport_rule")).toEqual([]);
  });
});

const OAUTH = [
  "PermissionType",
  "AppId",
  "AppDisplayName",
  "ResourceObjectId",
  "ResourceDisplayName",
  "Permission",
  "ConsentType",
  "PrincipalObjectId",
];
const oauth = (r: Record<string, string>): Graded =>
  one(
    csv(OAUTH, {
      AppId: "00000000-0000-4000-8000-000000000901",
      AppDisplayName: "Helper",
      ResourceObjectId: "00000000-0000-4000-8000-000000000902",
      ResourceDisplayName: "Microsoft Graph",
      ConsentType: "AllPrincipals",
      ...r,
    }),
  );

describe("OAuth grants (#2305)", () => {
  it("a high-risk APPLICATION permission: High + snap_oauth_high_risk_application", () => {
    for (const scope of ["Mail.ReadWrite", "Files.ReadWrite.All", "full_access_as_app"]) {
      const g = oauth({ PermissionType: "Application", Permission: scope });
      expect(g.severity, scope).toBe("High");
      expect(g.ruleIds, scope).toContain("snap_oauth_high_risk_application");
    }
  });
  it("a high-risk DELEGATED permission: Medium + snap_oauth_high_risk_delegated", () => {
    const g = oauth({
      PermissionType: "Delegated",
      Permission: "Mail.ReadWrite",
      ConsentType: "Principal",
      PrincipalObjectId: "00000000-0000-4000-8000-000000000903",
    });
    expect(g.severity).toBe("Medium");
    expect(g.ruleIds).toContain("snap_oauth_high_risk_delegated");
  });
  it("a look-alike scope and a low-risk scope stay Info", () => {
    for (const scope of ["Mail.ReadWrite.Shared", "User.Read", "Mail.Read"]) {
      const g = oauth({ PermissionType: "Application", Permission: scope });
      expect(g.severity, scope).toBe("Info");
      expect(
        g.ruleIds.filter((id) => id.startsWith("snap_")),
        scope,
      ).toEqual([]);
    }
  });
  it("tags.yaml and the importer name the same high-risk scopes", () => {
    for (const scope of HIGH_RISK_SCOPES) expect(YAML).toContain(scope.replace(/\./g, "\\."));
  });
});

const MFA = [
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
describe("MFA methods (#2305)", () => {
  it("no MFA method registered: Low, says Conditional Access enforcement is unknown", () => {
    const g = one(
      csv(MFA, { user: "user1@example.com", MFAstatus: "Disabled", password: "True", email: "True" }),
    );
    expect(g.severity).toBe("Low");
    expect(g.description).toMatch(/no MFA method registered/);
    expect(g.description).toMatch(/Conditional Access .* unknown/);
    expect(g.ruleIds).toContain("snap_mfa_none_registered");
  });
  it("MFA registered: Info, no observation rule", () => {
    const g = one(csv(MFA, { user: "user2@example.com", MFAstatus: "Enabled", app: "True" }));
    expect(g.severity).toBe("Info");
    expect(g.ruleIds.filter((id) => id.startsWith("snap_"))).toEqual([]);
  });
});
