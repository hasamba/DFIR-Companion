import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { bundledSigmaDir, loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import {
  AZURE_ACTIVITY,
  AZURE_M365,
  SIGMA_NAME_VALUE_MAX_ELEMENTS,
  sourceResolver,
  ualNameValue,
} from "../../src/analysis/sigmaLogSources.js";
import { reparseForRegrade, SIGMA_REGRADE_IMPORTERS } from "../../src/analysis/sigmaRegradeSources.js";
import { bundledSuzakuDir } from "../../src/analysis/sigmaSuzakuRules.js";

// Import-time Sigma grading of the Microsoft 365 unified audit log and the Azure Activity Log
// (#2500): Suzaku's suzaku/m365 + suzaku/azure/activity_logs rules and SigmaHQ's
// rules/cloud/azure/activity_logs, read through the real importers. Records are synthetic
// (example.com accounts, documentation IPs, zero GUIDs) in the shapes the exports really write.

type Row = Record<string, unknown>;

const { set } = loadBundledSigmaRuleSet();
const sigma = createSigmaImportGrader(set).snapshot();

/** A UAL record as a CSV export carries it: outer columns, the full record as AuditData JSON. */
const ual = (operation: string, audit: Row = {}): Row => ({
  CreationDate: "2026-03-01T10:00:00Z",
  UserIds: "admin@example.com",
  Operations: operation,
  AuditData: JSON.stringify({
    CreationTime: "2026-03-01T10:00:00",
    Id: "00000000-0000-0000-0000-000000000001",
    Operation: operation,
    OrganizationId: "00000000-0000-0000-0000-0000000000aa",
    RecordType: 1,
    ResultStatus: "True",
    UserKey: "admin@example.com",
    UserType: 2,
    Workload: "Exchange",
    ClientIP: "198.51.100.7",
    UserId: "admin@example.com",
    ObjectId: "victim@example.com",
    ...audit,
  }),
});

const params = (p: Record<string, unknown>) => ({
  Parameters: Object.entries(p).map(([Name, Value]) => ({ Name, Value })),
});

/** An Azure Activity Log event in the REST / `az monitor activity-log` shape. */
const azureRest = (operation: string, extra: Row = {}): Row => ({
  eventTimestamp: "2026-03-01T10:00:00Z",
  caller: "admin@example.com",
  correlationId: "00000000-0000-0000-0000-000000000002",
  resourceId: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1/providers/x/y",
  operationName: { value: operation, localizedValue: operation },
  status: { value: "Succeeded" },
  httpRequest: { clientIpAddress: "198.51.100.7" },
  ...extra,
});

const m365 = (records: Row[], s = sigma) =>
  parseM365Audit(JSON.stringify(records), { aggregate: false, sigma: s });
const azure = (records: Row[], s = sigma) =>
  parseCloudActivity(JSON.stringify(records), { aggregate: false, sigma: s });
const titles = (message: string | undefined) =>
  [...(message ?? "").matchAll(/Sigma rule: (.+?) \[/g)].map((m) => m[1]);

describe("the name/value resolver for UAL collections", () => {
  const read = (rec: Row, coll: string, key: string) => ualNameValue(coll, key)(rec);

  it("reads the Value of the element whose Name matches, case-insensitively", () => {
    const rec = params({ Identity: "victim", ForwardingSmtpAddress: "smtp:out@example.net" });
    expect(read(rec, "Parameters", "forwardingsmtpaddress")).toEqual({
      present: true,
      values: ["smtp:out@example.net"],
      incomplete: false,
    });
  });

  it("is absent when no element has that Name, and gives every value for duplicate names", () => {
    expect(read(params({ Identity: "victim" }), "Parameters", "ForwardingSmtpAddress").present).toBe(false);
    const dup = {
      Parameters: [
        { Name: "X", Value: "a" },
        { Name: "x", Value: "b" },
      ],
    };
    expect(read(dup, "Parameters", "X").values).toEqual(["a", "b"]);
  });

  it("keeps a null Value as null, flattens an array Value, and renders an object Value as JSON", () => {
    expect(read({ Parameters: [{ Name: "X", Value: null }] }, "Parameters", "X")).toMatchObject({
      present: true,
      values: [null],
    });
    expect(read({ Parameters: [{ Name: "X", Value: ["a", "b"] }] }, "Parameters", "X").values).toEqual([
      "a",
      "b",
    ]);
    expect(read({ Parameters: [{ Name: "X", Value: { k: 1 } }] }, "Parameters", "X").values).toEqual([
      '{"k":1}',
    ]);
  });

  it("reads a collection written as a JSON string", () => {
    const rec = { ExtendedProperties: JSON.stringify([{ Name: "UserAgent", Value: "azurehound/2.1" }]) };
    expect(read(rec, "ExtendedProperties", "UserAgent").values).toEqual(["azurehound/2.1"]);
  });

  it("marks a collection past the element cap incomplete, never absent", () => {
    const many = Array.from({ length: SIGMA_NAME_VALUE_MAX_ELEMENTS + 5 }, (_, i) => ({
      Name: `p${i}`,
      Value: "v",
    }));
    many.push({ Name: "X", Value: "late" });
    const r = read({ Parameters: many }, "Parameters", "X");
    expect(r.incomplete).toBe(true);
    expect(r.present).toBe(false);
  });

  it("the source also reads an export that already flattened the collection into an object", () => {
    const resolve = sourceResolver(AZURE_M365);
    expect(
      resolve(
        { Parameters: { ForwardingSmtpAddress: "smtp:a@example.net" } },
        "Parameters.ForwardingSmtpAddress",
      ).values,
    ).toEqual(["smtp:a@example.net"]);
    expect(
      resolve(params({ ForwardingSmtpAddress: "smtp:b@example.net" }), "Parameters.ForwardingSmtpAddress")
        .values,
    ).toEqual(["smtp:b@example.net"]);
  });

  it("reads the Azure operation name in all three export shapes", () => {
    const resolve = sourceResolver(AZURE_ACTIVITY);
    const op = "Microsoft.Authorization/roleAssignments/write";
    expect(resolve(azureRest(op), "operationName").values).toContain(op);
    expect(resolve({ operationName: op.toUpperCase() }, "operationName").values).toContain(op.toUpperCase());
    expect(resolve({ OperationNameValue: op }, "operationName").values).toContain(op);
    expect(
      resolve({ Properties: JSON.stringify({ statusCode: "Created" }) }, "properties.statusCode").values,
    ).toEqual(["Created"]);
  });
});

describe("Microsoft 365 audit records through the importer", () => {
  it("labels mail forwarding set through Set-Mailbox, without changing the severity at the defaults", () => {
    const rec = ual(
      "Set-Mailbox",
      params({ Identity: "victim", ForwardingSmtpAddress: "smtp:out@example.net" }),
    );
    const without = m365([rec], undefined);
    const r = m365([rec]);
    expect(titles(r.events[0].message)).toContain("M365 Mailbox Forwarding Configured via Set-Mailbox");
    expect(r.events[0].severity).toBe(without.events[0].severity);
    expect(r.events[0].message).toMatch(
      /Suzaku .*github\.com\/Yamato-Security\/suzaku-rules\/blob\/56c5275e/,
    );
  });

  it("does not label a Set-Mailbox that clears forwarding or sets something else", () => {
    const cleared = ual("Set-Mailbox", params({ Identity: "victim", ForwardingSmtpAddress: "" }));
    const other = ual("Set-Mailbox", params({ Identity: "victim", RetainDeletedItemsFor: "30.00:00:00" }));
    for (const rec of [cleared, other])
      expect(titles(m365([rec]).events[0].message)).not.toContain(
        "M365 Mailbox Forwarding Configured via Set-Mailbox",
      );
  });

  it("labels New-InboxRule and an AzureHound user agent", () => {
    expect(
      titles(m365([ual("New-InboxRule", params({ Name: "x", MoveToFolder: "RSS" }))]).events[0].message),
    ).toContain("M365 New Inbox Rule Created");
    const hound = ual("UserLoggedIn", {
      Workload: "AzureActiveDirectory",
      RecordType: 15,
      ExtendedProperties: [{ Name: "UserAgent", Value: "azurehound/v2.4.1" }],
    });
    const r = m365([hound]);
    expect(r.events.flatMap((e) => titles(e.message))).toContain("M365 Sign-in from AzureHound");
  });

  it("matches only on a Parameters value equal to the rule's", () => {
    const off = ual("Set-AdminAuditLogConfig", params({ UnifiedAuditLogIngestionEnabled: "False" }));
    const on = ual("Set-AdminAuditLogConfig", params({ UnifiedAuditLogIngestionEnabled: "True" }));
    const title = titles(m365([off]).events[0].message);
    expect(title.length).toBe(1);
    expect(titles(m365([on]).events[0].message)).not.toContain(title[0]);
  });

  it("re-grades a stored M365 file the same way", () => {
    const text = JSON.stringify([ual("New-InboxRule", params({ Name: "x" }))]);
    const rows = reparseForRegrade("m365", text, sigma!);
    expect(titles(rows[0].message)).toContain("M365 New Inbox Rule Created");
  });
});

describe("Azure Activity records through the importer", () => {
  const ROLE = "Microsoft.Authorization/roleAssignments/write";

  it("labels a completed role assignment (statusCode Created), not its Started event", () => {
    const done = azureRest(ROLE, { properties: { statusCode: "Created" } });
    const started = azureRest(ROLE, { status: { value: "Started" } });
    expect(titles(azure([done]).events[0].message)).toContain("Role Assignment Created");
    expect(titles(azure([started]).events[0].message)).not.toContain("Role Assignment Created");
  });

  it("reads the Log Analytics AzureActivity shape", () => {
    const la = {
      TimeGenerated: "2026-03-01T10:00:00Z",
      Caller: "admin@example.com",
      CorrelationId: "00000000-0000-0000-0000-000000000003",
      ResourceId: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg1",
      OperationNameValue: "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
      ActivityStatusValue: "Success",
      CategoryValue: "Administrative",
      Properties: JSON.stringify({ statusCode: "Created" }),
      Type: "AzureActivity",
    };
    expect(titles(azure([la]).events[0].message)).toContain("Virtual Machine Created");
  });

  it("re-grades a stored Azure Activity file", () => {
    expect(SIGMA_REGRADE_IMPORTERS.has("azure-activity")).toBe(true);
    const text = JSON.stringify([azureRest(ROLE, { properties: { statusCode: "Created" } })]);
    const rows = reparseForRegrade("azure-activity", text, sigma!);
    expect(titles(rows[0].message)).toContain("Role Assignment Created");
  });
});

// ── Coverage: every bundled rule is reached by a record built in the export's real shape ──────

type Rule = { title: string; logsource: { service: string }; detection: Record<string, unknown> };

const ruleFiles = (dir: string): Rule[] =>
  readdirSync(dir)
    .filter((f) => f.endsWith(".yml"))
    .map((f) => parseYaml(readFileSync(join(dir, f), "utf8")) as Rule);

/** A value the field's modifiers accept: the rule's own literal (first of a list), or any value for |exists. */
function sampleValue(key: string, value: unknown): unknown {
  const v = Array.isArray(value) ? value[0] : value;
  if (key.includes("|exists")) return "present";
  return v;
}

/**
 * The fields of the rule's selections (every selection except filters), one value per field:
 * `|startswith` and `|endswith` on the same field join into one value that satisfies both, the way
 * a real operation name does (MICROSOFT.NETWORK/DNSZONES + /A + /WRITE). A keyword selection (a bare
 * list) is the operation name the keyword names.
 */
function sampleFields(rule: Rule): Record<string, unknown> {
  const parts: Record<string, { start?: string; end?: string; value?: unknown }> = {};
  for (const [name, sel] of Object.entries(rule.detection)) {
    if (name === "condition" || name.startsWith("filter")) continue;
    if (Array.isArray(sel) && typeof sel[0] === "string") {
      parts.operationName = { value: sel[0] };
      continue;
    }
    const first = (Array.isArray(sel) ? sel[0] : sel) as Record<string, unknown> | string;
    if (!first || typeof first !== "object") continue;
    for (const [k, v] of Object.entries(first)) {
      const [field, ...mods] = k.split("|");
      const p = (parts[field] ??= {});
      const value = sampleValue(k, v);
      if (mods.includes("startswith")) p.start = String(value);
      else if (mods.includes("endswith")) p.end = String(value);
      else p.value = value;
    }
  }
  const out: Record<string, unknown> = {};
  for (const [field, p] of Object.entries(parts))
    out[field] = p.value ?? `${p.start ?? ""}${p.start && p.end ? "/SAMPLE" : ""}${p.end ?? ""}`;
  return out;
}

function m365Sample(rule: Rule): Row {
  const f = sampleFields(rule);
  const audit: Row = {};
  const p: Record<string, unknown> = {};
  const ext: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(f)) {
    const field = k.split("|")[0];
    if (field.startsWith("Parameters.")) p[field.slice(11)] = v;
    else if (field.startsWith("ExtendedProperties.")) ext[field.slice(19)] = v;
    else if (field !== "Operation") audit[field] = v;
  }
  const op = typeof f.Operation === "string" ? f.Operation : "UserLoggedIn";
  return ual(op, {
    ...audit,
    ...(Object.keys(p).length ? params(p) : {}),
    ...(Object.keys(ext).length
      ? { ExtendedProperties: Object.entries(ext).map(([Name, Value]) => ({ Name, Value })) }
      : {}),
  });
}

function azureSample(rule: Rule): Row {
  const f = sampleFields(rule);
  const rec: Row = azureRest("Microsoft.Resources/deployments/write");
  const props: Row = {};
  for (const [k, v] of Object.entries(f)) {
    const field = k.split("|")[0];
    if (field === "operationName" || field === "OperationNameValue")
      rec.operationName = { value: String(v), localizedValue: String(v) };
    else if (field.startsWith("properties.")) props[field.slice(11)] = v;
    else if (field === "ResourceId") rec.resourceId = `/subscriptions/0/providers/${String(v)}`;
    else if (field === "CategoryValue") rec.category = { value: v };
    else if (field === "ResourceProviderValue") rec.resourceProviderName = { value: v };
  }
  if (Object.keys(props).length) rec.properties = props;
  return rec;
}

/** Bundled rules no real-shaped record reaches. Pinned: a change here is a mapping regression. */
const UNREACHED: string[] = [];

describe("every bundled Microsoft 365 / Azure Activity rule is reachable", () => {
  const suzaku = bundledSuzakuDir()!;
  const sigmaHq = bundledSigmaDir()!;
  const cases: Array<[string, Rule, () => string | undefined]> = [
    ...ruleFiles(join(suzaku, "rules", "m365")).map((r): [string, Rule, () => string | undefined] => [
      "Suzaku M365",
      r,
      () =>
        m365([m365Sample(r)])
          .events.map((e) => e.message ?? "")
          .join("\n"),
    ]),
    ...[
      join(suzaku, "rules", "azure", "activity_logs"),
      join(sigmaHq, "rules", "cloud", "azure", "activity_logs"),
    ]
      .flatMap((d) => ruleFiles(d))
      .map((r): [string, Rule, () => string | undefined] => [
        "Azure Activity",
        r,
        () => azure([azureSample(r)]).events[0]?.message,
      ]),
  ];

  it("counts the bundled rules", () => {
    expect(cases.filter(([k]) => k === "Suzaku M365").length).toBe(21);
    expect(cases.filter(([k]) => k === "Azure Activity").length).toBe(4 + 33);
  });

  it("each rule fires on a record built in its export's real shape (except the pinned list)", () => {
    const unreached = cases.filter(([, r, run]) => !titles(run()).includes(r.title)).map(([, r]) => r.title);
    expect(unreached.sort()).toEqual([...UNREACHED].sort());
  });
});
