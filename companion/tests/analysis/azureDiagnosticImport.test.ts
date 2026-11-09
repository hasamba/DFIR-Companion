import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Azure diagnostic-settings exports (PT1H.json in a storage account, #2304). The schema is
// `time, resourceId, operationName, category, resultType, callerIpAddress, identity, properties` —
// not the REST Activity Log's. An Entra category carries the Graph sign-in / directory-audit record
// under `properties`; it must grade exactly as that Graph record does. Synthetic values only.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

interface Outcome {
  ruleIds: string[];
  severity: string;
  mitre: string[];
  timestamp: string;
  description: string;
}

function outcomes(text: string): Outcome[] {
  return parseM365Audit(text, { aggregate: false }).events.map((m, i) => {
    const event = {
      ...m,
      id: `e${i}`,
      relatedFindingIds: [],
      sourceScreenshots: [],
      mitreTechniques: m.mitreTechniques ?? [],
    } as unknown as ForensicEvent;
    const proposal = runTagger([event], RULES).perEvent[0];
    const after = proposal ? applyToForensicEvent(event, proposal) : event;
    return {
      ruleIds: [...(proposal?.ruleIds ?? [])].sort(),
      severity: after.severity,
      mitre: [...after.mitreTechniques].sort(),
      timestamp: after.timestamp,
      description: after.description,
    };
  });
}

const TENANT = "00000000-0000-4000-8000-000000000001";
const AADIAM = `/tenants/${TENANT}/providers/Microsoft.aadiam`;
const lines = (...recs: unknown[]): string => recs.map((r) => JSON.stringify(r)).join("\n");

/** A Graph `signIn` — what the Graph API and MES return, and what a PT1H record carries in `properties`. */
const graphSignIn = (over: Record<string, unknown> = {}) => ({
  id: "00000000-0000-4000-8000-000000000201",
  createdDateTime: "2026-11-01T11:01:00Z",
  userDisplayName: "Example User 1",
  userPrincipalName: "user1@example.com",
  userId: "00000000-0000-4000-8000-000000000301",
  appId: "00000000-0000-4000-8000-000000000400",
  appDisplayName: "Example App",
  ipAddress: "203.0.113.10",
  clientAppUsed: "Browser",
  correlationId: "00000000-0000-4000-8000-000000000501",
  isInteractive: true,
  riskLevelDuringSignIn: "none",
  riskState: "none",
  resourceDisplayName: "Office 365 Exchange Online",
  status: { errorCode: 50126, failureReason: "Invalid username or password." },
  location: { city: "Example City", state: "", countryOrRegion: "XX" },
  ...over,
});

/** A Graph `directoryAudit`. */
const graphAudit = (over: Record<string, unknown> = {}) => ({
  id: "Directory_00000000-0000-4000-8000-000000000c01",
  category: "ApplicationManagement",
  correlationId: "00000000-0000-4000-8000-000000000c02",
  result: "success",
  activityDisplayName: "Consent to application",
  activityDateTime: "2026-11-01T12:00:00Z",
  loggedByService: "Core Directory",
  operationType: "Assign",
  initiatedBy: { user: { userPrincipalName: "user3@example.com", ipAddress: "203.0.113.30" } },
  targetResources: [
    {
      id: "00000000-0000-4000-8000-000000000b03",
      displayName: "Example App",
      type: "ServicePrincipal",
      modifiedProperties: [
        { displayName: "ConsentContext.IsAdminConsent", oldValue: null, newValue: '"False"' },
        {
          displayName: "ConsentAction.Permissions",
          oldValue: null,
          newValue: '"Scope: Mail.Read offline_access"',
        },
      ],
    },
  ],
  ...over,
});

/** The diagnostic-settings envelope a storage account writes around one Entra record. */
const pt1h = (category: string, operationName: string, properties: Record<string, unknown>) => ({
  time: "2026-11-01T11:01:00.0000000Z",
  resourceId: AADIAM,
  operationName,
  operationVersion: "1.0",
  category,
  tenantId: TENANT,
  resultType: "50126",
  resultSignature: "None",
  durationMs: 0,
  callerIpAddress: "203.0.113.10",
  correlationId: "00000000-0000-4000-8000-000000000501",
  identity: "Example User 1",
  Level: 4,
  location: "XX",
  properties,
});

describe("PT1H.json — Entra categories grade like the Graph record they carry (#2304)", () => {
  it("SignInLogs is routed to the M365/Entra importer", () => {
    expect(detectImportKind("PT1H.json", lines(pt1h("SignInLogs", "Sign-in activity", graphSignIn())))).toBe(
      "m365",
    );
  });

  it("SignInLogs: same rules, severity, MITRE, time, user, IP and detail as the Graph signIn", () => {
    const fromPt1h = outcomes(lines(pt1h("SignInLogs", "Sign-in activity", graphSignIn())));
    expect(fromPt1h).toEqual(outcomes(JSON.stringify([graphSignIn()])));
    const [o] = fromPt1h;
    expect(o.severity).toBe("Medium");
    expect(o.mitre).toEqual(["T1078.004", "T1110"]);
    expect(o.timestamp).toBe("2026-11-01T11:01:00Z");
    expect(o.description).toBe(
      "Entra sign-in: [interactive] user1@example.com from 203.0.113.10 (Example City, XX) via Example App [FAILED 50126: Invalid username or password.]",
    );
  });

  it("NonInteractiveUserSignInLogs grades like the Graph signIn too", () => {
    const rec = pt1h(
      "NonInteractiveUserSignInLogs",
      "Sign-in activity",
      graphSignIn({ isInteractive: false }),
    );
    expect(detectImportKind("PT1H.json", lines(rec))).toBe("m365");
    expect(outcomes(lines(rec))).toEqual(outcomes(JSON.stringify([graphSignIn({ isInteractive: false })])));
  });

  it("the Graph fields the record leaves out come from the envelope: time, IP and outcome", () => {
    const bare = graphSignIn({ createdDateTime: undefined, ipAddress: undefined, status: undefined });
    const [o] = outcomes(lines(pt1h("SignInLogs", "Sign-in activity", bare)));
    expect(Date.parse(o.timestamp)).toBe(Date.parse("2026-11-01T11:01:00Z"));
    expect(o.description).toContain("from 203.0.113.10");
    expect(o.description).toContain("[FAILED 50126");
    expect(o.severity).toBe("Medium");
  });

  it("a top-level errorCode in `properties` beats a conflicting envelope resultType (Codex #2304)", () => {
    const props = graphSignIn({ status: undefined, errorCode: 50126 });
    const rec = { ...pt1h("SignInLogs", "Sign-in activity", props), resultType: "0", resultDescription: "" };
    const bare = outcomes(JSON.stringify([props]));
    const [o] = outcomes(lines(rec));
    expect(o).toEqual(bare[0]);
    expect(o.severity).toBe("Medium");
    expect(o.mitre).toEqual(["T1078.004", "T1110"]);
    expect(o.description).toContain("[FAILED 50126");
  });

  it("a partial `status` keeps its own code and only takes a missing reason from the envelope", () => {
    const props = graphSignIn({ status: { errorCode: 50126 } });
    const rec = {
      ...pt1h("SignInLogs", "Sign-in activity", props),
      resultType: "0",
      resultDescription: "Other",
    };
    const [o] = outcomes(lines(rec));
    expect(o.severity).toBe("Medium");
    expect(o.description).toContain("[FAILED 50126");
  });

  it("a differently-cased property is never overridden by the envelope's spelling", () => {
    const { createdDateTime: _c, ipAddress: _i, ...base } = graphSignIn();
    const props = { ...base, CreatedDateTime: "2026-11-01T09:00:00Z", IPAddress: "198.51.100.77" };
    const rec = { ...pt1h("SignInLogs", "Sign-in activity", props), callerIpAddress: "203.0.113.99" };
    const [o] = outcomes(lines(rec));
    expect(o).toEqual(outcomes(JSON.stringify([props]))[0]);
    expect(o.timestamp).toBe("2026-11-01T09:00:00Z");
    expect(o.description).toContain("from 198.51.100.77");
    expect(o.description).not.toContain("203.0.113.99");
  });

  it("an audit record's differently-cased time is never overridden by the envelope's", () => {
    const { activityDateTime: _a, ...base } = graphAudit();
    const props = { ...base, ActivityDateTime: "2026-11-01T08:00:00Z" };
    const rec = { ...pt1h("AuditLogs", "Consent to application", props), resultType: "" };
    expect(outcomes(lines(rec))).toEqual(outcomes(JSON.stringify([props])));
  });

  it("the legacy `{ records: [...] }` wrapper reads the same", () => {
    const text = JSON.stringify({ records: [pt1h("SignInLogs", "Sign-in activity", graphSignIn())] });
    expect(detectImportKind("PT1H.json", text)).toBe("m365");
    expect(outcomes(text)).toEqual(outcomes(JSON.stringify([graphSignIn()])));
  });

  it("AuditLogs: a consent grades like the Graph directoryAudit, with the consent rule", () => {
    const rec = { ...pt1h("AuditLogs", "Consent to application", graphAudit()), resultType: "" };
    expect(detectImportKind("PT1H.json", lines(rec))).toBe("m365");
    const fromPt1h = outcomes(lines(rec));
    expect(fromPt1h).toEqual(outcomes(JSON.stringify([graphAudit()])));
    expect(fromPt1h[0].ruleIds).toContain("ts_entra_oauth_consent_granted");
    expect(fromPt1h[0].description).toMatch(/^Entra audit: Consent to application\b/);
    expect(fromPt1h[0].timestamp).toBe("2026-11-01T12:00:00Z");
  });

  it("ServicePrincipalSignInLogs maps to a service-principal sign-in", () => {
    const sp = {
      id: "00000000-0000-4000-8000-000000000d01",
      createdDateTime: "2026-11-01T11:05:00Z",
      appId: "00000000-0000-4000-8000-000000000400",
      appDisplayName: "Example App",
      servicePrincipalId: "00000000-0000-4000-8000-000000000d02",
      servicePrincipalName: "Example App",
      ipAddress: "203.0.113.50",
      resourceDisplayName: "Microsoft Graph",
      status: { errorCode: 0 },
    };
    const text = lines({ ...pt1h("ServicePrincipalSignInLogs", "Sign-in activity", sp), resultType: "0" });
    expect(detectImportKind("PT1H.json", text)).toBe("m365");
    expect(outcomes(text)).toEqual(outcomes(JSON.stringify([sp])));
    expect(outcomes(text)[0].timestamp).toBe("2026-11-01T11:05:00Z");
  });
});

describe("PT1H.json — detection stays discriminating (#2304)", () => {
  it("a SignInLogs-category record that is not from Entra (no aadiam resourceId) is not claimed as m365", () => {
    const rec = {
      ...pt1h("SignInLogs", "Sign-in activity", graphSignIn()),
      resourceId: "/subscriptions/x/rg/y",
    };
    expect(detectImportKind("PT1H.json", lines(rec))).toBe("cloud");
  });

  it("an aadiam record without a `properties` object is not claimed as m365", () => {
    const { properties: _p, ...rec } = pt1h("SignInLogs", "Sign-in activity", graphSignIn());
    expect(detectImportKind("PT1H.json", lines(rec))).toBe("cloud");
  });

  it("an Entra category the M365 importer does not read (ProvisioningLogs) is not claimed", () => {
    expect(
      detectImportKind("PT1H.json", lines(pt1h("ProvisioningLogs", "Process escrow", { id: "p1" }))),
    ).toBe("cloud");
  });
});

// The Activity Log through diagnostic settings: `identity.claims` instead of REST's `caller`.
const ADMIN_PT1H = {
  time: "2026-11-01T13:00:00.0000000Z",
  resourceId:
    "/SUBSCRIPTIONS/00000000-0000-4000-8000-000000000700/RESOURCEGROUPS/RG1/PROVIDERS/MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/00000000-0000-4000-8000-000000000e01",
  operationName: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
  category: "Administrative",
  resultType: "Success",
  resultSignature: "Succeeded.Created",
  durationMs: 1200,
  callerIpAddress: "203.0.113.60",
  correlationId: "00000000-0000-4000-8000-000000000e02",
  identity: {
    authorization: {
      scope: "/subscriptions/00000000-0000-4000-8000-000000000700",
      action: "Microsoft.Authorization/roleAssignments/write",
    },
    claims: {
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "admin@example.com",
      name: "Example Admin",
      appid: "00000000-0000-4000-8000-000000000400",
    },
  },
  level: "Information",
  properties: {
    statusCode: "Created",
    eventCategory: "Administrative",
    message: "Microsoft.Authorization/roleAssignments/write",
  },
};

const ADMIN_REST = {
  eventTimestamp: "2026-11-01T13:00:00Z",
  operationName: { value: "Microsoft.Authorization/roleAssignments/write" },
  caller: "admin@example.com",
  httpRequest: { clientIpAddress: "203.0.113.60" },
  resourceId: ADMIN_PT1H.resourceId,
  correlationId: ADMIN_PT1H.correlationId,
  status: { value: "Succeeded" },
};

describe("PT1H.json — Activity categories import like the REST Activity Log (#2304)", () => {
  it("an Administrative record stays with the cloud importer", () => {
    expect(detectImportKind("PT1H.json", lines(ADMIN_PT1H))).toBe("cloud");
  });

  it("the caller is the UPN claim, as REST's `caller` is, and the grade matches the REST record", () => {
    const [pt] = parseCloudActivity(lines(ADMIN_PT1H), { aggregate: false }).events;
    const [rest] = parseCloudActivity(JSON.stringify([ADMIN_REST]), { aggregate: false }).events;
    expect(pt.description).toContain("by admin@example.com from 203.0.113.60");
    expect(Date.parse(pt.timestamp)).toBe(Date.parse(rest.timestamp));
    expect(pt.severity).toBe(rest.severity);
    expect(pt.mitreTechniques).toEqual(rest.mitreTechniques);
    expect(pt.description.toLowerCase()).toBe(rest.description.toLowerCase());
  });

  it("an app caller with no UPN claim falls back to its app id", () => {
    const claims = { appid: "00000000-0000-4000-8000-000000000400", name: "Example App" };
    const rec = { ...ADMIN_PT1H, identity: { ...ADMIN_PT1H.identity, claims } };
    const [e] = parseCloudActivity(lines(rec), { aggregate: false }).events;
    expect(e.description).toContain("by 00000000-0000-4000-8000-000000000400");
  });
});
