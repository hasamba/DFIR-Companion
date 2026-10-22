import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";

// Import-time Sigma grading through the real importers and the bundled SigmaHQ rules (#2202).
// Records are synthetic and shaped like the exports the importers already accept.

const { set } = loadBundledSigmaRuleSet();
const sigma = createSigmaImportGrader(set).snapshot();

const trail = (records: object[]) => JSON.stringify({ Records: records });

const ct = (o: Record<string, unknown>) => ({
  eventVersion: "1.08",
  eventTime: "2026-03-01T10:00:00Z",
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
  readOnly: false,
  eventID: `id-${Math.random()}`,
  ...o,
});

describe("CloudTrail with import-time Sigma", () => {
  it("raises a hand-graded Low row to High when a high rule matches", () => {
    const rec = ct({ eventSource: "securityhub.amazonaws.com", eventName: "BatchUpdateFindings" });
    const without = parseCloudTrail(trail([rec]));
    const withSigma = parseCloudTrail(trail([rec]), { sigma });
    expect(without.events[0].severity).not.toBe("High");
    expect(withSigma.events).toHaveLength(1);
    expect(withSigma.events[0].severity).toBe("High");
    expect(withSigma.events[0].description).toMatch(/^Sigma: AWS SecurityHub Findings Evasion - /);
    expect(withSigma.events[0].message).toMatch(
      /author .+, SigmaHQ r2026-07-01, https:\/\/github\.com\/SigmaHQ\/sigma\/blob\//,
    );
  });

  it("keeps StopLogging as ONE High event and tags it with the medium rule", () => {
    const rec = ct({ eventSource: "cloudtrail.amazonaws.com", eventName: "StopLogging" });
    const r = parseCloudTrail(trail([rec]), { sigma });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].description).toMatch(
      /^Sigma \(medium, tag only\): AWS CloudTrail Important Change - /,
    );
    expect(r.events[0].mitreTechniques).toContain("T1562.008");
  });

  it("stamps the grading snapshot on every graded event, matched or not (#2204)", () => {
    const rec = ct({ eventSource: "s3.amazonaws.com", eventName: "ListBuckets", readOnly: true });
    const r = parseCloudTrail(trail([rec]), { sigma });
    expect(r.events[0].canonical?.producer.ruleVersions).toContain(sigma?.token);
    expect(sigma?.token).toMatch(/^sigma:r2026-07-01:[0-9a-f]{12}:stable\+test:high:[0-9a-f]{8}:none$/);
    expect(r.sigmaRowsMatched).toBe(0);
  });

  it("is the pre-#2202 output exactly when no rule matches, or no grader is given", () => {
    const rec = ct({ eventSource: "s3.amazonaws.com", eventName: "ListBuckets", readOnly: true });
    const a = parseCloudTrail(trail([rec]));
    const b = parseCloudTrail(trail([rec]), { sigma });
    expect(b.events.map((e) => [e.description, e.severity, e.mitreTechniques])).toEqual(
      a.events.map((e) => [e.description, e.severity, e.mitreTechniques]),
    );
  });

  it("does nothing while the grader is switched off", () => {
    const off = createSigmaImportGrader(set, { enabled: () => false }).snapshot();
    expect(off).toBeUndefined();
    const rec = ct({ eventSource: "securityhub.amazonaws.com", eventName: "BatchUpdateFindings" });
    expect(parseCloudTrail(trail([rec]), { sigma: off }).events[0].description).not.toMatch(/Sigma/);
  });

  describe("cross-account replicas", () => {
    // One CreateUser seen from both accounts. Only the OWNER's replica (not kept by the merge)
    // carries the S3 Browser user agent the rule needs.
    const kept = ct({ eventSource: "iam.amazonaws.com", eventName: "CreateUser", sharedEventID: "shared-1" });
    const other = ct({
      eventSource: "iam.amazonaws.com",
      eventName: "CreateUser",
      sharedEventID: "shared-1",
      recipientAccountId: "222222222222",
      userIdentity: { type: "AWSAccount", accountId: "111111111111" },
      userAgent: "S3 Browser 11.5.7 https://s3browser.com",
    });

    for (const [label, order] of [
      ["kept first", [kept, other]],
      ["kept second", [other, kept]],
    ] as const) {
      it(`keeps a match found only on the replica the merge drops (${label})`, () => {
        const r = parseCloudTrail(trail([...order]), { sigma });
        expect(r.events).toHaveLength(1);
        expect(r.events[0].severity).toBe("High");
        expect(r.events[0].description).toMatch(/^Sigma: AWS IAM S3Browser User or AccessKey Creation/);
      });
    }
  });
});

describe("Entra with import-time Sigma", () => {
  const signIn = (o: Record<string, unknown>) => ({
    id: `s-${Math.random()}`,
    createdDateTime: "2026-03-01T10:00:00Z",
    userPrincipalName: "alice@example.test",
    appDisplayName: "Azure Portal",
    ipAddress: "198.51.100.7",
    clientAppUsed: "Browser",
    userAgent: "Mozilla/5.0",
    status: { errorCode: 0 },
    deviceDetail: { isCompliant: false, trustType: "" },
    location: { city: "Paris", countryOrRegion: "FR" },
    ...o,
  });
  const audit = (o: Record<string, unknown>) => ({
    id: `a-${Math.random()}`,
    activityDateTime: "2026-03-01T10:00:00Z",
    category: "Policy",
    result: "success",
    loggedByService: "Core Directory",
    initiatedBy: { user: { userPrincipalName: "alice@example.test" } },
    targetResources: [{ id: "t1", displayName: "Device Registration Policy", type: "Policy" }],
    ...o,
  });
  const graph = (rows: object[]) => JSON.stringify({ value: rows });

  it("grades an AzureHound sign-in High", () => {
    const r = parseM365Audit(graph([signIn({ userAgent: "azurehound/v2.1.0" })]), { sigma });
    expect(r.events).toHaveLength(1);
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].description).toMatch(/^Sigma: Discovery Using AzureHound - /);
  });

  it("leaves an ordinary successful sign-in from an unmanaged device untagged", () => {
    const r = parseM365Audit(graph([signIn({})]), { sigma });
    expect(r.events[0].description).not.toMatch(/Sigma/);
  });

  it("tags an account lockout (medium) without grading it", () => {
    const r = parseM365Audit(
      graph([signIn({ status: { errorCode: 50053, failureReason: "Account is locked" } })]),
      { sigma },
    );
    expect(r.events[0].description).toMatch(/^Sigma \(medium, tag only\): Account Lockout - /);
  });

  it("grades a Graph directory-audit record by its activity name", () => {
    const r = parseM365Audit(graph([audit({ activityDisplayName: "Set device registration policies" })]), {
      sigma,
    });
    expect(r.events[0].severity).toBe("High");
    expect(r.events[0].description).toMatch(/^Sigma: Changes to Device Registration Policy - /);
  });

  it("leaves a routine guest invitation untagged", () => {
    const r = parseM365Audit(
      graph([audit({ category: "UserManagement", activityDisplayName: "Invite external user" })]),
      { sigma },
    );
    expect(r.events.every((e) => !/Sigma/.test(e.description))).toBe(true);
  });
});
