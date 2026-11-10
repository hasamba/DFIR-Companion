// #2542: the SANS 504 S3 ransomware lab, end to end through the CloudTrail importer with the bundled
// Sigma + Suzaku rules at default settings. The attack steps rise above the AWS-service noise; the
// noise stays out of the forensic timeline; the missing data events are said on the timeline.
import { describe, expect, it } from "vitest";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { objectLoggingEvent, LOGGING_COVERAGE_ID } from "../../src/analysis/cloudBulkRead.js";
import { isCoverageNote } from "../../src/analysis/coverageEventTime.js";
import { loadBundledSigmaRuleSet } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import type { SiemEvent } from "../../src/analysis/siemImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import { ATTACKER_KEY, CREATED_KEY, SELECTORS_AT, sans504Upload } from "./fixtures/sans504Lab.js";

const sigma = createSigmaImportGrader(loadBundledSigmaRuleSet().set).snapshot();
const result = parseCloudTrail(sans504Upload(), { sigma, aggregate: false });
const rows = result.events;

const byAction = (action: string, who?: RegExp): SiemEvent[] =>
  rows.filter((e) => e.canonical?.event.action === action && (!who || who.test(e.description)));
const one = (action: string, who?: RegExp): SiemEvent => {
  const found = byAction(action, who);
  expect(found, action).toHaveLength(1);
  return found[0];
};
const lineage = (key: string): SiemEvent | undefined =>
  rows.find((e) => e.canonical?.awsLineage?.credentialId === key);

describe("SANS 504 S3 ransomware lab (#2542)", () => {
  it("grades the self-granted *:* inline policy Critical and says it was granted to the caller itself", () => {
    const grant = one("PutUserPolicy");
    expect(grant.severity).toBe("Critical");
    expect(grant.description).toMatch(/granted to the caller itself/);
  });

  it("keeps the new access key High and raises the later versioning check to High (precursor)", () => {
    expect(one("CreateAccessKey").severity).toBe("High");
    const check = one("GetBucketVersioning", /example-user/);
    expect(check.severity).toBe("High");
    expect(check.description).toMatch(/precursor/i);
  });

  it("leaves the responder's own versioning check where it was", () => {
    expect(one("GetBucketVersioning", /\[root\]/).severity).toBe("Info");
  });

  it("keeps the attacker's denied probes Medium", () => {
    for (const a of ["ListBuckets", "DescribeInstances", "ListFunctions20150331", "DescribeLogGroups"]) {
      const denied = byAction(a).filter((e) => e.canonical?.event.outcome === "failed");
      expect(denied.length, a).toBeGreaterThan(0);
      for (const e of denied) expect(e.severity, a).toBe("Medium");
    }
  });

  it("keeps every AWS-service log-delivery row at Info", () => {
    const service = rows.filter((e) => e.canonical?.cloud?.principalType === "AWSService");
    expect(service.length).toBe(5);
    for (const e of service) expect(e.severity, e.description).toBe("Info");
  });

  it("does not raise the responder's read-only 'not found' checks", () => {
    for (const a of [
      "GetBucketPolicyStatus",
      "GetBucketPolicy",
      "GetBucketWebsite",
      "GetBucketObjectLockConfiguration",
      "GetDashboard",
      "GetInsightSelectors",
    ])
      for (const e of byAction(a)) expect(["Info", "Low"], `${a}: ${e.description}`).toContain(e.severity);
  });

  it("builds a lineage row for the key CreateAccessKey issued, chained to the key that created it", () => {
    const row = lineage(CREATED_KEY);
    expect(row).toBeDefined();
    const block = row!.canonical!.awsLineage!;
    expect(block.issuance?.action).toBe("CreateAccessKey");
    expect(block.uses.records).toBe(1);
    expect(block.chained.some((c) => c.direction === "issued-from" && c.credentialId === ATTACKER_KEY)).toBe(
      true,
    );
    expect(row!.severity).not.toBe("Info");
  });

  it("states the enumeration burst on the attacker key's High lineage row", () => {
    const row = lineage(ATTACKER_KEY)!;
    expect(row.severity).toBe("High");
    expect(row.description).toMatch(/enumeration burst: \d+ read calls/);
    expect(row.description).toMatch(/4 denied probes/);
  });

  it("puts a data-event window note on the timeline, exempt from the severity gate", () => {
    const events: ForensicEvent[] = rows.map((e, i) => ({
      id: `lab-${i}`,
      timestamp: e.timestamp,
      description: e.description,
      severity: e.severity,
      mitreTechniques: e.mitreTechniques,
      relatedFindingIds: [],
      sourceScreenshots: [],
      ...(e.canonical ? { canonical: e.canonical } : {}),
    }));
    const note = objectLoggingEvent(events);
    expect(note?.id).toBe(LOGGING_COVERAGE_ID);
    expect(isCoverageNote(note!)).toBe(true);
    expect(note!.description).toContain(SELECTORS_AT.slice(0, 19));
    expect(note!.description).toMatch(/no object-level/i);
  });

  // Q2 (user decision): a bundled rule's ATT&CK technique is withheld where CloudTrail's own reading
  // proves it does not apply. The rule line stays; a note says why; no grade moves.
  const withheld = (e: SiemEvent, t: string): void => {
    expect(
      e.mitreTechniques.some((m) => m === t || m.startsWith(`${t}.`)),
      e.description,
    ).toBe(false);
    expect(e.message ?? "", e.description).toMatch(new RegExp(`ATT&CK ${t} withheld`));
  };

  it("withholds T1565 from the AWS-service object writes, keeping the rule line", () => {
    const writes = rows.filter(
      (e) => e.canonical?.cloud?.principalType === "AWSService" && e.canonical?.event.action === "PutObject",
    );
    expect(writes.length).toBe(4);
    const cloudTrailWrites = writes.filter((e) => /cloudtrail\.amazonaws\.com/.test(e.description));
    expect(cloudTrailWrites.length).toBe(2);
    for (const e of cloudTrailWrites) {
      withheld(e, "T1565");
      expect(e.message ?? "").toMatch(/Sigma rule: /);
      expect(e.severity).toBe("Info");
    }
  });

  it("withholds T1486 from the key CloudTrail created for its logs, without moving its grade", () => {
    const key = one("CreateKey");
    withheld(key, "T1486");
    expect(key.message ?? "").toMatch(/Sigma rule: /);
    expect(key.severity).toBe("Medium");
  });

  it("grades the CloudTrail-only bucket policy Medium and withholds T1048", () => {
    const policy = one("PutBucketPolicy");
    expect(policy.severity).toBe("Medium");
    expect(policy.description).toMatch(/grants only AWS services \(cloudtrail\.amazonaws\.com\)/);
    withheld(policy, "T1048");
    expect(policy.mitreTechniques).toContain("T1530");
  });

  it("withholds T1110 from the root's single failed sign-in that a success followed", () => {
    const failed = byAction("ConsoleLogin").filter((e) => e.canonical?.event.outcome === "failed");
    expect(failed).toHaveLength(1);
    withheld(failed[0], "T1110");
    expect(failed[0].severity).toBe("High");
  });

  it("keeps the withheld rows apart from tagged ones under default aggregation", () => {
    const agg = parseCloudTrail(sans504Upload(), { sigma }).events;
    const writes = agg.filter((e) => e.canonical?.event.action === "PutObject");
    for (const e of writes)
      if (/cloudtrail\.amazonaws\.com/.test(e.description))
        expect(e.mitreTechniques.some((m) => m.startsWith("T1565"))).toBe(false);
    const logins = agg.filter((e) => e.canonical?.event.action === "ConsoleLogin");
    expect(logins.every((e) => !e.mitreTechniques.includes("T1110"))).toBe(true);
  });
});
