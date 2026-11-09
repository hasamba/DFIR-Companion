// #2350 — import-time Sigma puts its head at the START of a row's description ("Sigma: <title> - "
// or "Sigma (<level>, not graded): <title> - "), and the cloud tagger rules are anchored on the
// importer's own prefix ("^AWS ModifySnapshotAttribute (", "^Entra audit:", "^Entra sign-in:").
// The tagger must still match those rules on a Sigma-matched row, through the real importers, the
// bundled Sigma rules and the SHIPPED tags.yaml — and in the streamed pre-grade too.
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import { createPreGrader } from "../../src/analysis/cloudStreamPreGrade.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { parseM365Audit } from "../../src/analysis/m365Import.js";
import { bundledSigmaDir, loadSigmaRuleDir } from "../../src/analysis/sigmaBundledRules.js";
import { createSigmaImportGrader } from "../../src/analysis/sigmaImportGrade.js";
import type { MappedEvent, SiemEvent } from "../../src/analysis/siemImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);
// SigmaHQ alone: these heads are SigmaHQ rules (a Suzaku rule may grade the same record, #2499).
const sigma = createSigmaImportGrader(loadSigmaRuleDir(bundledSigmaDir()!)).snapshot();

function tagged(e: SiemEvent) {
  const event = { ...e, id: "e0", relatedFindingIds: [], sourceScreenshots: [] } as unknown as ForensicEvent;
  return runTagger([event], RULES).perEvent[0] ?? { ruleIds: [], mitre: [], severity: undefined };
}

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
const snapshotShare = ct({
  eventSource: "ec2.amazonaws.com",
  eventName: "ModifySnapshotAttribute",
  requestParameters: {
    snapshotId: "snap-0123456789abcdef0",
    attributeType: "CREATE_VOLUME_PERMISSION",
    createVolumePermission: { add: { items: [{ group: "all" }] } },
  },
});
const createAccessKey = ct({
  eventSource: "iam.amazonaws.com",
  eventName: "CreateAccessKey",
  requestParameters: { userName: "bob" },
});

const graph = (rows: object[]) => JSON.stringify({ value: rows });
const signIn = (userAgent: string) => ({
  id: `s-${Math.random()}`,
  createdDateTime: "2026-03-01T10:00:00Z",
  userPrincipalName: "alice@example.test",
  appDisplayName: "Azure Portal",
  ipAddress: "198.51.100.7",
  clientAppUsed: "Browser",
  userAgent,
  status: { errorCode: 0 },
  deviceDetail: { isCompliant: false, trustType: "" },
  location: { city: "Paris", countryOrRegion: "FR" },
});
const audit = (activityDisplayName: string) => ({
  id: `a-${Math.random()}`,
  activityDateTime: "2026-03-01T10:00:00Z",
  activityDisplayName,
  category: "ApplicationManagement",
  result: "success",
  loggedByService: "Core Directory",
  initiatedBy: { user: { userPrincipalName: "alice@example.test" } },
  targetResources: [{ id: "t1", displayName: "app1", type: "ServicePrincipal" }],
});

const one = (events: SiemEvent[]): SiemEvent => {
  expect(events).toHaveLength(1);
  return events[0];
};

describe("tagger rules match regardless of the import-time Sigma head (#2350)", () => {
  it("cloud_aws_snapshot_shared on a public snapshot share with a Sigma match: tag, T1537, High", () => {
    const row = one(parseCloudTrail(trail([snapshotShare]), { sigma }).events);
    expect(row.description).toMatch(/^Sigma /);
    const t = tagged(row);
    expect(t.ruleIds).toContain("cloud_aws_snapshot_shared");
    expect(t.mitre).toContain("T1537");
    expect(t.severity).toBe("High");
  });

  it("ts_aws_iam_persistence on CreateAccessKey with a Sigma match", () => {
    const row = one(parseCloudTrail(trail([createAccessKey]), { sigma }).events);
    expect(row.description).toMatch(/^Sigma /);
    expect(tagged(row).ruleIds).toContain("ts_aws_iam_persistence");
  });

  it("ts_entra_service_principal_created on an Entra 'Add service principal' audit with a Sigma match", () => {
    const row = one(parseM365Audit(graph([audit("Add service principal")]), { sigma }).events);
    expect(row.description).toMatch(/^Sigma /);
    expect(tagged(row).ruleIds).toContain("ts_entra_service_principal_created");
  });

  it("mas_user_agent_offensive_tool on an AzureHound sign-in with a Sigma match", () => {
    const row = one(parseM365Audit(graph([signIn("azurehound/v2.1.0")]), { sigma }).events);
    expect(row.description).toMatch(/^Sigma: Discovery Using AzureHound - /);
    expect(tagged(row).ruleIds).toContain("mas_user_agent_offensive_tool");
  });

  it("does not strip a description that merely starts with 'Sigma:' and carries no Sigma rule line", () => {
    const plain = one(parseCloudTrail(trail([snapshotShare])).events);
    const forged = { ...plain, description: `Sigma: x - ${plain.description}`, message: "no rule here" };
    expect(tagged(forged).ruleIds).not.toContain("cloud_aws_snapshot_shared");
    // A "Sigma rule:" line whose title is not the head's title does not strip it either.
    const mismatched = {
      ...forged,
      message: "Sigma rule: Other Title [abc-123] — level medium, status test",
    };
    expect(tagged(mismatched).ruleIds).not.toContain("cloud_aws_snapshot_shared");
  });
});

describe("streamed cloud pre-grade sees past the Sigma head (#2350)", () => {
  it("raises an Info row with a tag-only Sigma head that a High tagger rule matches", () => {
    const row = one(parseCloudTrail(trail([snapshotShare]), { sigma }).events);
    expect(row.description).toMatch(/^Sigma /);
    const info: MappedEvent = {
      timestamp: row.timestamp,
      description: row.description,
      severity: "Info",
      mitre: [],
      aggKey: "k",
      ...(row.message ? { message: row.message } : {}),
    };
    const { rows, raised } = createPreGrader(RULES).grade([info]);
    expect(raised).toBe(1);
    expect(rows[0].severity).toBe("High");
    expect(rows[0].mitre).toContain("T1537");
  });
});
