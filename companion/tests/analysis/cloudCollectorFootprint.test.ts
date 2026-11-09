import { describe, expect, it, vi } from "vitest";
import {
  COLLECTOR_AUTHOR_PREFIX,
  COLLECTOR_LABEL,
  COLLECTOR_SPAN_SKEW_MS,
  collectorFootprintTags,
  collectorRunFor,
  isCollectorNote,
  tagCollectorFootprint,
  type CollectorRun,
} from "../../src/analysis/cloudCollectorFootprint.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const ROLE_CALLER = "arn:aws:sts::111122223333:assumed-role/dfir-companion-read/dfir-companion-collect";
const START = "2026-11-05T10:00:00.000Z";
const END = "2026-11-05T10:30:00.000Z";

function run(over: Partial<CollectorRun> = {}, caller = ROLE_CALLER): CollectorRun {
  return {
    collectionId: "cc-20261105t100000-aaaaaaaa",
    provider: "aws",
    spans: [{ from: START, to: END, caller }],
    ...over,
  };
}

let seq = 0;
function awsRow(over: {
  action?: string;
  at?: string;
  end?: string;
  issuer?: string;
  principalId?: string;
  accountId?: string;
  actorName?: string;
  type?: string;
}): ForensicEvent {
  return {
    id: `r${++seq}`,
    timestamp: over.at ?? "2026-11-05T10:10:00.000Z",
    ...(over.end ? { endTimestamp: over.end } : {}),
    description: "AWS call",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: {
      schemaVersion: 1,
      event: { category: "cloud", type: over.type ?? "api", action: over.action ?? "DescribeRegions" },
      actor: { kind: "cloud_principal", name: over.actorName ?? "dfir-companion-read" },
      authentication: {
        issuer: over.issuer ?? "arn:aws:iam::111122223333:role/dfir-companion-read",
      },
      cloud: {
        provider: "aws",
        principalId: over.principalId ?? "AROAEXAMPLEID:dfir-companion-collect",
        accountId: over.accountId ?? "111122223333",
      },
    },
  } as unknown as ForensicEvent;
}

function cloudRow(provider: string, action: string, actor: { name?: string; id?: string }, at?: string) {
  return {
    id: `r${++seq}`,
    timestamp: at ?? "2026-11-05T10:10:00.000Z",
    description: "cloud call",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: {
      schemaVersion: 1,
      event: {
        category: "cloud",
        type:
          provider === "gcp" ? "api-call" : provider === "azure" ? "activity-operation" : "audit-operation",
        action,
      },
      actor: { kind: "account", ...actor },
      cloud: { provider },
    },
  } as unknown as ForensicEvent;
}

describe("collectorRunFor — AWS assumed role", () => {
  it("tags a collector read by the collector's role session inside the run", () => {
    expect(collectorRunFor(awsRow({}), [run()])).toBe("cc-20261105t100000-aaaaaaaa");
  });

  it("does not tag the same identity outside every run (acceptance)", () => {
    expect(collectorRunFor(awsRow({ at: "2026-11-05T11:30:00.000Z" }), [run()])).toBeNull();
    expect(collectorRunFor(awsRow({ at: "2026-11-05T09:00:00.000Z" }), [run()])).toBeNull();
  });

  it("allows the clock-skew slack on both sides, and no more", () => {
    const justBefore = new Date(Date.parse(START) - COLLECTOR_SPAN_SKEW_MS + 1000).toISOString();
    const justAfter = new Date(Date.parse(END) + COLLECTOR_SPAN_SKEW_MS - 1000).toISOString();
    const tooLate = new Date(Date.parse(END) + COLLECTOR_SPAN_SKEW_MS + 1000).toISOString();
    expect(collectorRunFor(awsRow({ at: justBefore }), [run()])).not.toBeNull();
    expect(collectorRunFor(awsRow({ at: justAfter }), [run()])).not.toBeNull();
    expect(collectorRunFor(awsRow({ at: tooLate }), [run()])).toBeNull();
  });

  it("does not tag an aggregate that reaches outside the run", () => {
    expect(collectorRunFor(awsRow({ end: "2026-11-05T12:00:00.000Z" }), [run()])).toBeNull();
    expect(collectorRunFor(awsRow({ end: "2026-11-05T10:20:00.000Z" }), [run()])).not.toBeNull();
  });

  it("leaves every write and every read outside the collector's own set untagged", () => {
    for (const action of ["CreateAccessKey", "PutBucketPolicy", "StopLogging", "GetSecretValue", "ListUsers"])
      expect(collectorRunFor(awsRow({ action }), [run()]), action).toBeNull();
    for (const action of ["LookupEvents", "GetCallerIdentity", "GetObject", "ListObjects", "GetFindings"])
      expect(collectorRunFor(awsRow({ action }), [run()]), action).not.toBeNull();
  });

  it("requires the collector's session, role and account", () => {
    // Another session of the same role (the read check, another investigator, an attacker).
    expect(
      collectorRunFor(awsRow({ principalId: "AROAEXAMPLEID:dfir-companion-read-check" }), [run()]),
    ).toBeNull();
    expect(
      collectorRunFor(awsRow({ issuer: "arn:aws:iam::111122223333:role/other-role" }), [run()]),
    ).toBeNull();
    expect(
      collectorRunFor(awsRow({ issuer: "arn:aws:iam::999999999999:role/dfir-companion-read" }), [run()]),
    ).toBeNull();
    // A role with a path still matches the assumed-role ARN, which drops the path.
    expect(
      collectorRunFor(awsRow({ issuer: "arn:aws:iam::111122223333:role/ops/dfir-companion-read" }), [run()]),
    ).not.toBeNull();
  });

  it("never tags a summary row (lineage, compute lifecycle)", () => {
    for (const type of ["credential-lineage", "compute-lifecycle", "privilege-path", "service-account-join"])
      expect(collectorRunFor(awsRow({ type }), [run()]), type).toBeNull();
  });

  it("ignores a row with no canonical envelope or no time", () => {
    const bare = { ...awsRow({}), canonical: undefined } as unknown as ForensicEvent;
    expect(collectorRunFor(bare, [run()])).toBeNull();
    expect(collectorRunFor({ ...awsRow({}), timestamp: "" }, [run()])).toBeNull();
  });
});

describe("collectorRunFor — other identities", () => {
  it("AWS IAM user: user name and account", () => {
    const r = run({}, "arn:aws:iam::111122223333:user/ops/dfir-reader");
    const user = awsRow({ actorName: "dfir-reader", issuer: "", principalId: "AIDAEXAMPLE" });
    const noIssuer = {
      ...user,
      canonical: { ...user.canonical!, authentication: undefined },
    } as ForensicEvent;
    expect(collectorRunFor(noIssuer, [r])).not.toBeNull();
    const otherAcct = awsRow({ actorName: "dfir-reader", accountId: "999999999999" });
    expect(
      collectorRunFor({ ...otherAcct, canonical: { ...otherAcct.canonical!, authentication: undefined } }, [
        r,
      ]),
    ).toBeNull();
  });

  it("Microsoft: the app id as a whole token in the actor", () => {
    const appId = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
    const r = run({ provider: "microsoft" }, appId);
    expect(
      collectorRunFor(cloudRow("m365", "AuditSearchCreated", { name: appId.toUpperCase() }), [r]),
    ).not.toBeNull();
    expect(
      collectorRunFor(cloudRow("m365", "AuditSearchCompleted", { name: `ServicePrincipal_${appId}` }), [r]),
    ).not.toBeNull();
    expect(
      collectorRunFor(cloudRow("m365", "AuditSearchCreated", { name: "someone@contoso.example" }), [r]),
    ).toBeNull();
    expect(collectorRunFor(cloudRow("m365", "AuditSearchCreated", { name: `${appId}0` }), [r])).toBeNull();
    // A write by the app is never tagged.
    expect(collectorRunFor(cloudRow("m365", "Add service principal.", { name: appId }), [r])).toBeNull();
  });

  it("GCP: the service-account email, qualified methods kept whole", () => {
    const sa = "dfir-collector@proj.iam.gserviceaccount.com";
    const r = run({ provider: "gcp" }, sa);
    expect(
      collectorRunFor(
        cloudRow("gcp", "google.logging.v2.LoggingServiceV2.ListLogEntries", { name: sa.toUpperCase() }),
        [r],
      ),
    ).not.toBeNull();
    expect(collectorRunFor(cloudRow("gcp", "storage.objects.get", { name: sa }), [r])).not.toBeNull();
    expect(collectorRunFor(cloudRow("gcp", "v1.compute.instances.get", { name: sa }), [r])).toBeNull();
    expect(collectorRunFor(cloudRow("gcp", "SetIamPolicy", { name: sa }), [r])).toBeNull();
    expect(
      collectorRunFor(
        cloudRow("gcp", "storage.objects.get", { name: "other@proj.iam.gserviceaccount.com" }),
        [r],
      ),
    ).toBeNull();
  });

  it("an unusable caller matches nothing", () => {
    expect(collectorRunFor(awsRow({}), [run({}, "unknown")])).toBeNull();
    expect(collectorRunFor(awsRow({}), [run({}, "arn:aws:iam::111122223333:root")])).toBeNull();
  });

  it("matches across collections: the earliest-started matching run names the tag", () => {
    const later = run({
      collectionId: "cc-20261105t101500-bbbbbbbb",
      spans: [{ from: "2026-11-05T10:05:00.000Z", to: END, caller: ROLE_CALLER }],
    });
    expect(collectorRunFor(awsRow({}), [later, run()])).toBe("cc-20261105t100000-aaaaaaaa");
  });
});

describe("collectorFootprintTags / tagCollectorFootprint", () => {
  it("writes one tagger-authored tag per matched row and changes no row", async () => {
    const rows = [
      awsRow({}),
      awsRow({ action: "CreateAccessKey" }),
      awsRow({ at: "2026-11-06T00:00:00.000Z" }),
    ];
    const before = JSON.stringify(rows);
    const tags = collectorFootprintTags(rows, [run()]);
    expect(tags).toEqual([
      {
        targetType: "event",
        targetId: rows[0].id,
        label: COLLECTOR_LABEL,
        author: `${COLLECTOR_AUTHOR_PREFIX}cc-20261105t100000-aaaaaaaa`,
      },
    ]);
    expect(tags[0].author.startsWith("tagger:")).toBe(true); // never protects a row from the cap
    const addMany = vi.fn(async (_c: string, inputs: readonly unknown[]) => inputs);
    const onTags = vi.fn();
    const n = await tagCollectorFootprint(
      { tags: { addMany }, runsFor: async () => [run()], onTags },
      "c1",
      rows,
    );
    expect(n).toBe(1);
    expect(addMany).toHaveBeenCalledTimes(1);
    expect(onTags).toHaveBeenCalledWith("c1");
    expect(JSON.stringify(rows)).toBe(before); // grade, MITRE, origin untouched
  });

  it("never throws: a failing run reader or tag store is logged", async () => {
    const logLine = vi.fn();
    const addMany = vi.fn(async () => []);
    expect(
      await tagCollectorFootprint(
        { tags: { addMany }, runsFor: async () => Promise.reject(new Error("boom")), logLine },
        "c1",
        [awsRow({})],
      ),
    ).toBe(0);
    expect(logLine).toHaveBeenCalled();
    expect(addMany).not.toHaveBeenCalled();
  });

  it("reads no runs when no row could match", async () => {
    const runsFor = vi.fn(async () => [run()]);
    const addMany = vi.fn(async () => []);
    await tagCollectorFootprint({ tags: { addMany }, runsFor }, "c1", []);
    expect(runsFor).not.toHaveBeenCalled();
  });

  it("names the note an author carries", () => {
    expect(isCollectorNote(`${COLLECTOR_AUTHOR_PREFIX}cc-1`)).toBe(true);
    expect(isCollectorNote("tagger:aws-recon")).toBe(false);
  });
});
