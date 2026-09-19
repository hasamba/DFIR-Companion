import { describe, it, expect } from "vitest";
import { cleanDescription } from "../../src/analysis/correlate.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  readCloudRecord,
  splitResource,
  clientFromDescription,
  groupBulkReads,
  roleAssumptions,
  assumptionFor,
  gradeGroup,
  summarizeBulkReads,
  legacySummaryId,
  summaryHead,
  summaryId,
  objectLoggingNote,
  MIN_OBJECTS,
  MIN_CONTAINERS,
  MAX_RECORDS_PER_GROUP,
  recurringPrincipals,
  roleSegment,
  type BulkGroup,
} from "../../src/analysis/cloudBulkRead.js";
import { emptyState, type ForensicEvent } from "../../src/analysis/stateTypes.js";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import type { AnalysisDelta } from "../../src/analysis/responseSchema.js";

let seq = 0;
const at = (min: number) => new Date(Date.parse("2026-01-01T10:00:00Z") + min * 60000).toISOString();

/** A cloud read event as an importer that stamps the canonical envelope produces it. */
const ROLE_PRINCIPAL = "arn:aws:sts::123456789012:assumed-role/app-role/i-0abc123def456789";

const read = (over: {
  action?: string;
  principal?: string;
  ip?: string;
  resource?: string;
  min?: number;
  description?: string;
  outcome?: string;
}): ForensicEvent =>
  ({
    id: `e${++seq}`,
    timestamp: at(over.min ?? 0),
    description: over.description ?? "AWS GetObject (s3) by app-role from 10.0.1.5",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: {
      event: { action: over.action ?? "GetObject", outcome: over.outcome },
      actor: { name: over.principal ?? ROLE_PRINCIPAL },
      cloud: { resource: over.resource ?? "corp-data/report.pdf" },
      network: { source: { address: over.ip ?? "10.0.1.5" } },
    },
  }) as unknown as ForensicEvent;

const manyReads = (n: number, over: Parameters<typeof read>[0] = {}) =>
  Array.from({ length: n }, (_v, i) =>
    read({ ...over, resource: `corp-data/file-${i}.csv`, min: (over.min ?? 0) + i * 0.01 }),
  );

describe("readCloudRecord", () => {
  it("reads an object read out of the canonical envelope", () => {
    const r = readCloudRecord(read({}));
    expect(r?.principal).toBe(ROLE_PRINCIPAL);
    expect(r?.container).toBe("corp-data");
    expect(r?.object).toBe("report.pdf");
  });

  it("ignores an action that is not a read", () => {
    expect(readCloudRecord(read({ action: "PutObject" }))).toBeNull();
    expect(readCloudRecord(read({ action: "DeleteBucket" }))).toBeNull();
  });

  it("ignores an event whose time cannot be read", () => {
    const e = { ...read({}), timestamp: "not a date" };
    expect(readCloudRecord(e)).toBeNull();
  });

  it("ignores a read with neither a principal nor a credential", () => {
    const e = {
      ...read({}),
      description: "",
      canonical: { event: { action: "GetObject" }, cloud: {} },
    };
    expect(readCloudRecord(e as unknown as ForensicEvent)).toBeNull();
  });

  // #931 item 4: Account Key / SAS-authenticated reads carry no actor at all. credentialId is
  // already a first-class dimension of groupKey() — a credential-only identity must still be
  // read, not dropped.
  it("reads a credential-only record (Account Key / SAS auth, no actor) by its credentialId", () => {
    const e = {
      ...read({}),
      description: "",
      canonical: {
        event: { action: "get blob" },
        cloud: { resource: "acct1/cont1/obj1" },
        authentication: { credentialId: "key1(deadbeef...)" },
      },
    };
    const r = readCloudRecord(e as unknown as ForensicEvent);
    expect(r?.principal).toBe("");
    expect(r?.credentialId).toBe("key1(deadbeef...)");
    expect(r?.container).toBe("acct1");
    expect(r?.object).toBe("cont1/obj1");
  });

  it("falls back to the importer's description format when there is no envelope", () => {
    const e = {
      id: "x1",
      timestamp: at(0),
      description: "AWS GetObject (s3) by alice from 203.0.113.9",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      srcIp: "203.0.113.9",
    } as unknown as ForensicEvent;
    const r = readCloudRecord(e);
    expect(r?.principal).toBe("alice");
    expect(r?.sourceIp).toBe("203.0.113.9");
  });

  it("splits a resource into container and object", () => {
    expect(splitResource("corp-data/a/b.csv")).toEqual({ container: "corp-data", object: "a/b.csv" });
    expect(splitResource("s3://corp-data")).toEqual({ container: "corp-data", object: "" });
    expect(splitResource("")).toEqual({ container: "", object: "" });
  });

  // No importer retains CloudTrail's userAgent field today.
  it("reads a client name only when the evidence actually carries one", () => {
    expect(clientFromDescription("AWS GetObject by x [ua: rclone/v1.65]")).toBe("rclone/v1.65");
    expect(clientFromDescription("M365 FileDownloaded by x using MegaSync")).toBe("MegaSync");
    expect(clientFromDescription("AWS GetObject (s3) by app-role from 10.0.1.5")).toBe("");
  });

  // #1106: the outcome is carried through so a denied/failed call can be told apart from one that
  // actually returned data.
  it("reads canonical.event.outcome, trimmed and lowercased", () => {
    expect(readCloudRecord(read({ outcome: "Failed" }))?.outcome).toBe("failed");
    expect(readCloudRecord(read({ outcome: " Success " }))?.outcome).toBe("success");
  });

  it("is '' when the source carries no outcome at all", () => {
    expect(readCloudRecord(read({}))?.outcome).toBe("");
  });
});

describe("groupBulkReads", () => {
  it("reports one group when a principal reads many objects in a window", () => {
    const g = groupBulkReads(manyReads(MIN_OBJECTS + 5));
    expect(g).toHaveLength(1);
    expect(g[0].objectCount).toBe(MIN_OBJECTS + 5);
    expect(g[0].principal).toBe(ROLE_PRINCIPAL);
  });

  it("says nothing about a handful of reads", () => {
    expect(groupBulkReads(manyReads(5))).toEqual([]);
  });

  // A retry loop reading one object two hundred times is one object.
  it("counts distinct objects, not calls", () => {
    const same = Array.from({ length: 200 }, (_v, i) => read({ resource: "corp-data/a.csv", min: i * 0.01 }));
    expect(groupBulkReads(same)).toEqual([]);
  });

  it("reports breadth across containers on its own", () => {
    const wide = Array.from({ length: MIN_CONTAINERS + 1 }, (_v, i) =>
      read({ resource: `bucket-${i}`, action: "ListObjectsV2", min: i }),
    );
    const g = groupBulkReads(wide);
    expect(g).toHaveLength(1);
    expect(g[0].containerCount).toBe(MIN_CONTAINERS + 1);
  });

  it("does not merge two principals into one group", () => {
    const g = groupBulkReads([
      ...manyReads(MIN_OBJECTS + 1),
      ...manyReads(MIN_OBJECTS + 1, { principal: "other" }),
    ]);
    expect(g).toHaveLength(2);
  });

  it("does not merge two source addresses into one group", () => {
    const g = groupBulkReads([
      ...manyReads(MIN_OBJECTS + 1),
      ...manyReads(MIN_OBJECTS + 1, { ip: "203.0.113.9" }),
    ]);
    expect(g).toHaveLength(2);
  });

  it("does not join reads spread far beyond the window", () => {
    const spread = Array.from({ length: MIN_OBJECTS + 5 }, (_v, i) =>
      read({ resource: `corp-data/f-${i}`, min: i * 120 }),
    );
    expect(groupBulkReads(spread)).toEqual([]);
  });

  it("marks a group that holds enumeration calls only", () => {
    const lists = Array.from({ length: MIN_CONTAINERS + 1 }, (_v, i) =>
      read({ resource: `bucket-${i}`, action: "ListBucket", min: i }),
    );
    expect(groupBulkReads(lists)[0].listOnly).toBe(true);
  });

  // #1106: a denied/failed call never returned data and must not inflate the breadth count.
  describe("denied/failed reads (#1106)", () => {
    it("excludes a failed read from objectCount and reports it in failedCount", () => {
      const good = manyReads(MIN_OBJECTS + 1);
      const failed = manyReads(3, { min: 200, outcome: "failed" });
      const g = groupBulkReads([...good, ...failed]);
      expect(g).toHaveLength(1);
      expect(g[0].objectCount).toBe(MIN_OBJECTS + 1);
      expect(g[0].failedCount).toBe(3);
    });

    it("also recognizes 'failure' (Azure Storage's own spelling), case-insensitively", () => {
      const good = manyReads(MIN_OBJECTS + 1);
      const failed = manyReads(2, { min: 200, outcome: "FAILURE" });
      const g = groupBulkReads([...good, ...failed]);
      expect(g[0].failedCount).toBe(2);
    });

    it("never lets enough failed reads alone cross the breadth threshold", () => {
      const failedOnly = manyReads(MIN_OBJECTS + 5, { outcome: "failed" });
      expect(groupBulkReads(failedOnly)).toEqual([]);
    });

    it("does not exclude an unrecognized or absent outcome — fails open (#1106's own scoping)", () => {
      const unknownOutcome = manyReads(MIN_OBJECTS + 1, { outcome: "unknown" });
      const g = groupBulkReads(unknownOutcome);
      expect(g[0].objectCount).toBe(MIN_OBJECTS + 1);
      expect(g[0].failedCount).toBe(0);
    });

    it("failedCount is 0 by default", () => {
      expect(groupBulkReads(manyReads(MIN_OBJECTS + 1))[0].failedCount).toBe(0);
    });
  });
});

describe("role assumption", () => {
  const assume = read({
    action: "AssumeRole",
    principal: "alice",
    resource: "arn:aws:iam::123456789012:role/app-role",
    min: -10,
    description: "AWS AssumeRole (sts) by alice from 203.0.113.9",
  });

  it("reads AssumeRole calls off the timeline", () => {
    const a = roleAssumptions([assume]);
    expect(a).toHaveLength(1);
    expect(a[0].by).toBe("alice");
    expect(a[0].role).toBe("app-role");
  });

  it("ties a bulk read back to who opened the session", () => {
    const group = groupBulkReads(manyReads(MIN_OBJECTS + 1))[0];
    const m = assumptionFor(group, roleAssumptions([assume]));
    expect(m?.assumption.by).toBe("alice");
    expect(m?.by).toBe("role-time");
  });

  it("ignores an assumption that happened after the reads", () => {
    const late = { ...assume, timestamp: at(600) };
    const group = groupBulkReads(manyReads(MIN_OBJECTS + 1))[0];
    expect(assumptionFor(group, roleAssumptions([late]))).toBeNull();
  });

  it("ignores an assumption of a different role", () => {
    const other = read({
      action: "AssumeRole",
      principal: "bob",
      resource: "arn:aws:iam::123456789012:role/other-role",
      min: -5,
    });
    const group = groupBulkReads(manyReads(MIN_OBJECTS + 1))[0];
    expect(assumptionFor(group, roleAssumptions([other]))).toBeNull();
  });
});

describe("gradeGroup — breadth is a question, not an answer", () => {
  const group = (over: Partial<BulkGroup> = {}): BulkGroup => ({
    principal: ROLE_PRINCIPAL,
    credentialId: "",
    provider: "aws",
    account: "",
    sourceIp: "10.0.1.5",
    userAgent: "",
    objectCount: 4000,
    containerCount: 2,
    containers: ["corp-data"],
    sampleObjects: ["corp-data/a.csv"],
    eventIds: ["e1", "e2"],
    first: at(0),
    last: at(30),
    listOnly: false,
    truncated: false,
    failedCount: 0,
    ...over,
  });

  // Backup, replication, indexing and analytics all read at this scale on a schedule.
  it("grades volume alone Medium and names the alternative", () => {
    const v = gradeGroup(group());
    expect(v?.severity).toBe("Medium");
    expect(v?.reason).toContain("Backup, replication, indexing and analytics");
  });

  it("raises when the session was opened by someone assuming the role", () => {
    const v = gradeGroup(group(), {
      assumptions: [{ role: "app-role", by: "alice", time: Date.parse(at(-10)), issuedKey: "", account: "" }],
    });
    expect(v?.severity).toBe("High");
    expect(v?.reason).toContain("opened by alice");
    expect(v?.reason).toContain("matched by role name and time; the key id is not on these rows");
  });

  it("raises when the reads came from outside the cloud", () => {
    expect(gradeGroup(group({ sourceIp: "203.0.113.9" }))?.severity).toBe("High");
  });

  it("raises when a person-driven tool did the reading", () => {
    const v = gradeGroup(group({ userAgent: "rclone/v1.65" }));
    expect(v?.severity).toBe("High");
    expect(v?.reason).toContain("a tool a person drives");
  });

  it("honours an environment baseline of expected bulk readers", () => {
    expect(gradeGroup(group(), { expectedPrincipals: [ROLE_PRINCIPAL.toUpperCase()] })).toBeNull();
  });

  // The one number an analyst most wants, and no provider records it.
  it("always states that byte counts are not recorded", () => {
    expect(gradeGroup(group())?.reason).toContain("never HOW MANY BYTES");
  });

  it("states that an enumeration-only group is what disabled data events look like", () => {
    const v = gradeGroup(group({ listOnly: true, objectCount: 0, containerCount: 8 }));
    expect(v?.reason).toContain("data events disabled");
    expect(v?.reason).toContain("not evidence that none happened");
  });

  it("says when the client was not retained by the import", () => {
    expect(gradeGroup(group())?.reason).toContain("client that made these calls was not retained");
  });

  // #1106: a denied/failed call is disclosed, never silently dropped.
  it("discloses denied/failed calls excluded from the counts", () => {
    const v = gradeGroup(group({ failedCount: 7 }));
    expect(v?.reason).toContain("7 denied/failed call(s)");
    expect(v?.reason).toContain("excluded from the counts above because they returned no data");
  });

  it("says nothing about failures when there were none", () => {
    expect(gradeGroup(group({ failedCount: 0 }))?.reason).not.toContain("denied/failed");
  });

  it("carries a bounded sample and the contributing event ids", () => {
    const v = gradeGroup(group());
    expect(v?.reason).toContain("corp-data/a.csv");
    expect(v?.reason).toContain("e1, e2");
  });
});

describe("summarizeBulkReads — one summary, the reads untouched", () => {
  const events = () => manyReads(MIN_OBJECTS + 5);

  it("adds exactly one summary event and changes none of the reads", () => {
    const input = events();
    const out = summarizeBulkReads(input);
    expect(out).toHaveLength(input.length + 1);
    const summary = out[out.length - 1];
    expect(summary.description).toContain("[cloud bulk read:");
    for (let i = 0; i < input.length; i++) expect(out[i]).toBe(input[i]);
  });

  it("tags the summary with collection techniques", () => {
    const summary = summarizeBulkReads(events()).at(-1);
    expect(summary?.mitreTechniques).toContain("T1530");
    expect(summary?.sources).toEqual(["Cloud bulk read"]);
  });

  // The group grows as more of an export is imported; two summaries would read as two sessions.
  it("replaces its own summary on a re-merge rather than adding a second", () => {
    const once = summarizeBulkReads(events());
    const twice = summarizeBulkReads(once);
    expect(twice.filter((e) => e.description.includes("[cloud bulk read:"))).toHaveLength(1);
    expect(twice).toHaveLength(once.length);
  });

  it("gives a group a stable id", () => {
    const g = groupBulkReads(events())[0];
    expect(summaryId(g)).toBe(summaryId(g));
    expect(summaryId(g)).toMatch(/^bulkread-/);
  });

  it("returns the input untouched when nothing is in bulk", () => {
    const input = manyReads(3);
    expect(summarizeBulkReads(input)).toBe(input);
  });
});

// "No bulk read found" must never be reported as an answer when the logging was off.
describe("objectLoggingNote", () => {
  it("says object logging is on when object reads are present", () => {
    expect(objectLoggingNote(manyReads(3))).toContain("Object-level logging is on");
  });

  it("says enumeration-only is the disabled-data-events shape", () => {
    const lists = [read({ resource: "bucket-a", action: "ListBucket" })];
    const note = objectLoggingNote(lists);
    expect(note).toContain("data events");
    expect(note).toContain("No conclusion about what was downloaded");
  });

  it("says plainly when the case holds no object-storage activity", () => {
    expect(objectLoggingNote([])).toContain("no cloud object-storage activity");
  });
});

// Every one of these was a real defect the first version shipped.
describe("regressions", () => {
  // firstStr returned the bucket and threw the key away, so objectCount was structurally always 0
  // and MIN_OBJECTS was unreachable on real CloudTrail. Pinned against the real importer.
  it("keeps the object key, so a real CloudTrail GetObject carries an object", async () => {
    const { parseCloudTrail } = await import("../../src/analysis/awsImport.js");
    const record = {
      eventTime: "2026-01-01T10:00:00Z",
      eventName: "GetObject",
      eventSource: "s3.amazonaws.com",
      userIdentity: { type: "AssumedRole", arn: ROLE_PRINCIPAL },
      sourceIPAddress: "203.0.113.9",
      requestParameters: { bucketName: "corp-data", key: "finance/q4.xlsx" },
    };
    const parsed = parseCloudTrail(JSON.stringify({ Records: [record] }));
    expect(parsed.events[0].canonical?.cloud?.resource).toBe("corp-data/finance/q4.xlsx");
  });

  // 300 GetObject calls on 300 files collapsed into one aggregated event with a count of 300.
  it("does not aggregate distinct object reads into one row", async () => {
    const { parseCloudTrail } = await import("../../src/analysis/awsImport.js");
    const Records = Array.from({ length: 60 }, (_v, i) => ({
      eventTime: "2026-01-01T10:00:00Z",
      eventName: "GetObject",
      eventSource: "s3.amazonaws.com",
      userIdentity: { type: "AssumedRole", arn: ROLE_PRINCIPAL },
      sourceIPAddress: "203.0.113.9",
      requestParameters: { bucketName: "corp-data", key: `finance/f-${i}.xlsx` },
    }));
    const parsed = parseCloudTrail(JSON.stringify({ Records }));
    expect(new Set(parsed.events.map((e) => e.aggKey)).size).toBe(60);
  });

  // A management-plane call repeated by one principal genuinely is one thing.
  it("still aggregates management-plane calls", async () => {
    const { parseCloudTrail } = await import("../../src/analysis/awsImport.js");
    const Records = Array.from({ length: 10 }, () => ({
      eventTime: "2026-01-01T10:00:00Z",
      eventName: "DescribeInstances",
      eventSource: "ec2.amazonaws.com",
      userIdentity: { type: "AssumedRole", arn: ROLE_PRINCIPAL },
      sourceIPAddress: "10.0.0.1",
      requestParameters: {},
    }));
    const parsed = parseCloudTrail(JSON.stringify({ Records }));
    expect(new Set(parsed.events.map((e) => e.aggKey)).size).toBe(1);
  });

  // "M365 SharePoint: FileDownloaded by …" — reading the first word captured "SharePoint", so
  // three of the actions READ_ACTION_RE lists could never be reached.
  it("reads the action past a service segment in the description", () => {
    const e = {
      id: "m1",
      timestamp: at(0),
      description: "M365 SharePoint: FileDownloaded by alice@corp.test from 203.0.113.9",
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    } as unknown as ForensicEvent;
    expect(readCloudRecord(e)?.action).toBe("FileDownloaded");
  });

  // The densest-window scan was O(n^2) with an allocation per start index, inside the state lock.
  it("scans a large group in one forward pass", () => {
    const many = Array.from({ length: 20_000 }, (_v, i) =>
      read({ resource: `corp-data/f-${i}.csv`, min: i * 0.002 }),
    );
    const started = Date.now();
    const g = groupBulkReads(many);
    expect(Date.now() - started).toBeLessThan(4_000);
    expect(g[0].objectCount).toBeGreaterThan(1_000);
  });

  // correlate.ts keys duplicates on timestamp + cleanDescription + host, and cleanDescription
  // strips the whole marker. With the identity only inside it, two sessions that started in the
  // same second deduplicated into one and a data-theft finding vanished.
  it("puts the principal and source outside the stripped marker", async () => {
    const { cleanDescription } = await import("../../src/analysis/correlate.js");
    const alice = manyReads(MIN_OBJECTS + 1, { principal: "alice" });
    const bob = manyReads(MIN_OBJECTS + 1, { principal: "bob", ip: "198.51.100.4" });
    const out = summarizeBulkReads([...alice, ...bob]);
    const summaries = out.filter((e) => e.description.includes("[cloud bulk read:"));
    expect(summaries).toHaveLength(2);
    const cleaned = summaries.map((e) => cleanDescription(e.description));
    expect(new Set(cleaned).size).toBe(2);
  });

  // role "admin" matched principal ".../superadmin-role/sess", and role "a" matched almost
  // anything — a false causal attribution of one person's action to another.
  it("matches the role segment exactly, not as a substring", () => {
    const group = groupBulkReads(manyReads(MIN_OBJECTS + 1))[0];
    const a = (role: string, by: string) => ({
      role,
      by,
      time: Date.parse(at(-5)),
      issuedKey: "",
      account: "",
    });
    expect(assumptionFor(group, [a("app", "mallory")])).toBeNull();
    expect(assumptionFor(group, [a("superapp-role", "mallory")])).toBeNull();
    expect(assumptionFor(group, [a("app-role", "alice")])?.assumption.by).toBe("alice");
  });

  it("reads the role name out of an ARN", () => {
    expect(roleSegment("arn:aws:iam::123456789012:role/path/to/app-role")).toBe("app-role");
    expect(roleSegment("app-role")).toBe("app-role");
    expect(roleSegment("")).toBe("");
  });

  // A backup job reads at this scale every night; an operator does it once.
  it("treats a principal that reads on several days as a scheduled job", () => {
    const days = [0, 1, 2].flatMap((d) => manyReads(MIN_OBJECTS + 1, { min: d * 1440 }));
    expect(recurringPrincipals(days)).toContain(ROLE_PRINCIPAL.toLowerCase());
    expect(gradeGroup(groupBulkReads(days)[0], { recurringPrincipals: [ROLE_PRINCIPAL] })).toBeNull();
  });

  // objectLoggingNote was a string builder no analyst ever saw.
  it("puts the object-logging gap on the timeline", () => {
    const lists = Array.from({ length: 3 }, (_v, i) =>
      read({ resource: `bucket-${i}`, action: "ListBucket", min: i }),
    );
    const out = summarizeBulkReads(lists);
    const coverage = out.find((e) => e.id === "cloud-object-logging-coverage");
    expect(coverage?.severity).toBe("Medium");
    expect(coverage?.description).toContain("data events");
    // and it is replaced, not duplicated, on a re-merge
    expect(summarizeBulkReads(out).filter((e) => e.id === "cloud-object-logging-coverage")).toHaveLength(1);
  });

  it("says nothing about object logging when object reads are present", () => {
    expect(
      summarizeBulkReads(manyReads(3)).find((e) => e.id === "cloud-object-logging-coverage"),
    ).toBeUndefined();
  });

  it("discloses when a group held more records than one pass measures", () => {
    const g = groupBulkReads(
      Array.from({ length: MAX_RECORDS_PER_GROUP + 10 }, (_v, i) =>
        read({ resource: `corp-data/f-${i}.csv`, min: i * 0.001 }),
      ),
    );
    expect(g[0].truncated).toBe(true);
    expect(gradeGroup(g[0])?.reason).toContain("the real total is higher");
  });

  // #1140: `truncated` was assigned from a single export-wide counter, so one principal exceeding
  // the cap marked every OTHER principal's group truncated too — even one with a handful of reads.
  it("marks only the principal that exceeded the cap as truncated, not every group in the export", () => {
    const over = Array.from({ length: MAX_RECORDS_PER_GROUP + 10 }, (_v, i) =>
      read({ principal: "over-cap", resource: `corp-data/f-${i}.csv`, min: i * 0.001 }),
    );
    const small = manyReads(MIN_OBJECTS + 1, { principal: "well-under-cap" });
    const g = groupBulkReads([...over, ...small]);
    expect(g.find((x) => x.principal === "over-cap")?.truncated).toBe(true);
    expect(g.find((x) => x.principal === "well-under-cap")?.truncated).toBe(false);
  });

  it("says an unreadable source address was unreadable, not internal", () => {
    const g = groupBulkReads(manyReads(MIN_OBJECTS + 1, { ip: "not-an-address" }))[0];
    const v = gradeGroup(g);
    expect(v?.severity).toBe("Medium");
    expect(v?.reason).toContain("could not be read");
  });

  it("treats an IPv6 source outside the cloud as corroboration", () => {
    const g = groupBulkReads(manyReads(MIN_OBJECTS + 1, { ip: "2001:db8::1" }))[0];
    expect(gradeGroup(g)?.severity).toBe("High");
  });
});

// Only awsImport stamps a canonical resource. Without a description fallback the container and the
// object were empty for every other provider, so the object count was zero and the pass was blind
// to all of them — an AWS-only feature wearing a cloud-wide name.
describe("the other providers", () => {
  const ev = (description: string) =>
    ({
      id: `p${++seq}`,
      timestamp: at(0),
      description,
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    }) as unknown as ForensicEvent;

  it("reads a GCP object read", () => {
    const r = readCloudRecord(
      ev(
        "GCP storage.objects.get (storage) by svc@proj.iam.gserviceaccount.com from 10.0.0.1 on corp-data/finance/q4.csv",
      ),
    );
    expect(r?.container).toBe("corp-data");
    expect(r?.object).toBe("finance/q4.csv");
  });

  // Azure writes a TWO-WORD operation. Taking the first word returned "Get", which is not a read.
  it("reads an Azure blob read, whose action is two words", () => {
    const r = readCloudRecord(ev("Azure Get Blob by svc from 10.0.0.1 on drop/export.zip"));
    expect(r?.action).toBe("Get Blob");
    expect(r?.container).toBe("drop");
    expect(r?.object).toBe("export.zip");
  });

  it("reads an M365 download, whose target follows an arrow", () => {
    const r = readCloudRecord(
      ev(
        "M365 SharePoint: FileDownloaded by alice@corp.test from 203.0.113.9 \u2192 Finance/Payroll/2026.xlsx",
      ),
    );
    expect(r?.action).toBe("FileDownloaded");
    expect(r?.container).toBe("Finance");
    expect(r?.object).toBe("Payroll/2026.xlsx");
  });

  it("does not invent a resource when the description carries none", () => {
    const r = readCloudRecord(ev("M365 FileDownloaded by alice@corp.test from 203.0.113.9"));
    expect(r?.object).toBe("");
  });

  it("groups a GCP principal's reads into a finding", () => {
    const many = Array.from(
      { length: MIN_OBJECTS + 5 },
      (_v, i) =>
        ({
          id: `g${i}`,
          timestamp: at(i * 0.01),
          description: `GCP storage.objects.get (storage) by svc@proj.iam.gserviceaccount.com from 203.0.113.9 on corp-data/f-${i}.csv`,
          severity: "Info",
          mitreTechniques: [],
          relatedFindingIds: [],
          sourceScreenshots: [],
        }) as unknown as ForensicEvent,
    );
    const g = groupBulkReads(many);
    expect(g[0]?.objectCount).toBe(MIN_OBJECTS + 5);
  });
});

// Found by the codex review of this item. Several were caused by the fix that preceded them.
describe("codex review regressions", () => {
  const cev = (id: string, description: string, min: number) =>
    ({
      id,
      timestamp: new Date(Date.parse("2026-01-01T10:00:00Z") + min * 60000).toISOString(),
      description,
      severity: "Info",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    }) as unknown as ForensicEvent;

  // Adding the resource fallback made " on " and " → " terminators the principal parser did not
  // know, so without a source address each object path was swallowed into a DIFFERENT principal.
  it("does not swallow the resource into the principal when there is no source address", () => {
    const many = Array.from({ length: MIN_OBJECTS + 10 }, (_v, i) =>
      cev(`n${i}`, `GCP storage.objects.get (storage) by svc@x.test on objects/f-${i}.csv`, i * 0.01),
    );
    const g = groupBulkReads(many);
    expect(g[0]?.principal).toBe("svc@x.test");
    expect(g[0]?.objectCount).toBe(MIN_OBJECTS + 10);
  });

  // GCP, Azure and M365 put the address in prose only. Every source became "" and fifty callers
  // were grouped as one, which makes a distributed read look like a single session.
  it("recovers a non-AWS source address, so distinct callers do not merge", () => {
    const spread = Array.from({ length: 50 }, (_v, i) =>
      cev(
        `s${i}`,
        `GCP storage.objects.get (storage) by svc@x.test from 10.0.0.${i} on data/f-${i}.csv`,
        i * 0.01,
      ),
    );
    expect(readCloudRecord(spread[0])?.sourceIp).toBe("10.0.0.0");
    expect(groupBulkReads(spread)).toEqual([]);
  });

  // A near-miss window must never displace a hit: ranking by score and testing the winner
  // afterwards dropped the group entirely.
  it("keeps a qualifying window over a higher-scoring one that qualifies for neither threshold", () => {
    const hit = Array.from({ length: 50 }, (_v, i) =>
      cev(`q${i}`, `AWS GetObject (s3) by app from 10.0.0.1 on b1/f-${i}.csv`, i * 0.01),
    );
    const nearMiss = Array.from({ length: 49 }, (_v, i) =>
      cev(`m${i}`, `AWS GetObject (s3) by app from 10.0.0.1 on b${i % 4}/g-${i}.csv`, 120 + i * 0.01),
    );
    expect(groupBulkReads([...hit, ...nearMiss])[0]?.objectCount).toBe(50);
  });

  // A schedule explains VOLUME. It does not explain a new source, a new client, or a role someone
  // else just assumed — and it used to silence the finding before any of those were considered.
  it("still reports a scheduled principal when something else is wrong", () => {
    const days = [0, 1440, 2880].flatMap((d) =>
      Array.from({ length: MIN_OBJECTS + 10 }, (_v, i) =>
        cev(`d${d}-${i}`, `AWS GetObject (s3) by app from 203.0.113.9 on b/f-${d}-${i}.csv`, d + i * 0.01),
      ),
    );
    const rec = recurringPrincipals(days);
    expect(rec.length).toBeGreaterThan(0);
    const verdict = gradeGroup(groupBulkReads(days)[0], { recurringPrincipals: rec });
    expect(verdict).not.toBeNull();
    expect(verdict?.reason).toContain("explains none of the above");
  });

  it("still suppresses a scheduled principal when volume is the only signal", () => {
    const days = [0, 1440, 2880].flatMap((d) =>
      Array.from({ length: MIN_OBJECTS + 10 }, (_v, i) =>
        cev(`p${d}-${i}`, `AWS GetObject (s3) by app from 10.0.0.5 on b/f-${d}-${i}.csv`, d + i * 0.01),
      ),
    );
    expect(
      gradeGroup(groupBulkReads(days)[0], { recurringPrincipals: recurringPrincipals(days) }),
    ).toBeNull();
  });

  // The identity carried no time, so a second session replaced the first and one vanished.
  it("gives two sessions by one identity different ids", () => {
    const session = (p: string, min: number) =>
      groupBulkReads(
        Array.from({ length: MIN_OBJECTS + 5 }, (_v, i) =>
          cev(`${p}${i}`, `AWS GetObject (s3) by app from 10.0.0.1 on b/${p}-${i}.csv`, min + i * 0.01),
        ),
      )[0];
    expect(summaryId(session("mon", 0))).not.toBe(summaryId(session("fri", 7200)));
  });

  // A public address is NOT necessarily outside the cloud — a cloud VM, a NAT gateway and a hosted
  // runner all present one, and the finding used to assert otherwise.
  it("does not claim a public address is outside the cloud", () => {
    const many = Array.from({ length: MIN_OBJECTS + 5 }, (_v, i) =>
      cev(`x${i}`, `AWS GetObject (s3) by app from 54.240.0.1 on b/f-${i}.csv`, i * 0.01),
    );
    const reason = gradeGroup(groupBulkReads(many)[0])?.reason ?? "";
    expect(reason).not.toContain("outside the cloud");
    expect(reason).toContain("a NAT gateway and a hosted runner all present one");
  });
});

describe("reachability", () => {
  it("runs from the merge", () => {
    const merge = readFileSync(join(process.cwd(), "src/analysis/stateMerge.ts"), "utf8");
    expect(merge).toContain("summarizeBulkReads");
  });

  it("has its marker stripped before correlation keys a duplicate", () => {
    // The registry correlate.ts reads (derivedNote.ts), exercised: the note comes off the key.
    expect(cleanDescription(`base text [cloud bulk read: a reason]`)).toBe("base text");
  });
});

// #979: a group is one credential; the issuance that minted THAT key decides the attribution.
describe("credential-id attribution (#979)", () => {
  const withKey = (key: string, over: Parameters<typeof read>[0] = {}) =>
    manyReads(MIN_OBJECTS + 1, over).map((e) => ({
      ...e,
      canonical: { ...e.canonical!, authentication: { credentialId: key } },
    }));
  it("two keys under one role, address and client are two groups; a key match beats time and says so", () => {
    const groups = groupBulkReads([...withKey("ASIAAAAA"), ...withKey("ASIABBBB", { min: 1 })]);
    expect(groups).toHaveLength(2);
    expect(groups.map((g) => g.credentialId).sort()).toEqual(["ASIAAAAA", "ASIABBBB"]);
    const issued = {
      role: "app-role",
      by: "alice",
      time: Date.parse(at(-300)),
      issuedKey: "ASIAAAAA",
      account: "",
    };
    const other = {
      role: "app-role",
      by: "bob",
      time: Date.parse(at(-5)),
      issuedKey: "ASIABBBB",
      account: "",
    };
    const a = groups.find((g) => g.credentialId === "ASIAAAAA")!;
    const m = assumptionFor(a, [issued, other]);
    expect(m?.assumption.by).toBe("alice");
    expect(m?.by).toBe("key");
    // Rows that name a key no issuance minted: no role-name fallback — that would name another person.
    expect(
      assumptionFor(a, [
        { role: "app-role", by: "bob", time: Date.parse(at(-5)), issuedKey: "", account: "" },
      ]),
    ).toBeNull();
    const v = gradeGroup(a, { assumptions: [issued] });
    expect(v?.reason).toContain("issued to alice assuming this role");
    expect(v?.reason).toContain("(matched by the key id)");
  });
  it("roleAssumptions reads the issued key off an issuance row's target", () => {
    const issuance = {
      ...read({
        action: "AssumeRole",
        principal: "alice",
        resource: "arn:aws:iam::123456789012:role/app-role",
        min: -10,
      }),
    };
    issuance.canonical = {
      ...issuance.canonical!,
      target: { kind: "other", id: "ASIAAAAA", name: "temporary credential" },
    };
    expect(roleAssumptions([issuance])[0].issuedKey).toBe("ASIAAAAA");
  });
});

// #1356: the summary id must be as discriminating as the grouping. Two groups the grouping keeps
// apart (two credentials under one role from one address; one role name in two accounts or on two
// providers) whose densest window starts in the same second shared ONE id, and the replaced-by-id
// filter on the next merge silently deleted one of the two summaries.
describe("summaryId is as discriminating as groupKey (#1356)", () => {
  const stamped = (over: { key?: string; account?: string; provider?: string }) =>
    manyReads(MIN_OBJECTS + 1, { principal: "Backup" }).map((e) => ({
      ...e,
      canonical: {
        ...e.canonical!,
        ...(over.key ? { authentication: { credentialId: over.key } } : {}),
        cloud: {
          ...e.canonical!.cloud,
          provider: over.provider ?? "aws",
          accountId: over.account ?? "111122223333",
        },
      },
    }));
  const idsOf = (out: ForensicEvent[]) =>
    out.filter((e) => e.description.includes("[cloud bulk read:")).map((e) => e.id);

  it("two credentials under one role, address, client and start second get two ids", () => {
    const groups = groupBulkReads([...stamped({ key: "ASIAAAAA" }), ...stamped({ key: "ASIABBBB" })]);
    expect(groups).toHaveLength(2);
    expect(groups[0].first).toBe(groups[1].first);
    expect(summaryId(groups[0])).not.toBe(summaryId(groups[1]));
  });

  it("one role name in two accounts, or on two providers, gets two ids", () => {
    const [a, b] = groupBulkReads([
      ...stamped({ account: "111122223333" }),
      ...stamped({ account: "444455556666" }),
    ]);
    expect(summaryId(a)).not.toBe(summaryId(b));
    const [c, d] = groupBulkReads([...stamped({ provider: "aws" }), ...stamped({ provider: "gcp" })]);
    expect(summaryId(c)).not.toBe(summaryId(d));
  });

  it("both summaries survive a re-merge", () => {
    const input = [...stamped({ key: "ASIAAAAA" }), ...stamped({ key: "ASIABBBB" })];
    const once = summarizeBulkReads(input);
    expect(idsOf(once)).toHaveLength(2);
    const twice = summarizeBulkReads(once);
    expect(idsOf(twice).sort()).toEqual(idsOf(once).sort());
    expect(twice).toHaveLength(once.length);
  });

  // The loss was real only through the whole merge: correlate.ts unions rows whose timestamp,
  // cleaned description and host agree, and the marker is stripped before that comparison — so
  // the identity has to be spoken outside the marker as well as hashed into the id.
  it("two credentials under one role both reach the persisted timeline, merge after merge", () => {
    const rows = [...stamped({ key: "ASIAAAAA" }), ...stamped({ key: "ASIABBBB" })];
    const base = {
      findings: [],
      iocs: [],
      mitreTechniques: [],
      threadsOpened: [],
      threadsClosed: [],
      timelineNote: "",
      summary: "",
    };
    const ctx = { windowSequence: 1, timestamp: at(60), sourceScreenshots: [] };
    const delta = { ...base, forensicEvents: rows } as unknown as AnalysisDelta;
    const first = mergeDelta(emptyState("c1"), delta, ctx);
    const second = mergeDelta(first, delta, { ...ctx, windowSequence: 2 });
    const third = mergeDelta(second, { ...base, forensicEvents: [] }, { ...ctx, windowSequence: 3 });
    for (const state of [first, second, third]) {
      const summaries = state.forensicTimeline.filter((e) => e.description.includes("[cloud bulk read:"));
      expect(summaries.map((e) => e.id).sort()).toEqual(idsOf(first.forensicTimeline).sort());
      expect(summaries).toHaveLength(2);
      expect(summaries.map((e) => e.description.split(" [cloud bulk read:")[0]).sort()).toEqual([
        "Cloud bulk read by Backup (credential ASIAAAAA…) in aws account 111122223333 from 10.0.1.5",
        "Cloud bulk read by Backup (credential ASIABBBB…) in aws account 111122223333 from 10.0.1.5",
      ]);
    }
  });

  it("a credential-only group still names the fingerprint alone; a bare principal reads as before", () => {
    const [keyOnly] = groupBulkReads(
      manyReads(MIN_OBJECTS + 1, { description: "AWS GetObject (s3) from 10.0.1.5" }).map((e) => ({
        ...e,
        canonical: {
          ...e.canonical!,
          actor: { kind: "account", name: "" },
          authentication: { credentialId: "ASIACCCC" },
        },
      })),
    );
    expect(summaryHead(keyOnly)).toBe("Cloud bulk read by credential ASIACCCC… from 10.0.1.5");
    const [bare] = groupBulkReads(manyReads(MIN_OBJECTS + 1, { principal: "Backup" }));
    expect(summaryHead(bare)).toBe("Cloud bulk read by Backup from 10.0.1.5");
  });

  // A case merged before the fix holds a summary under the old id: it is replaced, not orphaned.
  it("replaces a summary persisted under the pre-#1356 id instead of leaving it beside the new one", () => {
    const input = stamped({ key: "ASIAAAAA" });
    const [g] = groupBulkReads(input);
    const legacy = legacySummaryId(g);
    expect(legacy).not.toBe(summaryId(g));
    const once = summarizeBulkReads(input);
    const persistedBefore = once.map((e) => (e.id === summaryId(g) ? { ...e, id: legacy } : e));
    const again = summarizeBulkReads(persistedBefore);
    expect(idsOf(again)).toEqual([summaryId(g)]);
    expect(again.some((e) => e.id === legacy)).toBe(false);
  });

  // A delimiter inside one component must not let two groups spell one key.
  it("a separator character inside a component cannot make two groups share an id", () => {
    const [a] = groupBulkReads(stamped({ key: "x|", account: "y" }));
    const [b] = groupBulkReads(stamped({ key: "x", account: "|y" }));
    expect(summaryId(a)).not.toBe(summaryId(b));
  });

  it("the id is case-insensitive on the added components, like groupKey", () => {
    const [a] = groupBulkReads(stamped({ key: "asiaaaaa", account: "AbC", provider: "AWS" }));
    const [b] = groupBulkReads(stamped({ key: "ASIAAAAA", account: "abc", provider: "aws" }));
    expect(summaryId(a)).toBe(summaryId(b));
  });
});

// Code round 1 on #979: a group is one account of one provider; the key match is the (account, key)
// tuple and never an issuance after the reads began.
describe("account, provider and chronology (#979 code round)", () => {
  const inAccount = (account: string, provider = "aws", over: Parameters<typeof read>[0] = {}) =>
    manyReads(MIN_OBJECTS + 1, { principal: "Backup", ...over }).map((e) => ({
      ...e,
      canonical: { ...e.canonical!, cloud: { ...e.canonical!.cloud, provider, accountId: account } },
    }));
  it("the same role name, address and client in two accounts, or on two providers, are two groups", () => {
    expect(groupBulkReads([...inAccount("111122223333"), ...inAccount("444455556666")])).toHaveLength(2);
    expect(groupBulkReads([...inAccount("111122223333"), ...inAccount("111122223333", "gcp")])).toHaveLength(
      2,
    );
    expect(
      groupBulkReads([...inAccount("111122223333"), ...inAccount("111122223333")]).length,
    ).toBeLessThanOrEqual(1);
  });
  it("a key issued in another account, or after the reads began, is not the group's issuance", () => {
    const rows = manyReads(MIN_OBJECTS + 1).map((e) => ({
      ...e,
      canonical: {
        ...e.canonical!,
        authentication: { credentialId: "ASIAAAAA" },
        cloud: { ...e.canonical!.cloud, provider: "aws", accountId: "111122223333" },
      },
    }));
    const g = groupBulkReads(rows)[0];
    const base = { role: "app-role", by: "alice", issuedKey: "ASIAAAAA" };
    expect(assumptionFor(g, [{ ...base, time: Date.parse(at(-5)), account: "444455556666" }])).toBeNull();
    expect(assumptionFor(g, [{ ...base, time: Date.parse(at(5)), account: "111122223333" }])).toBeNull();
    expect(assumptionFor(g, [{ ...base, time: Date.parse(at(-5)), account: "111122223333" }])?.by).toBe(
      "key",
    );
    expect(assumptionFor(g, [{ ...base, time: Date.parse(at(-5)), account: "" }])?.by).toBe("key");
  });
});
