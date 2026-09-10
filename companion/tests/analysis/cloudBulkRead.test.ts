import { describe, it, expect } from "vitest";
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
  summaryId,
  objectLoggingNote,
  MIN_OBJECTS,
  MIN_CONTAINERS,
  type BulkGroup,
} from "../../src/analysis/cloudBulkRead.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

let seq = 0;
const at = (min: number) => new Date(Date.parse("2026-01-01T10:00:00Z") + min * 60000).toISOString();

/** A cloud read event as an importer that stamps the canonical envelope produces it. */
const read = (over: {
  action?: string;
  principal?: string;
  ip?: string;
  resource?: string;
  min?: number;
  description?: string;
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
      event: { action: over.action ?? "GetObject" },
      actor: { name: over.principal ?? "app-role" },
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
    expect(r?.principal).toBe("app-role");
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
});

describe("groupBulkReads", () => {
  it("reports one group when a principal reads many objects in a window", () => {
    const g = groupBulkReads(manyReads(MIN_OBJECTS + 5));
    expect(g).toHaveLength(1);
    expect(g[0].objectCount).toBe(MIN_OBJECTS + 5);
    expect(g[0].principal).toBe("app-role");
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
});

describe("role assumption", () => {
  const assume = read({
    action: "AssumeRole",
    principal: "alice",
    resource: "app-role",
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
    expect(assumptionFor(group, roleAssumptions([assume]))?.by).toBe("alice");
  });

  it("ignores an assumption that happened after the reads", () => {
    const late = { ...assume, timestamp: at(600) };
    const group = groupBulkReads(manyReads(MIN_OBJECTS + 1))[0];
    expect(assumptionFor(group, roleAssumptions([late]))).toBeNull();
  });

  it("ignores an assumption of a different role", () => {
    const other = read({ action: "AssumeRole", principal: "bob", resource: "other-role", min: -5 });
    const group = groupBulkReads(manyReads(MIN_OBJECTS + 1))[0];
    expect(assumptionFor(group, roleAssumptions([other]))).toBeNull();
  });
});

describe("gradeGroup — breadth is a question, not an answer", () => {
  const group = (over: Partial<BulkGroup> = {}): BulkGroup => ({
    principal: "app-role",
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
      assumptions: [{ role: "app-role", by: "alice", time: Date.parse(at(-10)) }],
    });
    expect(v?.severity).toBe("High");
    expect(v?.reason).toContain("opened by alice");
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
    expect(gradeGroup(group(), { expectedPrincipals: ["APP-ROLE"] })).toBeNull();
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

describe("reachability", () => {
  it("runs from the merge", () => {
    const merge = readFileSync(join(process.cwd(), "src/analysis/stateMerge.ts"), "utf8");
    expect(merge).toContain("summarizeBulkReads");
  });

  it("has its marker stripped before correlation keys a duplicate", () => {
    const corr = readFileSync(join(process.cwd(), "src/analysis/correlate.ts"), "utf8");
    expect(corr).toContain("cloud bulk read");
  });
});
