// #2542 item 8: the object-logging coverage row, time-aware. A case whose S3 data events were turned
// on part-way holds later object records, so the old "no reads at all" test never fired and the
// unlogged window read as "nothing happened".
import { describe, expect, it } from "vitest";
import {
  objectLoggingEvent,
  LOGGING_COVERAGE_ID,
  summarizeBulkReads,
} from "../../src/analysis/cloudBulkRead.js";
import { isCoverageNote } from "../../src/analysis/coverageEventTime.js";
import { demoteBelowSeverity } from "../../src/analysis/forensicGate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

const T = "2024-05-01T23:53:36Z";
let n = 0;
const ev = (timestamp: string, action: string, canonical: Record<string, unknown> = {}): ForensicEvent =>
  ({
    id: `e-${++n}`,
    timestamp,
    description: `AWS ${action} (s3) by example-user from 192.0.2.10`,
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    canonical: {
      event: { action },
      actor: { name: "example-user" },
      cloud: { provider: "aws", ...((canonical.cloud as object) ?? {}) },
      ...canonical,
    },
  }) as unknown as ForensicEvent;
const selectors = (at = T, over: Record<string, unknown> = {}) =>
  ev(at, "PutEventSelectors", {
    loggingChange: {
      provider: "aws",
      target: "management-events",
      targetKind: "trail",
      state: "reconfigured",
      facts: [{ name: "eventSelector[0]", value: "management All; data events: AWS::S3::Object arn:aws:s3" }],
      priorStateInRecord: false,
      effectiveNotEstablished: false,
      denied: false,
      ...over,
    },
  });
const mgmt = (at: string) =>
  ev(at, "GetBucketVersioning", { cloud: { provider: "aws", resource: "example-eng" } });
const object = (at: string, action = "GetObject") =>
  ev(at, action, { cloud: { provider: "aws", resource: "example-log/AWSLogs/x.json.gz" } });

describe("objectLoggingEvent — logging that began part-way (#2542)", () => {
  it("states the unlogged window up to the selector change when object records exist only after it", () => {
    const note = objectLoggingEvent([
      mgmt("2024-05-01T13:00:00Z"),
      selectors(),
      object("2024-05-02T16:32:46Z"),
    ]);
    expect(note?.id).toBe(LOGGING_COVERAGE_ID);
    expect(note!.timestamp).toBe("2024-05-01T13:00:00Z");
    expect(note!.description).toContain(
      "No object-level (data) records in this case before 2024-05-01T23:53:36Z",
    );
    expect(note!.description).toContain("from 2024-05-01T13:00:00Z to 2024-05-01T23:53:36Z");
    expect(note!.description).toContain("Other trails' selectors are not in this evidence");
    expect(note!.description).not.toMatch(/data events were off/i);
  });
  it("is a coverage note the severity gate keeps", () => {
    const note = objectLoggingEvent([mgmt("2024-05-01T13:00:00Z"), selectors()])!;
    expect(isCoverageNote(note)).toBe(true);
    expect(note.severity).toBe("Medium");
    expect(demoteBelowSeverity([note], "High").kept.map((e) => e.id)).toEqual([note.id]);
  });
  it("is silent when any object record — a read or a write — precedes the change", () => {
    expect(
      objectLoggingEvent([object("2024-05-01T12:00:00Z"), selectors(), object("2024-05-02T00:00:00Z")]),
    ).toBeNull();
    expect(objectLoggingEvent([object("2024-05-01T12:00:00Z", "PutObject"), selectors()])).toBeNull();
  });
  it("is not silenced by a non-object row whose resource holds a slash (a role ARN)", () => {
    const assume = ev("2024-05-01T12:00:00Z", "AssumeRole", {
      cloud: { provider: "aws", resource: "arn:aws:iam::123456789012:role/Deploy" },
    });
    expect(objectLoggingEvent([assume, selectors()])?.id).toBe(LOGGING_COVERAGE_ID);
  });
  it("ignores a failed selector change and one that selects no object activity", () => {
    const failed = selectors(T, { failure: "denied", denied: true, state: "requested" });
    expect(
      objectLoggingEvent([mgmt("2024-05-01T13:00:00Z"), failed, object("2024-05-02T00:00:00Z")]),
    ).toBeNull();
    const managementOnly = selectors(T, {
      facts: [{ name: "eventSelector[0]", value: "management All; data events: none selected" }],
    });
    expect(
      objectLoggingEvent([mgmt("2024-05-01T13:00:00Z"), managementOnly, object("2024-05-02T00:00:00Z")]),
    ).toBeNull();
  });
  it("leaves the case with no selector change as it was: object reads present → no note", () => {
    expect(objectLoggingEvent([mgmt("2024-05-01T13:00:00Z"), object("2024-05-02T00:00:00Z")])).toBeNull();
  });
});

describe("summarizeBulkReads — withdrawing a contradicted window note (#2564)", () => {
  const stored = (events: ForensicEvent[]) => objectLoggingEvent(events)!;
  const ids = (events: readonly ForensicEvent[]) => events.map((e) => e.id);

  it("drops a stored window note once an object record earlier than the selector change is present", () => {
    const base = [mgmt("2024-05-01T13:00:00Z"), selectors()];
    const note = stored(base);
    const early = object("2024-05-01T14:00:00Z");
    const out = summarizeBulkReads([...base, note, early]);
    expect(ids(out)).not.toContain(LOGGING_COVERAGE_ID);
    expect(ids(out)).toContain(early.id);
  });
  it("keeps the stored window note when the new object record is after the change", () => {
    const base = [mgmt("2024-05-01T13:00:00Z"), selectors()];
    const out = summarizeBulkReads([...base, stored(base), object("2024-05-02T14:00:00Z")]);
    expect(out.filter((e) => e.id === LOGGING_COVERAGE_ID)).toHaveLength(1);
  });
  it("leaves the logging-is-off note alone: only the dated variant is withdrawn", () => {
    const list = ev("2024-05-01T13:00:00Z", "ListObjects", {
      cloud: { provider: "aws", resource: "example-log" },
    });
    const off = objectLoggingEvent([list]);
    expect(off?.description).toMatch(/^Cloud object logging is off/);
    const out = summarizeBulkReads([list, off!, selectors(), object("2024-05-01T14:00:00Z")]);
    expect(out.filter((e) => e.id === LOGGING_COVERAGE_ID).map((e) => e.description)).toEqual([
      off!.description,
    ]);
  });
});
