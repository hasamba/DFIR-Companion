// #2543: an importer's context note rides the delta into the case IOC; first note wins; a model
// response can never plant one.
import { describe, expect, it } from "vitest";
import { mergeDelta } from "../../src/analysis/stateMerge.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { deltaSchema, stripAiExtractedFrom, type AnalysisDelta } from "../../src/analysis/responseSchema.js";
import { addIoc, mergeRowIocs, type SiemIoc } from "../../src/analysis/iocSink.js";

const base: AnalysisDelta = {
  findings: [],
  iocs: [],
  mitreTechniques: [],
  threadsOpened: [],
  threadsClosed: [],
  timelineNote: "",
  summary: "",
};
const ctx = (n: number) => ({
  windowSequence: n,
  timestamp: `2026-11-10T10:0${n}:00.000Z`,
  sourceScreenshots: [],
});
const ARN = "arn:aws:iam::123456789012:user/dev-user";

describe("importer IOC note (#2543)", () => {
  it("creates the IOC with the importer's note, and a later sighting does not overwrite it", () => {
    let s = mergeDelta(
      emptyState("c1"),
      deltaSchema.parse({
        ...base,
        iocs: [{ id: "i1", type: "other", value: ARN, note: "AWS IAM principal — first" }],
      }),
      ctx(1),
    );
    s = mergeDelta(
      s,
      deltaSchema.parse({
        ...base,
        iocs: [{ id: "i2", type: "other", value: ARN, note: "AWS IAM principal — second" }],
      }),
      ctx(2),
    );
    expect(s.iocs).toHaveLength(1);
    expect(s.iocs[0].note).toBe("AWS IAM principal — first");
  });

  it("puts a multi-line note on one line at merge", () => {
    const s = mergeDelta(
      emptyState("c1"),
      { ...base, iocs: [{ id: "i1", type: "other", value: "p1", note: "line one\nline two" }] },
      ctx(1),
    );
    expect(s.iocs[0].note).toBe("line one line two");
  });

  it("a model response's note is stripped, like extractedFrom", () => {
    const delta = deltaSchema.parse({
      ...base,
      iocs: [{ id: "i1", type: "ip", value: "198.51.100.9", note: "trust me" }],
    });
    const stripped = stripAiExtractedFrom(delta);
    expect(stripped.iocs[0]).not.toHaveProperty("note");
    expect(mergeDelta(emptyState("c1"), stripped, ctx(1)).iocs[0].note).toBeUndefined();
  });

  it("the import sink keeps the first note across rows", () => {
    const file = new Map<string, SiemIoc>();
    const a = new Map<string, SiemIoc>();
    addIoc(a, "other", ARN, undefined, "first");
    const b = new Map<string, SiemIoc>();
    addIoc(b, "other", ARN, undefined, "second");
    mergeRowIocs(file, a, "k1");
    mergeRowIocs(file, b, "k2");
    expect([...file.values()][0]).toMatchObject({ note: "first", sourceAggKeys: ["k1", "k2"] });
  });
});
