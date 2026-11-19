import { describe, it, expect } from "vitest";
import {
  fingerprintArtifacts,
  flowMetaVql,
  huntFlowMetaVql,
  parseFlowMeta,
  parseHuntFlowMeta,
} from "../../src/integrations/velociraptor/veloArtifactFingerprint.js";

// #2700: what the Velociraptor server holds for each artifact of a hunt or flow right now, so a
// re-import can tell a changed artifact from one it already read in full.

const huntRow = (over: Record<string, unknown> = {}) => ({
  ClientId: "C.1",
  FlowId: "F.A.H",
  State: "FINISHED",
  Rows: 10,
  Created: 1,
  Started: 2,
  Active: 3,
  Results: ["Windows.NTFS.MFT", "Windows.Detection.Yara/Matches"],
  ...over,
});
const meta = (...rows: Record<string, unknown>[]) => parseHuntFlowMeta(rows)!;

describe("VQL", () => {
  it("reads a hunt's flows through hunt_flows() and one flow's top-level fields through flows()", () => {
    expect(huntFlowMetaVql("H.ABC")).toContain("FROM hunt_flows(hunt_id='H.ABC')");
    expect(huntFlowMetaVql("H.ABC")).toContain("Flow.artifacts_with_results AS Results");
    const flow = flowMetaVql("C.1", "F.X");
    expect(flow).toContain("FROM flows(client_id='C.1') WHERE session_id='F.X'");
    expect(flow).toContain("artifacts_with_results AS Results");
    expect(flow).not.toContain("Flow.");
  });
});

describe("parseHuntFlowMeta / parseFlowMeta", () => {
  it("parses well-formed rows", () => {
    expect(meta(huntRow())).toEqual([
      {
        clientId: "C.1",
        flowId: "F.A.H",
        state: "FINISHED",
        rows: 10,
        created: 1,
        started: 2,
        active: 3,
        results: ["Windows.NTFS.MFT", "Windows.Detection.Yara/Matches"],
      },
    ]);
  });

  it("reads omitted zero-value fields as zero / empty (protobuf JSON drops defaults)", () => {
    const [m] = meta({ ClientId: "C.1", FlowId: "F.A", State: "RUNNING" });
    expect(m).toMatchObject({ rows: 0, created: 0, started: 0, active: 0, results: [] });
  });

  it("reads numeric strings (64-bit counters arrive as strings)", () => {
    expect(meta(huntRow({ Rows: "12", Active: "1700000000000000" }))[0]).toMatchObject({
      rows: 12,
      active: 1700000000000000,
    });
  });

  it("an empty hunt is known and empty, not unknown", () => {
    expect(parseHuntFlowMeta([])).toEqual([]);
  });

  it.each([
    ["not an array", "nope"],
    ["a bad client id", [huntRow({ ClientId: "x" })]],
    ["a bad flow id", [huntRow({ FlowId: "nope" })]],
    ["a non-string state", [huntRow({ State: 3 })]],
    ["a negative row count", [huntRow({ Rows: -1 })]],
    ["a non-numeric row count", [huntRow({ Rows: "lots" })]],
    ["results that are not a list", [huntRow({ Results: "Windows.NTFS.MFT" })]],
    ["a bad time", [huntRow({ Active: {} })]],
    ["a null row", [null]],
  ])("voids the whole read on %s", (_label, rows) => {
    expect(parseHuntFlowMeta(rows)).toBeUndefined();
  });

  it("a flow that is not on the server is unknown, not empty", () => {
    expect(parseFlowMeta([])).toBeUndefined();
    expect(parseFlowMeta([huntRow()])).toHaveLength(1);
  });
});

describe("fingerprintArtifacts", () => {
  const MFT = "Windows.NTFS.MFT";
  const fp = (m: ReturnType<typeof meta>, art = MFT) => fingerprintArtifacts(m, [art])![art];

  it("is undefined when the server state is unknown", () => {
    expect(fingerprintArtifacts(undefined, [MFT])).toBeUndefined();
  });

  it("matches an artifact by name or by its source-qualified result address", () => {
    const m = meta(huntRow());
    expect(fp(m).listed).toBe(true);
    expect(fp(m, "Windows.Detection.Yara").listed).toBe(true);
    expect(fp(m, "Windows.Detection.Yara/Matches").listed).toBe(true);
    expect(fp(m).hash).not.toBe(fp(m, "Windows.Detection.Yara").hash); // the addresses differ
    expect(fp(m, "Windows.NTFS").listed).toBe(false); // a name prefix is not a match
  });

  it("gives an artifact no host reported a stable 'nothing listed' hash", () => {
    expect(fp([], "X")).toEqual(fp(meta(huntRow()), "X"));
    expect(fp([], "X").listed).toBe(false);
  });

  it.each([
    ["more rows", { Rows: 11 }],
    ["a newer activity time", { Active: 4 }],
    ["a relaunch (new start time)", { Started: 9 }],
    ["a different state", { State: "ERROR" }],
  ])("changes on %s", (_label, over) => {
    expect(fp(meta(huntRow(over))).hash).not.toBe(fp(meta(huntRow())).hash);
  });

  it("changes when a new host reports the artifact, and is order-independent", () => {
    const two = meta(huntRow(), huntRow({ ClientId: "C.2", FlowId: "F.B.H" }));
    expect(fp(two).hash).not.toBe(fp(meta(huntRow())).hash);
    expect(fp([...two].reverse()).hash).toBe(fp(two).hash);
  });

  it("marks an artifact live while any host that listed it is still collecting", () => {
    expect(fp(meta(huntRow(), huntRow({ ClientId: "C.2", FlowId: "F.B", State: "RUNNING" }))).live).toBe(
      true,
    );
    expect(fp(meta(huntRow(), huntRow({ ClientId: "C.2", FlowId: "F.B", State: "ERROR" }))).live).toBe(false);
  });

  it("a running host that has not listed the artifact does not make it live", () => {
    const m = meta(huntRow(), huntRow({ ClientId: "C.2", FlowId: "F.B", State: "RUNNING", Results: [] }));
    expect(fp(m).live).toBe(false);
  });
});
