import { describe, it, expect } from "vitest";
import { parseVeloRef } from "../../src/analysis/veloRef.js";

describe("parseVeloRef", () => {
  it("parses a bare hunt id", () => {
    expect(parseVeloRef("H.CABC123")).toEqual({ kind: "hunt", huntId: "H.CABC123" });
    expect(parseVeloRef("  H.CABC123  ")).toEqual({ kind: "hunt", huntId: "H.CABC123" });
  });
  it("parses a hunt GUI URL", () => {
    expect(parseVeloRef("https://velo:8889/app/index.html?org_id=root#/hunts/H.CABC123/overview"))
      .toEqual({ kind: "hunt", huntId: "H.CABC123" });
  });
  it("parses a client+flow pair (either order, slash/space separated)", () => {
    expect(parseVeloRef("C.deadbeef/F.CFF001")).toEqual({ kind: "flow", clientId: "C.deadbeef", flowId: "F.CFF001" });
    expect(parseVeloRef("F.CFF001 C.deadbeef")).toEqual({ kind: "flow", clientId: "C.deadbeef", flowId: "F.CFF001" });
  });
  it("parses a collection GUI URL", () => {
    expect(parseVeloRef("https://velo:8889/app/index.html?org_id=root#/collected/C.deadbeef/F.CFF001/overview"))
      .toEqual({ kind: "flow", clientId: "C.deadbeef", flowId: "F.CFF001" });
  });
  it("keeps a hunt-launched flow's trailing .H suffix (does not truncate it)", () => {
    expect(parseVeloRef("C.9e5afcaf10536cd9/F.D93M3ERL39HVE.H"))
      .toEqual({ kind: "flow", clientId: "C.9e5afcaf10536cd9", flowId: "F.D93M3ERL39HVE.H" });
    expect(parseVeloRef("https://velo/app/index.html#/collected/C.9e5afcaf10536cd9/F.D93M3ERL39HVE.H/overview"))
      .toEqual({ kind: "flow", clientId: "C.9e5afcaf10536cd9", flowId: "F.D93M3ERL39HVE.H" });
  });
  it("flags a notebook URL — a flow/hunt's notebook shows the analyst's own filtered VQL, not raw rows", () => {
    expect(parseVeloRef("https://velo:8889/app/index.html?org_id=root#/collected/C.deadbeef/F.CFF001/notebook"))
      .toEqual({ kind: "flow", clientId: "C.deadbeef", flowId: "F.CFF001", isNotebookUrl: true });
    expect(parseVeloRef("https://velo:8889/app/index.html?org_id=root#/hunts/H.CABC123/notebook"))
      .toEqual({ kind: "hunt", huntId: "H.CABC123", isNotebookUrl: true });
    // A plain "overview"/results URL (no /notebook segment) is NOT flagged.
    expect(parseVeloRef("https://velo:8889/app/index.html?org_id=root#/collected/C.deadbeef/F.CFF001/overview"))
      .toEqual({ kind: "flow", clientId: "C.deadbeef", flowId: "F.CFF001" });
  });

  it("returns null for junk / an id missing its partner", () => {
    expect(parseVeloRef("")).toBeNull();
    expect(parseVeloRef("not an id")).toBeNull();
    expect(parseVeloRef("F.CFF001")).toBeNull();          // flow id without a client id
    expect(parseVeloRef("C.deadbeef")).toBeNull();        // client id without a flow id
    expect(parseVeloRef("H.CABC/F.CFF")).toBeNull();      // ambiguous (both a hunt and a flow token)
  });
});
