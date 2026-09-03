import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The live-snapshot choice beside Deploy on an AI-suggested hunt (#809). The helpers are pure
// (VQL in, boolean or HTML out; a container in, a ctx fragment out), so they are proven here
// without a DOM, the same way the Sigma card's renderers are.

interface SnapshotApi {
  vqlReadsLiveState: (vql: string) => boolean;
  huntSnapshotToggleHtml: (cls: string, idx: number, vql: string) => string;
  huntSnapshotCtx: (container: unknown, cls: string, idx: number) => Record<string, unknown>;
}

describe("the live-snapshot choice on an AI-suggested hunt (#809)", () => {
  const api = () => loadDashboardModule<SnapshotApi>("dashboard-hunt-snapshot.js", ["dashboard-escape.js"]);

  it("reads live state when every FROM is a live-state plugin", () => {
    const a = api();
    expect(a.vqlReadsLiveState("SELECT Name FROM pslist() WHERE Name =~ 'x'")).toBe(true);
    expect(a.vqlReadsLiveState("SELECT * FROM netstat() WHERE Raddr.IP = '1.2.3.4'")).toBe(true);
    expect(
      a.vqlReadsLiveState("SELECT FullPath, hash(path=FullPath).SHA256 AS H FROM glob(globs='C:/x/*.exe')"),
    ).toBe(true);
    expect(a.vqlReadsLiveState("SELECT * FROM reg_keys(globs='HKLM/x/*')")).toBe(true);
  });

  it("does not guess for an event-backed query, an artifact, a wrapper, or no FROM at all", () => {
    const a = api();
    expect(a.vqlReadsLiveState("SELECT * FROM parse_evtx(filename='C:/x.evtx')")).toBe(false);
    expect(a.vqlReadsLiveState("SELECT * FROM Artifact.Windows.EventLogs.Evtx()")).toBe(false);
    expect(
      a.vqlReadsLiveState(
        "SELECT * FROM foreach(row={SELECT * FROM glob(globs='x')}, query={SELECT * FROM read_file(filenames=FullPath)})",
      ),
    ).toBe(false);
    expect(
      a.vqlReadsLiveState("SELECT * FROM pslist() WHERE Pid IN (SELECT Pid FROM parse_evtx(filename='x'))"),
    ).toBe(false);
    expect(a.vqlReadsLiveState("")).toBe(false);
    expect(a.vqlReadsLiveState("SELECT 1")).toBe(false);
  });

  it("renders a checkbox that is ticked only for a live-state query, with the class and index the deploy handler reads", () => {
    const a = api();
    const on = a.huntSnapshotToggleHtml("vhs-snapshot", 3, "SELECT * FROM pslist()");
    expect(on).toContain('class="vhs-snapshot"');
    expect(on).toContain('data-idx="3"');
    expect(on).toContain(" checked");
    expect(on).toMatch(/empty ≠ miss/);
    const off = a.huntSnapshotToggleHtml("pbh-snapshot", 0, "SELECT * FROM parse_evtx(filename='x')");
    expect(off).not.toContain(" checked");
  });

  it("turns the ticked box into coverage: snapshot on the deploy ctx, and nothing when unticked", () => {
    const a = api();
    const container = (checked: boolean) => ({
      querySelector: (sel: string) => (sel === '.vhs-snapshot[data-idx="2"]' ? { checked } : null),
    });
    expect(a.huntSnapshotCtx(container(true), "vhs-snapshot", 2)).toEqual({ coverage: "snapshot" });
    expect(a.huntSnapshotCtx(container(false), "vhs-snapshot", 2)).toEqual({});
    expect(a.huntSnapshotCtx(null, "vhs-snapshot", 2)).toEqual({});
  });
});
