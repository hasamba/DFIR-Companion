import { describe, it, expect } from "vitest";
import { backfillHighSeverityFindings } from "../../src/analysis/highSeverityFindings.js";
import {
  emptyState,
  type Finding,
  type ForensicEvent,
  type InvestigationState,
} from "../../src/analysis/stateTypes.js";

// #2092: a dismissed finding that explains a whole parent-process cluster (one script host and the
// cmd.exe children it spawned) must also explain the siblings it never cited, and an auto finding the
// analyst dismissed must stay dismissed when the next synthesis re-mints it.

const GUID = "{11111111-2222-3333-4444-555555555555}";
const PARENT_CMD = "cscript.exe C:\\Windows\\system32\\gatherNetworkInfo.vbs";

function ev(over: Partial<ForensicEvent> & { id: string }): ForensicEvent {
  return {
    timestamp: "2026-05-26T12:25:36Z",
    description: "desc",
    severity: "Info",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "HOST-A",
    ...over,
  };
}

function child(id: string, cmd: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return ev({
    id,
    severity: "High",
    path: "C:\\Windows\\System32\\cmd.exe",
    description: `Suspicious child: Image=C:\\Windows\\System32\\cmd.exe - CommandLine=cmd.exe /c ${cmd} - ParentImage=C:\\Windows\\System32\\cscript.exe - ParentCommandLine=${PARENT_CMD} @ HOST-A`,
    message: `ProcessGuid: {c-${id}}\nParentProcessGuid: ${GUID}`,
    ...over,
  });
}

function finding(id: string, eventIds: string[], status: Finding["status"]): Finding {
  return {
    id,
    severity: "Info",
    confidence: 80,
    title: id,
    description: id,
    relatedIocs: [],
    mitreTechniques: [],
    sourceScreenshots: [],
    firstSeen: "t",
    lastUpdated: "t",
    status,
    relatedEventIds: eventIds,
  };
}

function cluster(
  citedByDismissal: string[],
  extra: ForensicEvent[] = [],
  findings: Finding[] = [],
): InvestigationState {
  const parent = ev({
    id: "p",
    path: "C:\\Windows\\System32\\cscript.exe",
    description: `Process create: ${PARENT_CMD} @ HOST-A`,
    message: `ProcessGuid: ${GUID}\nParentProcessGuid: {root}`,
  });
  const state = emptyState("c1");
  state.forensicTimeline.push(
    parent,
    child("c1", "ipconfig /all"),
    child("c2", "netstat -ano"),
    child("c3", "route print"),
    child("s1", "arp -a output"),
    child("s2", "nbtstat -n output"),
    ...extra,
  );
  state.findings.push(finding("fD", citedByDismissal, "dismissed"), ...findings);
  return state;
}

const ids = (s: InvestigationState): Set<string> => new Set(s.forensicTimeline.map((e) => e.id));
const autoIds = (s: InvestigationState): string[] =>
  s.findings.filter((f) => f.id.startsWith("f-auto-")).map((f) => f.id);
const links = (s: InvestigationState, id: string): string[] =>
  s.forensicTimeline.find((e) => e.id === id)!.relatedFindingIds;

describe("dismissed parent-process cluster fold (#2092)", () => {
  it("folds uncited siblings onto a dismissal that cites the parent and its children", () => {
    const state = cluster(["p", "c1", "c2", "c3"]);
    const out = backfillHighSeverityFindings(state, ids(state), "t");
    expect(autoIds(out)).toEqual([]);
    expect(links(out, "s1")).toEqual(["fD"]);
    expect(links(out, "s2")).toEqual(["fD"]);
  });

  it("folds when three cited children share the parent, even without the parent row", () => {
    const state = cluster(["c1", "c2", "c3"]);
    const out = backfillHighSeverityFindings(state, ids(state), "t");
    expect(autoIds(out)).toEqual([]);
  });

  it("does not treat a single-row dismissal as a cluster allowlist", () => {
    const state = cluster(["c1"]);
    const out = backfillHighSeverityFindings(state, ids(state), "t");
    expect(autoIds(out).length).toBeGreaterThan(0);
    expect(links(out, "s1")).not.toContain("fD");
  });

  it("does not fold a cluster a live finding also cites", () => {
    const state = cluster(["p", "c1", "c2", "c3"], [], [finding("fLive", ["c2"], "open")]);
    const out = backfillHighSeverityFindings(state, ids(state), "t");
    // Not folded onto the dismissal; the existing twin fold or a new auto finding decides instead.
    expect(links(out, "s1")).not.toContain("fD");
    expect(links(out, "s2")).not.toContain("fD");
  });

  it("never folds a Critical sibling", () => {
    const state = cluster(
      ["p", "c1", "c2", "c3"],
      [child("s3", "whoami /all output", { severity: "Critical" })],
    );
    const out = backfillHighSeverityFindings(state, ids(state), "t");
    expect(links(out, "s3")[0]).toMatch(/^f-auto-/);
  });

  it("does not fold a sibling on another host", () => {
    const other = child("s4", "hostname output here", {
      asset: "HOST-B",
      description: `Suspicious child: Image=C:\\Windows\\System32\\cmd.exe - CommandLine=cmd.exe /c hostname - ParentImage=C:\\Windows\\System32\\cscript.exe - ParentCommandLine=${PARENT_CMD} @ HOST-B`,
    });
    const state = cluster(["p", "c1", "c2", "c3"], [other]);
    const out = backfillHighSeverityFindings(state, ids(state), "t");
    expect(links(out, "s4")[0]).toMatch(/^f-auto-/);
  });

  it("falls back to ParentImage + ParentCommandLine when no GUIDs are logged", () => {
    const state = cluster(["c1", "c2", "c3"]);
    const stripped = {
      ...state,
      forensicTimeline: state.forensicTimeline.map((e) => ({ ...e, message: undefined })),
    };
    const out = backfillHighSeverityFindings(stripped, ids(stripped), "t");
    expect(autoIds(out)).toEqual([]);
  });

  it("does not cluster on a bare parent with no arguments", () => {
    const bare = (id: string, cmd: string): ForensicEvent =>
      ev({
        id,
        severity: "High",
        path: "C:\\Windows\\System32\\cmd.exe",
        description: `Suspicious child: Image=C:\\Windows\\System32\\cmd.exe - CommandLine=cmd.exe /c ${cmd} - ParentImage=C:\\Windows\\explorer.exe - ParentCommandLine=C:\\Windows\\explorer.exe @ HOST-A`,
      });
    const state = emptyState("c1");
    state.forensicTimeline.push(
      bare("b1", "one thing"),
      bare("b2", "two thing"),
      bare("b3", "three th"),
      bare("b4", "four thing"),
    );
    state.findings.push(finding("fD", ["b1", "b2", "b3"], "dismissed"));
    const out = backfillHighSeverityFindings(state, ids(state), "t");
    expect(links(out, "b4")[0]).toMatch(/^f-auto-/);
  });
});

describe("carried-over auto dismissals (#2092)", () => {
  function lone(): InvestigationState {
    const state = emptyState("c1");
    state.forensicTimeline.push(ev({ id: "e1", severity: "High", description: "Lone detection" }));
    return state;
  }

  it("re-mints a previously dismissed f-auto finding as dismissed, not open", () => {
    const prior = new Map([["f-auto-e1", finding("f-auto-e1", ["e1"], "dismissed")]]);
    const out = backfillHighSeverityFindings(lone(), new Set(["e1"]), "t", prior);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({ id: "f-auto-e1", status: "dismissed" });
    expect(links(out, "e1")).toEqual(["f-auto-e1"]);
  });

  it("lets the model win when it re-issues the auto id itself", () => {
    const state = lone();
    state.findings.push({ ...finding("f-auto-e1", [], "open"), severity: "High" });
    const prior = new Map([["f-auto-e1", finding("f-auto-e1", ["e1"], "dismissed")]]);
    const out = backfillHighSeverityFindings(state, new Set(["e1"]), "t", prior);
    expect(out.findings.find((f) => f.id === "f-auto-e1")!.status).toBe("open");
  });

  it("still mints open when there was no prior dismissal", () => {
    const out = backfillHighSeverityFindings(lone(), new Set(["e1"]), "t", new Map());
    expect(out.findings[0].status).toBe("open");
  });
});
