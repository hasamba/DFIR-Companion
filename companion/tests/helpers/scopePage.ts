// The scope sandbox for the case-switch suites (#2904, #2915): the real DfirScope plus the real
// js/dashboard-scope-load.js on the fake page, with a state the test holds and a render it records.
import { fakePage } from "./caseSwitchPage.js";
import { loadDashboardModule } from "./dashboardModule.js";

export interface Finding {
  id: string;
  confidence?: number;
}
export interface StateLike {
  caseId: string;
  forensicTimeline: Array<{ id: string; timestamp: string; relatedFindingIds?: string[] }>;
  findings: Finding[];
  iocs: unknown[];
  mitreTechniques: unknown[];
}

export const bState: StateLike = {
  caseId: "CASE-B",
  forensicTimeline: [
    { id: "e1", timestamp: "2020-01-01T00:00:00Z", relatedFindingIds: ["f1"] },
    { id: "e2", timestamp: "2030-01-01T00:00:00Z" },
  ],
  findings: [{ id: "f1", confidence: 40 }],
  iocs: [],
  mitreTechniques: [],
};
export const A_WINDOW = { start: "2029-01-01T00:00:00.000Z", end: "2031-01-01T00:00:00.000Z" };
export const B_WINDOW = { start: "2019-01-01T00:00:00.000Z", end: "2021-01-01T00:00:00.000Z" };

export interface ScopeSandbox {
  loadScope(caseId: string): void;
  receiveScopePush(caseId: string, msg: { start: string | null; end: string | null }): void;
  noteScopeConfirmed(caseId: string): boolean;
  DfirScope: {
    isEmpty(): boolean;
    get(): { start: string | null; end: string | null };
    project(s: StateLike): StateLike;
    confirm(start: string | null, end: string | null): void;
  };
  DfirState: object;
  render: (s: unknown) => void;
}

export function scopePage() {
  const p = fakePage();
  const sb = loadDashboardModule<ScopeSandbox>(
    "dashboard-scope-load.js",
    ["dashboard-state.js", "dashboard-time.js", "dashboard-scope.js"],
    p.globals,
  );
  let held: StateLike | null = null;
  const renders: unknown[] = [];
  sb.DfirState = { ...sb.DfirState, lastState: () => held };
  sb.render = (s) => renders.push(s);
  return {
    p,
    sb,
    renders,
    hold: (s: StateLike | null) => {
      held = s;
    },
  };
}
