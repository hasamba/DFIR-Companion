// #2561: the forensic timeline's trusted-source rows — the "Hide trusted" toggle, the count label, the
// pill's hover text and the "Mark a source" form. Rows from another case are never applied.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface TrustedApi {
  activeCaseId: string;
  loadTrustedActivity(caseId: string): Promise<void>;
  isTrustedRow(id: string): boolean;
  trustedRowInfo(id: string): { label: string; value: string } | null;
  trustedRowsHidden(): boolean;
  trustedCountIn(list: Array<{ id: string }>): number;
  toggleTrustedHidden(): void;
  markTrustedSourceFromForm(): Promise<void>;
}

function load(rows: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  const calls: string[] = [];
  const els: Record<
    string,
    { value?: string; hidden?: boolean; textContent?: string; classList?: unknown; setAttribute?: unknown }
  > = {
    evTrustedFilterBtn: {
      hidden: true,
      textContent: "",
      classList: { toggle: () => {} },
      setAttribute: () => {},
    },
    trustedSourceValue: { value: "" },
    trustedSourceLabel: { value: "ours" },
  };
  let renders = 0;
  const api = loadDashboardModule<TrustedApi>("dashboard-trusted-activity.js", [], {
    activeCaseId: "c1",
    document: { getElementById: (id: string) => els[id] ?? null },
    DfirState: { lastFt: () => [] },
    renderTimelineEvents: () => renders++,
    fetch: (url: string) => {
      calls.push(url);
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ rows, count: Object.keys(rows).length }),
      });
    },
    ...extra,
  });
  return { api, calls, els, renders: () => renders };
}

describe("trusted-source rows (#2561)", () => {
  const rows = {
    ev1: { label: "responder", value: "203.0.113.10" },
    ev2: { label: "ours", value: "arn:aws:iam::123456789012:root" },
  };

  it("loads the honoured rows, shows the toggle with the count, and repaints the timeline", async () => {
    const { api, els, calls, renders } = load(rows);
    await api.loadTrustedActivity("c1");
    expect(calls).toEqual(["/cases/c1/trusted-activity"]);
    expect(api.isTrustedRow("ev1")).toBe(true);
    expect(api.trustedRowInfo("ev2")?.value).toBe("arn:aws:iam::123456789012:root");
    expect(api.trustedCountIn([{ id: "ev1" }, { id: "ev9" }])).toBe(1);
    expect(els.evTrustedFilterBtn.hidden).toBe(false);
    expect(els.evTrustedFilterBtn.textContent).toBe("Hide trusted (2)");
    expect(renders()).toBe(1);
    api.toggleTrustedHidden();
    expect(api.trustedRowsHidden()).toBe(true);
    expect(els.evTrustedFilterBtn.textContent).toBe("Trusted hidden (2)");
  });

  it("never applies another case's rows, and a case switch turns the toggle off", async () => {
    const { api } = load(rows);
    await api.loadTrustedActivity("c1");
    api.toggleTrustedHidden();
    api.activeCaseId = "c2";
    expect(api.isTrustedRow("ev1")).toBe(false);
    await api.loadTrustedActivity("c2");
    expect(api.trustedRowsHidden()).toBe(false);
  });

  it("keeps the toggle hidden when the case has no trusted row", async () => {
    const { api, els } = load({});
    await api.loadTrustedActivity("c1");
    expect(els.evTrustedFilterBtn.hidden).toBe(true);
  });

  it("the Mark a source form saves through setIocAttribution and refuses an empty value", async () => {
    const saved: Array<[string, string | null]> = [];
    const { api, els } = load(rows, {
      setIocAttribution: (v: string, l: string | null) => {
        saved.push([v, l]);
        return Promise.resolve();
      },
      showToast: () => {},
    });
    await api.markTrustedSourceFromForm();
    expect(saved).toEqual([]);
    els.trustedSourceValue.value = " arn:aws:iam::123456789012:root ";
    els.trustedSourceLabel.value = "responder";
    await api.markTrustedSourceFromForm();
    expect(saved).toEqual([["arn:aws:iam::123456789012:root", "responder"]]);
    expect(els.trustedSourceValue.value).toBe("");
    els.trustedSourceValue.value = "203.0.113.10";
    els.trustedSourceLabel.value = "";
    await api.markTrustedSourceFromForm();
    expect(saved.at(-1)).toEqual(["203.0.113.10", null]);
  });
});

describe("timeline count label and filter key (#2561)", () => {
  interface DisplayApi {
    timelineCountLabel(o: Record<string, unknown>): { text: string; title: string };
    timelineFilterKey(f: Record<string, unknown>): string;
  }
  const display = () =>
    loadDashboardModule<DisplayApi>("dashboard-timeline-display.js", ["dashboard-escape.js"], {
      document: { getElementById: () => null, querySelectorAll: () => [] },
      localStorage: { getItem: () => null, setItem: () => {} },
      DfirState: { lastState: () => ({ forensicTimeline: [] }), lastFt: () => [] },
    });
  const base = { total: 52, totalFiltered: 52, pageSize: 0, page: 0, totalPages: 1, filtering: false };

  it("says how many shown rows are trusted, and how many the toggle hides", () => {
    const api = display();
    expect(api.timelineCountLabel({ ...base, trustedShown: 30 }).text).toBe("(52 events, 30 trusted)");
    const hidden = api.timelineCountLabel({ ...base, totalFiltered: 22, filtering: true, trustedHidden: 30 });
    expect(hidden.text).toContain("30 trusted hidden");
    expect(hidden.title).toMatch(/grade is unchanged/);
    expect(api.timelineCountLabel(base).text).toBe("(52 events)");
  });

  it("the hide toggle is part of the filter identity (the page resets when it flips)", () => {
    const api = display();
    expect(api.timelineFilterKey({ caseId: "c1", trustedHidden: true })).not.toBe(
      api.timelineFilterKey({ caseId: "c1", trustedHidden: false }),
    );
  });
});

describe("trusted tag hover text (#2561)", () => {
  it("names the label and the value, ARN colons included", () => {
    const src = readFileSync(new URL("../../../public/js/dashboard-tags.js", import.meta.url), "utf8");
    expect(src).toContain('const TRUSTED_NOTE_PREFIX = "tagger:trusted-activity:"');
    expect(src).toMatch(
      /Analyst-marked trusted source \(\$\{rest\.slice\(0, at\)\}: \$\{rest\.slice\(at \+ 1\)\}\) — routine activity, grade unchanged/,
    );
  });
});
