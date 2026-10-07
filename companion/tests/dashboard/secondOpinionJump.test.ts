// A finished 2nd-opinion run shows its result: it jumps to the panel, or — when the analyst is
// busy — leaves a toast and a note in the panel instead of pulling them away.
import { describe, it, expect, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  runSecondOpinion(): void;
}

const REC = {
  generatedAt: "2026-10-07T10:00:00Z",
  modelA: "a",
  modelB: "b",
  agreementCount: 3,
  deltas: [{ id: "d1", kind: "severity", title: "T", status: "pending", aSeverity: "Low", bSeverity: "High" }],
};

function harness(doc: { hidden?: boolean; activeElement?: { tagName: string } | null } = {}) {
  const els = new Map<string, Record<string, unknown>>();
  const el = (id: string) => {
    if (!els.has(id))
      els.set(id, { value: "", textContent: "", innerHTML: "", disabled: false, checked: false, style: {}, scrollIntoView: vi.fn() });
    return els.get(id)!;
  };
  const listeners: Array<() => void> = [];
  const document = {
    hidden: doc.hidden ?? false,
    activeElement: doc.activeElement ?? null,
    getElementById: (id: string) => el(id),
    addEventListener: (_: string, f: () => void) => listeners.push(f),
    removeEventListener: () => {},
  };
  const revealSection = vi.fn();
  const showToast = vi.fn();
  const api = loadDashboardModule<Api>(
    "dashboard-second-opinion.js",
    ["dashboard-escape.js", "dashboard-time.js"],
    {
      document,
      revealSection,
      showToast,
      localStorage: { getItem: () => null, setItem: () => {} },
      fetch: () => Promise.resolve({ status: 200, ok: true, json: () => Promise.resolve(REC) }),
    },
  );
  el("caseId").value = "case-1";
  return { api, el, document, revealSection, showToast, listeners };
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

describe("second opinion finished (jump + note)", () => {
  it("jumps to the panel and leaves a note when the analyst is idle", async () => {
    const h = harness();
    h.api.runSecondOpinion();
    await settle();
    expect(h.revealSection).toHaveBeenCalledWith("sec-findings");
    expect(h.el("secondOpinionPanel").scrollIntoView).toHaveBeenCalled();
    expect(h.showToast).toHaveBeenCalledTimes(1);
    expect(String(h.el("secondOpinionPanel").innerHTML)).toContain("Run finished");
  });

  it("does not jump while the analyst types; toast and note remain", async () => {
    const h = harness({ activeElement: { tagName: "TEXTAREA" } });
    h.api.runSecondOpinion();
    await settle();
    expect(h.revealSection).not.toHaveBeenCalled();
    expect(h.showToast).toHaveBeenCalledWith(expect.stringContaining("2nd opinion"), "warn");
    expect(String(h.el("secondOpinionPanel").innerHTML)).toContain("Run finished");
  });

  it("waits for the tab to return when it is hidden", async () => {
    const h = harness({ hidden: true });
    h.api.runSecondOpinion();
    await settle();
    expect(h.revealSection).not.toHaveBeenCalled();
    h.document.hidden = false;
    h.listeners.forEach((f) => f());
    expect(h.revealSection).toHaveBeenCalledWith("sec-findings");
  });
});
