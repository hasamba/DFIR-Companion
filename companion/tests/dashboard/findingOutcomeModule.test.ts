import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The finding attack-outcome module (#930 item 8) driven the way the browser drives it, with a
// fetch we resolve by hand so responses can arrive late and out of order. The three failures the
// adversarial review named are all ordering failures: a late GET or PATCH from the previous case
// landing on the next one, and two quick edits to one finding answering in the wrong order.

interface Api {
  loadFindingOutcome(caseId: string): void;
  findingOutcomeControls(fid: string): string;
  setFindingControl(fid: string, value: string): void;
  setFindingExecution(fid: string, value: string): void;
}

interface Deferred {
  resolve(body: unknown, init?: { ok?: boolean; status?: number }): void;
  reject(err: Error): void;
  url: string;
}

function harness() {
  const pending: Deferred[] = [];
  const renders: number[] = [];
  const toasts: string[] = [];
  let caseInput = "";
  const globals = {
    document: { getElementById: () => ({ value: caseInput }), addEventListener: () => {} },
    fetch: (url: string) =>
      new Promise((res, rej) => {
        pending.push({
          url,
          resolve: (body, init = {}) =>
            res({ ok: init.ok ?? true, status: init.status ?? 200, json: () => Promise.resolve(body) }),
          reject: rej,
        });
      }),
    DfirState: { lastState: () => ({ findings: [] }) },
    render: () => renders.push(1),
    investigatorName: () => "Alice",
    showToast: (t: string) => toasts.push(t),
    escAttr: (s: string) => String(s),
    ICON_TARGET: "<svg/>",
    ICON_FLAG: "<svg/>",
  };
  const api = loadDashboardModule<Api>("dashboard-finding-outcome.js", [], globals);
  return {
    api,
    pending,
    renders,
    toasts,
    setCase: (id: string) => {
      caseInput = id;
    },
  };
}

const selected = (html: string, axis: "ctl" | "exec") => {
  const m = html.match(new RegExp(`class="fout-select fout-${axis}"[^>]*>([\\s\\S]*?)</select>`));
  const opt = m?.[1].match(/<option value="([^"]*)" selected>/);
  return opt?.[1] ?? "";
};

const rec = (fid: string, control: string) => ({
  findingId: fid,
  execution: null,
  control,
  note: "",
  semanticKey: "",
  updatedAt: "",
  updatedBy: "",
});

const tick = () => new Promise((r) => setTimeout(r, 0));

describe("dashboard-finding-outcome ordering", () => {
  it("a late GET for the previous case never lands on the next case's cards", async () => {
    const h = harness();
    h.api.loadFindingOutcome("A");
    h.api.loadFindingOutcome("B");
    expect(h.pending.map((p) => p.url)).toEqual(["/cases/A/finding-outcome", "/cases/B/finding-outcome"]);
    h.pending[1]!.resolve([]); // B answers first, empty
    await tick();
    h.pending[0]!.resolve([rec("f1", "blocked")]); // A answers late, with a record for a recurring id
    await tick();
    expect(selected(h.api.findingOutcomeControls("f1"), "ctl")).toBe(""); // B shows nothing for f1
  });

  it("a late PATCH from the previous case is discarded — no cache write, no render, no toast", async () => {
    const h = harness();
    h.api.loadFindingOutcome("A");
    h.pending.shift()!.resolve([]);
    await tick();
    h.setCase("A");
    h.api.setFindingControl("f1", "blocked"); // PATCH for case A in flight
    const patchA = h.pending.shift()!;
    h.api.loadFindingOutcome("B"); // analyst switches case
    h.pending.shift()!.resolve([]);
    await tick();
    const rendersBefore = h.renders.length;
    patchA.resolve({ record: rec("f1", "blocked") }); // A's save answers after B loaded
    await tick();
    expect(selected(h.api.findingOutcomeControls("f1"), "ctl")).toBe("");
    expect(h.renders.length).toBe(rendersBefore);
    expect(h.toasts).toEqual([]);
  });

  it("two quick edits to one finding answering out of order keep the NEWER value", async () => {
    const h = harness();
    h.api.loadFindingOutcome("A");
    h.pending.shift()!.resolve([]);
    await tick();
    h.setCase("A");
    h.api.setFindingControl("f1", "blocked");
    h.api.setFindingControl("f1", "remediated");
    const [first, second] = [h.pending.shift()!, h.pending.shift()!];
    second.resolve({ record: rec("f1", "remediated") });
    await tick();
    first.resolve({ record: rec("f1", "blocked") }); // the older request answers last
    await tick();
    expect(selected(h.api.findingOutcomeControls("f1"), "ctl")).toBe("remediated");
  });

  it("a failed save reverts the control to the last saved value and says why on screen", async () => {
    const h = harness();
    h.api.loadFindingOutcome("A");
    h.pending.shift()!.resolve([rec("f1", "blocked")]);
    await tick();
    h.setCase("A");
    h.api.setFindingControl("f1", "remediated");
    const rendersBefore = h.renders.length;
    h.pending.shift()!.resolve({ error: "ENOSPC: no space left on device" }, { ok: false, status: 500 });
    await tick();
    expect(selected(h.api.findingOutcomeControls("f1"), "ctl")).toBe("blocked"); // last SAVED value
    expect(h.renders.length).toBe(rendersBefore + 1); // re-rendered so the select snaps back
    expect(h.toasts[0]).toMatch(/not saved: ENOSPC/);
  });

  it("a network failure is reported the same way", async () => {
    const h = harness();
    h.api.loadFindingOutcome("A");
    h.pending.shift()!.resolve([]);
    await tick();
    h.setCase("A");
    h.api.setFindingExecution("f1", "observed");
    h.pending.shift()!.reject(new Error("Failed to fetch"));
    await tick();
    expect(h.toasts[0]).toMatch(/not saved: Failed to fetch/);
    expect(selected(h.api.findingOutcomeControls("f1"), "exec")).toBe("");
  });
});
