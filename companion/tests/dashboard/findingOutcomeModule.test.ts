import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The finding attack-outcome module (#930 item 8) driven the way the browser drives it, with a
// fetch we resolve by hand so responses can arrive late and out of order. The three failures the
// adversarial review named are all ordering failures: a late GET or PATCH from the previous case
// landing on the next one, and two quick edits to one finding answering in the wrong order.

interface Api {
  loadFindingOutcome(caseId: string): void;
  findingOutcomeControls(fid: string, finding?: unknown): string;
  findingSimulationChip(finding: unknown): string;
  setSimulationOverride(treatAsReal: boolean): void;
  setFindingControl(fid: string, value: string): void;
  setFindingExecution(fid: string, value: string): void;
}

interface Deferred {
  resolve(body: unknown, init?: { ok?: boolean; status?: number }): void;
  reject(err: Error): void;
  url: string;
}

function harness() {
  const pending: (Deferred & { body?: string })[] = [];
  const renders: number[] = [];
  const toasts: string[] = [];
  let caseInput = "";
  const globals = {
    document: { getElementById: () => ({ value: caseInput }), addEventListener: () => {} },
    fetch: (url: string, init?: { body?: string }) =>
      new Promise((res, rej) => {
        pending.push({
          url,
          body: init?.body,
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
    esc: (s: string) => String(s),
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
    h.pending[1].resolve([]); // B answers first, empty
    await tick();
    h.pending[0].resolve([rec("f1", "blocked")]); // A answers late, with a record for a recurring id
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

  // #1595: the simulation verdict's one-click override lives with the finding controls.
  describe("simulation verdict", () => {
    const verdict = (overridden = false) => ({
      id: "f14",
      severity: "Critical",
      simulation: { role: "verdict", originalSeverity: "Info", appliedSeverity: "Critical", overridden },
    });

    it("offers the override only on the verdict card", () => {
      const h = harness();
      expect(h.api.findingOutcomeControls("f1", { id: "f1", severity: "High" })).not.toMatch(/fsim-btn/);
      const capped = {
        id: "f1",
        severity: "Medium",
        simulation: { role: "simulated", originalSeverity: "Critical" },
      };
      expect(h.api.findingOutcomeControls("f1", capped)).not.toMatch(/fsim-btn/);
      expect(h.api.findingOutcomeControls("f14", verdict())).toMatch(
        /data-fsim-real="true"[^>]*>Treat as real intrusion/,
      );
      expect(h.api.findingOutcomeControls("f14", verdict(true))).toMatch(
        /data-fsim-real="false"[^>]*>Undo: treat as simulation/,
      );
    });

    it("the chip keeps the live-intrusion severity beside the cap", () => {
      const h = harness();
      const capped = {
        id: "f1",
        severity: "Medium",
        simulation: { role: "simulated", originalSeverity: "Critical" },
      };
      expect(h.api.findingSimulationChip(capped)).toMatch(
        /simulated — pending owner confirmation · live-intrusion severity Critical/,
      );
      const live = {
        id: "f4",
        severity: "Critical",
        simulation: { role: "live-exposure", originalSeverity: "Critical" },
      };
      expect(h.api.findingSimulationChip(live)).toMatch(/live exposure — remediate regardless/);
      expect(h.api.findingSimulationChip({ id: "f9", severity: "High" })).toBe("");
    });

    it("posts the override and reports a failure on screen", async () => {
      const h = harness();
      h.setCase("A");
      h.api.setSimulationOverride(true);
      const req = h.pending.shift()!;
      expect(req.url).toBe("/cases/A/simulation-override");
      expect(JSON.parse(req.body!)).toEqual({ treatAsReal: true, updatedBy: "Alice" });
      req.resolve({ error: "disk full" }, { ok: false, status: 500 });
      await tick();
      expect(h.toasts[0]).toMatch(/Simulation override not saved: disk full/);
    });
  });
});
