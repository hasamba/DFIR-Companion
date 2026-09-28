// A finished second opinion's status line must not outlive the next run.
//
// The 2nd-opinion button writes "second opinion: 14 disagreements (12 agreed)" into #status when
// the run returns. clearTransientStatus() — called on every `idle` push — only reset lines that
// named synthesis, scope, false-positive or import work, so that result stayed on screen through a
// later Velociraptor import and a full re-synthesis, reading as if it described the current state.
//
// The in-flight "running second opinion …" line must still survive an idle: the run refreshes the
// primary synthesis first, and that inner synthesis can push idle while model B is still working.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface AiStatusApi {
  clearTransientStatus: () => void;
}

function statusHarness(text: string) {
  const status = { textContent: text };
  const globals = {
    document: { getElementById: (id: string) => (id === "status" ? status : null) },
    ws: { readyState: 1 },
  };
  return {
    status,
    api: loadDashboardModule<AiStatusApi>("dashboard-ai-status.js", [], globals),
  };
}

describe("the status line after a second opinion", () => {
  it.each([
    "second opinion: 14 disagreements (12 agreed)",
    "second opinion: 1 disagreement (0 agreed)",
    "second opinion failed: provider timeout",
    "second opinion error: Failed to fetch",
  ])("clears %j on the next idle", (text) => {
    const { status, api } = statusHarness(text);
    api.clearTransientStatus();
    expect(status.textContent).toBe("connected (live)");
  });

  it("keeps the in-flight line while the run is still working", () => {
    const text = "running second opinion (refreshing the primary, then a different model)…";
    const { status, api } = statusHarness(text);
    api.clearTransientStatus();
    expect(status.textContent).toBe(text);
  });

  it("still keeps an unrelated notice", () => {
    const { status, api } = statusHarness("report written: case.md");
    api.clearTransientStatus();
    expect(status.textContent).toBe("report written: case.md");
  });
});
