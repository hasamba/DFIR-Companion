// A mixed import batch's failure reasons must survive the next idle (#1786).
//
// A batch where one file lands and one is refused ends with a summary like
// "imported csv — analyzing (see AI status) · 1 file(s) failed / unrecognized · big.csv: upload
// exceeds the 1 MB limit …". The landed file's background job then pushes `idle`, and
// clearTransientStatus() reset any line naming "import" to "connected (live)" — so the reason the
// analyst needed was on screen for a few seconds and then gone, with nothing saying a file failed.
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
  return { status, api: loadDashboardModule<AiStatusApi>("dashboard-ai-status.js", [], globals) };
}

describe("an import summary with failures survives idle (#1786)", () => {
  it.each([
    "imported csv — analyzing (see AI status) · 1 file(s) failed / unrecognized · big.csv: upload exceeds the 1 MB limit",
    "imported evtx — analyzing (see AI status) · 1 screenshot(s), 1 failed · shot.png: HTTP 500",
  ])("keeps %j", (text) => {
    const { status, api } = statusHarness(text);
    api.clearTransientStatus();
    expect(status.textContent).toBe(text);
  });

  it("still clears a clean import summary", () => {
    const { status, api } = statusHarness("imported csv — analyzing (see AI status)");
    api.clearTransientStatus();
    expect(status.textContent).toBe("connected (live)");
  });
});
