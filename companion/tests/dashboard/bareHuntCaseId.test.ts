import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #832: the bare per-entity hunt goes to the global /velociraptor/hunt, which cannot know which case
// the analyst is in. The page does know — it names the case in the body so the server can write the
// hunt into that case's activity log.

interface BareHuntApi {
  launchHuntInto: (vql: string, description: string, res: unknown, btn: unknown, ctx?: unknown) => void;
}

function load(caseId: string | null) {
  const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
  const fetch = (url: string, init: { body: string }) => {
    calls.push({ url, body: JSON.parse(init.body) as Record<string, unknown> });
    return Promise.resolve({ ok: false, json: () => Promise.resolve({ error: "stub" }) });
  };
  const api = loadDashboardModule<BareHuntApi>("dashboard-sigma-hunt.js", [], {
    esc: (s: string) => String(s),
    escAttr: (s: string) => String(s),
    enabledHuntPlatforms: new Set(["velociraptor"]),
    veloEnabled: true,
    ICON_DOWNLOAD: "",
    ICON_HUNT: "",
    fetch,
    document: {
      getElementById: (id: string) => (id === "caseId" && caseId !== null ? { value: caseId } : null),
      querySelectorAll: () => [],
    },
  });
  return { api, calls };
}

describe("launchHuntInto — the bare fleet hunt names the active case", () => {
  it("sends the case id from the page so the server can record the hunt in that case", async () => {
    const { api, calls } = load(" c1 ");
    api.launchHuntInto("SELECT 1 FROM scope()", "d", { innerHTML: "" }, null);
    await Promise.resolve();
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/velociraptor/hunt");
    expect(calls[0].body).toEqual({ vql: "SELECT 1 FROM scope()", description: "d", caseId: "c1" });
  });

  it("omits caseId when the page has no case, keeping the case-less contract", async () => {
    const { api, calls } = load(null);
    api.launchHuntInto("SELECT 1 FROM scope()", "d", { innerHTML: "" }, null);
    await Promise.resolve();
    expect(calls[0].body).toEqual({ vql: "SELECT 1 FROM scope()", description: "d" });
  });
});
