import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #832: the bare per-entity hunt goes to the global /velociraptor/hunt, which cannot know which case
// the analyst is in. The page does know — it names the case in the body so the server can write the
// hunt into that case's activity log.

interface BareHuntApi {
  launchHuntInto: (vql: string, description: string, res: unknown, btn: unknown, ctx?: unknown) => void;
}

interface HuntReply {
  ok: boolean;
  body: Record<string, unknown>;
}

const drain = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

function load(caseId: string | null, reply: HuntReply = { ok: false, body: { error: "stub" } }) {
  const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
  const fetch = (url: string, init: { body: string }) => {
    calls.push({ url, body: JSON.parse(init.body) as Record<string, unknown> });
    return Promise.resolve({ ok: reply.ok, json: () => Promise.resolve(reply.body) });
  };
  const api = loadDashboardModule<BareHuntApi>("dashboard-sigma-hunt.js", ["dashboard-escape.js"], {
    enabledHuntPlatforms: new Set(["velociraptor"]),
    veloEnabled: true,
    ICON_DOWNLOAD: "",
    ICON_HUNT: "",
    consumePendingHuntHypothesis: () => undefined,
    fetch,
    setTimeout: () => 0,
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

  it("shows the analyst when the hunt launched but its activity-log append failed", async () => {
    const result = { innerHTML: "", querySelector: () => ({}) };
    const { api, calls } = load("c1", {
      ok: true,
      body: {
        huntId: "H.TEST",
        state: "RUNNING",
        artifact: "Custom.Test",
        sources: [],
        auditWarning: "activity log append failed <EACCES>",
      },
    });

    api.launchHuntInto("SELECT 1 FROM scope()", "d", result, null, { caseId: "c1", title: "Sigma" });
    await drain();

    expect(calls[0].url).toBe("/cases/c1/velociraptor/deploy-hunt");
    expect(result.innerHTML).toContain("activity log append failed &lt;EACCES&gt;");
    expect(result.innerHTML).toContain("H.TEST");
  });

  it("shows the audit warning alongside a failed hunt", async () => {
    const result = { innerHTML: "", querySelector: () => ({}) };
    const { api } = load("c1", {
      ok: false,
      body: {
        error: "hunt launch failed <offline>",
        auditWarning: "activity log append failed <EACCES>",
      },
    });

    api.launchHuntInto("SELECT 1 FROM scope()", "d", result, null, { caseId: "c1", title: "Sigma" });
    await drain();

    expect(result.innerHTML).toContain("activity log append failed &lt;EACCES&gt;");
    expect(result.innerHTML).toContain("hunt launch failed &lt;offline&gt;");
  });
});
