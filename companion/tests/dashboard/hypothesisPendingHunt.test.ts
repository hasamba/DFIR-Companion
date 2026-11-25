// #2847 — "test via hunt" arms the next deployed hunt to test one hypothesis. The armed link was
// never cleared on a case switch (and the switch wiped its note, so it was also invisible and could
// not be cancelled), so the next hunt deployed in ANOTHER case carried the first case's hypothesis
// id. AI-generated hypothesis ids are a hash of the title, so that id can exist in both cases and
// an empty hunt would count as a miss against an unrelated hypothesis.
//
// The link now remembers the case it was armed in. It is handed out only to a hunt in that case,
// it is always cleared when read, and a hypothesis load for another case drops it.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  loadHypotheses: (caseId: string) => void;
  linkNextHuntToHypothesis: (id: string, title?: string) => void;
  consumePendingHuntHypothesis: (caseId: string) => string | undefined;
  clearPendingHuntHypothesis: () => void;
}

interface El {
  value: string;
  textContent: string;
  innerHTML: string;
  scrollIntoView: () => void;
}

const SAME_ID = "synth:1a2b";
const settle = () => new Promise((r) => setTimeout(r, 10));

function openPage(caseOnScreen: string) {
  const els = new Map<string, El>();
  const el = (id: string): El => {
    const have = els.get(id);
    if (have) return have;
    const made: El = { value: "", textContent: "", innerHTML: "", scrollIntoView: () => {} };
    els.set(id, made);
    return made;
  };
  el("caseId").value = caseOnScreen;
  const globals = {
    document: {
      getElementById: (id: string) => el(id),
      querySelector: (): null => null,
      querySelectorAll: (): unknown[] => [],
      addEventListener: () => {},
    },
    CSS: { escape: (s: string) => s },
    fetch: () => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) }),
  };
  const api = loadDashboardModule<Api>(
    "dashboard-hypotheses.js",
    ["dashboard-escape.js", "dashboard-presidio.js"],
    globals,
  );
  const switchTo = (caseId: string) => {
    el("caseId").value = caseId;
    api.loadHypotheses(caseId);
  };
  return { api, el, switchTo };
}

describe("the pending 'test via hunt' link stays in its own case (#2847)", () => {
  it("a hunt in the case the link was armed in still gets the hypothesis id", () => {
    const { api } = openPage("case-a");
    api.linkNextHuntToHypothesis(SAME_ID, "RDP was the way in");
    expect(api.consumePendingHuntHypothesis("case-a")).toBe(SAME_ID);
    // Read once: the next hunt is not linked again.
    expect(api.consumePendingHuntHypothesis("case-a")).toBeUndefined();
  });

  it("a hunt in another case gets nothing, and the link is gone afterwards", () => {
    const { api } = openPage("case-a");
    api.linkNextHuntToHypothesis(SAME_ID, "RDP was the way in");
    expect(api.consumePendingHuntHypothesis("case-b")).toBeUndefined();
    expect(api.consumePendingHuntHypothesis("case-a")).toBeUndefined();
  });

  it("opening another case drops the link before any hunt is deployed", async () => {
    const { api, switchTo } = openPage("case-a");
    api.linkNextHuntToHypothesis(SAME_ID, "RDP was the way in");
    switchTo("case-b");
    await settle();
    expect(api.consumePendingHuntHypothesis("case-b")).toBeUndefined();
    // Coming back does not revive it — the analyst arms it again if they still want it.
    switchTo("case-a");
    await settle();
    expect(api.consumePendingHuntHypothesis("case-a")).toBeUndefined();
  });

  it("a reload of the same case keeps the link armed", async () => {
    const { api, switchTo } = openPage("case-a");
    api.linkNextHuntToHypothesis(SAME_ID, "RDP was the way in");
    switchTo("case-a");
    await settle();
    expect(api.consumePendingHuntHypothesis("case-a")).toBe(SAME_ID);
  });

  it("the analyst's cancel still clears the link", () => {
    const { api } = openPage("case-a");
    api.linkNextHuntToHypothesis(SAME_ID, "RDP was the way in");
    api.clearPendingHuntHypothesis();
    expect(api.consumePendingHuntHypothesis("case-a")).toBeUndefined();
  });

  it("a recorded hunt deploy asks for the link with the case it deploys into", async () => {
    const asked: unknown[] = [];
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    const hunt = loadDashboardModule<{
      launchHuntInto: (vql: string, d: string, res: unknown, btn: null, ctx: unknown) => void;
    }>("dashboard-sigma-hunt.js", ["dashboard-escape.js"], {
      enabledHuntPlatforms: new Set(["velociraptor"]),
      veloEnabled: true,
      ICON_DOWNLOAD: "",
      ICON_HUNT: "",
      consumePendingHuntHypothesis: (caseId: unknown) => {
        asked.push(caseId);
        return caseId === "case-b" ? SAME_ID : undefined;
      },
      fetch: (url: string, init: { body: string }) => {
        calls.push({ url, body: JSON.parse(init.body) as Record<string, unknown> });
        return Promise.resolve({ ok: false, json: () => Promise.resolve({ error: "stub" }) });
      },
      setTimeout: () => 0,
      document: {
        getElementById: (id: string) => (id === "caseId" ? { value: "case-b" } : null),
        querySelectorAll: () => [],
      },
    });
    hunt.launchHuntInto("SELECT 1 FROM scope()", "d", { innerHTML: "" }, null, {
      caseId: "case-b",
      title: "t",
    });
    await Promise.resolve();
    expect(asked).toEqual(["case-b"]);
    expect(calls[0].body.relatedHypothesisId).toBe(SAME_ID);
  });

  it("a link armed with no case open is never handed to a hunt", () => {
    const { api } = openPage("");
    api.linkNextHuntToHypothesis(SAME_ID, "RDP was the way in");
    expect(api.consumePendingHuntHypothesis("")).toBeUndefined();
  });
});
