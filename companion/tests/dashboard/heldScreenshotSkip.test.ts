// #2498: "AI: error — N screenshot(s) could not be analyzed" offered only a retry. The Skip button
// lets the analyst accept the gap. These cases pin that it shows only for a real hold (read from
// GET ai-state, never from the error text), posts the token it was shown with, is bound to the case
// it was shown for, and that a stale answer cannot bring it back after a skip.
import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { dashboardStylesheet, loadDashboardModule } from "../helpers/dashboardModule.js";

interface AiStatusApi {
  applyAiStatus: (evt: Record<string, unknown>) => void;
  refreshAiState: (caseId: string) => Promise<void>;
}

interface Btn {
  style: Record<string, string>;
  onclick: (() => unknown) | null;
  setAttribute: (k: string, v: string) => void;
  attrs: Record<string, string>;
}
const btn = (): Btn => {
  const b: Btn = {
    style: { display: "none" },
    onclick: null,
    attrs: {},
    setAttribute: (k, v) => {
      b.attrs[k] = v;
    },
  };
  return b;
};

interface Call {
  url: string;
  method: string;
  body?: Record<string, unknown>;
}

const HOLD = { count: 13, gaveUp: true, token: "tok-1", lastError: "401 invalid api key" };

function page(
  opts: { hold?: typeof HOLD | null; postStatus?: number; postBody?: Record<string, unknown> } = {},
) {
  const els: Record<string, unknown> = {
    aiStatus: { className: "", textContent: "", title: "" },
    status: { textContent: "" },
    heldSkipBtn: btn(),
  };
  const calls: Call[] = [];
  const state = { hold: opts.hold === undefined ? HOLD : opts.hold };
  const json = (body: unknown, status = 200) =>
    Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) });
  const globals = {
    document: { getElementById: (id: string) => els[id] ?? null },
    fetch: (url: string, init?: { method?: string; body?: string }) => {
      const method = init?.method ?? "GET";
      calls.push({ url, method, body: init?.body ? JSON.parse(init.body) : undefined });
      if (url.endsWith("/ai-state") && method === "GET")
        return json({
          state: state.hold ? "error" : "idle",
          detail: "x",
          holds: [],
          running: [],
          screenshotHold: state.hold,
        });
      if (url.endsWith("/skip-held-screenshots")) {
        const status = opts.postStatus ?? 200;
        if (status === 200) state.hold = null;
        return json(opts.postBody ?? { skipped: 13, remaining: 0, sequenceNumbers: [] }, status);
      }
      if (url === "/system/presidio-health") return json({ reachable: true });
      if (url.endsWith("/anon-control")) return json({ presidioConfigured: false });
      return json({});
    },
    setAi: () => {},
    showImportProgress: () => {},
    hideImportProgress: () => {},
    fmtTime: () => "",
    aiEnabled: true,
    activeCaseId: "INC-1",
    loadHostDuplicates: () => {},
    loadRelatedCases: () => {},
    loadPresidioPending: () => {},
    ws: null,
  };
  const api = loadDashboardModule<AiStatusApi>("dashboard-ai-status.js", [], globals);
  return {
    api,
    calls,
    state,
    // The sandbox IS the page's global object: switching case is a write to it.
    switchCase: (id: string) => ((api as unknown as Record<string, unknown>).activeCaseId = id),
    skip: els.heldSkipBtn as Btn,
    status: els.status as { textContent: string },
  };
}

// The fetch stubs resolve at once, so every await chain drains as microtasks before one timer tick.
const settle = () => new Promise((r) => setTimeout(r, 0));

describe("Skip screenshots the AI could not analyze (#2498)", () => {
  it("shows Skip when ai-state reports a hold, with the reason in the tooltip", async () => {
    const p = page();
    await p.api.refreshAiState("INC-1");
    expect(p.skip.style.display).toBe("");
    expect(p.skip.attrs["data-tip"]).toContain("13 screenshot(s)");
    expect(p.skip.attrs["data-tip"]).toContain("401 invalid api key");
    expect(p.skip.attrs["data-tip"]).toContain("saved as evidence");
  });

  it("stays hidden without a hold", async () => {
    const p = page({ hold: null });
    await p.api.refreshAiState("INC-1");
    expect(p.skip.style.display).toBe("none");
  });

  it("a pushed error checks ai-state for a hold rather than reading the error text", async () => {
    const p = page();
    p.api.applyAiStatus({ status: "error", detail: "provider down" });
    await settle();
    expect(p.calls.some((c) => c.url.endsWith("/ai-state"))).toBe(true);
    expect(p.skip.style.display).toBe("");
  });

  it("posts the token it was shown with, then hides and refreshes", async () => {
    const p = page();
    await p.api.refreshAiState("INC-1");
    await p.skip.onclick!();
    await settle();
    const post = p.calls.find((c) => c.method === "POST");
    expect(post?.url).toBe("/cases/INC-1/ai-state/skip-held-screenshots");
    expect(post?.body).toEqual({ token: "tok-1" });
    expect(p.skip.style.display).toBe("none");
    expect(p.status.textContent).toMatch(/skipped AI analysis of 13 screenshot\(s\)/);
  });

  it("says when the activity log entry could not be written", async () => {
    const p = page({ postBody: { skipped: 13, remaining: 0, warning: "activity log append failed" } });
    await p.api.refreshAiState("INC-1");
    await p.skip.onclick!();
    await settle();
    expect(p.status.textContent).toMatch(/activity log/);
  });

  it("a 409 says the screenshots changed and re-checks instead of skipping", async () => {
    const p = page({ postStatus: 409, postBody: { error: "changed" } });
    await p.api.refreshAiState("INC-1");
    await p.skip.onclick!();
    await settle();
    expect(p.status.textContent).toMatch(/changed/);
    expect(p.calls.filter((c) => c.url.endsWith("/ai-state")).length).toBeGreaterThan(1);
  });

  it("never posts for a case the analyst has left", async () => {
    const p = page();
    await p.api.refreshAiState("INC-1");
    p.switchCase("INC-2");
    await p.skip.onclick!();
    expect(p.calls.some((c) => c.method === "POST")).toBe(false);
    expect(p.skip.style.display).toBe("none");
  });

  it("a newer pushed status hides the button", async () => {
    const p = page();
    await p.api.refreshAiState("INC-1");
    p.api.applyAiStatus({ status: "analyzing", phase: "extracting", detail: "retrying 13 screenshot(s)" });
    expect(p.skip.style.display).toBe("none");
  });
});

describe("Skip screenshots — markup and toolbar icon", () => {
  const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  const css = dashboardStylesheet();

  it("has the button, hidden until a hold is reported, with a short visible label", () => {
    const tag = html.match(/<button id="heldSkipBtn"[^>]*>([^<]*)</);
    expect(tag?.[0]).toContain("display:none");
    expect(tag?.[1]).toBe("Skip screenshots");
  });

  it("has a ::before icon and keeps its label in the icons-only collapse", () => {
    expect(css).toMatch(/#heldSkipBtn::before\s*\{[^}]*background-image/);
    expect(css).toMatch(/#heldSkipBtn::before[,\s][\s\S]{0,800}background: no-repeat center \/ contain;/);
    expect(css).toMatch(/\.toolbar-main\.icons-only #heldSkipBtn\s*\{[^}]*font-size:\s*12px/);
  });
});
