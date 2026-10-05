// Presidio unreachable: offer Retry, or Continue without Presidio for this case (#1945).
//
// A failed AI call because the analyzer is down used to leave a red pill and nothing to press. The
// only escape the message named was "clear DFIR_PRESIDIO_URL", which needs a restart. The per-case
// untick already worked at once, but it sat three clicks away in the Anonymization panel.
//
// These cases pin that the two buttons appear ONLY when the server's health probe says the analyzer
// does not answer (never from the error text), and that "continue" is the per-case switch, posted
// with the version the dashboard loaded, so the route's activity entry records the choice.
import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { dashboardStylesheet, loadDashboardModule } from "../helpers/dashboardModule.js";

interface AiStatusApi {
  applyAiStatus: (evt: Record<string, unknown>) => void;
}

interface Btn {
  style: Record<string, string>;
  textContent: string;
  title: string;
  onclick: (() => unknown) | null;
  setAttribute: (k: string, v: string) => void;
  attrs: Record<string, string>;
}
const btn = (): Btn => {
  const b: Btn = {
    style: { display: "none" },
    textContent: "",
    title: "",
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

interface Opts {
  reachable: boolean | undefined;
  presidio?: boolean;
  configured?: boolean;
  postStatus?: number;
}

function page(opts: Opts) {
  const els: Record<string, unknown> = {
    aiStatus: { className: "", textContent: "", title: "" },
    status: { textContent: "" },
    presidioRetryBtn: btn(),
    presidioContinueBtn: btn(),
  };
  const calls: Call[] = [];
  const health = { reachable: opts.reachable };
  const counters = { resynth: 0, anonReload: 0 };
  const json = (body: unknown, status = 200) =>
    Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body) });
  const globals = {
    document: { getElementById: (id: string) => els[id] ?? null },
    fetch: (url: string, init?: { method?: string; body?: string }) => {
      const method = init?.method ?? "GET";
      calls.push({ url, method, body: init?.body ? JSON.parse(init.body) : undefined });
      if (url === "/system/presidio-health")
        return json({ configured: true, url: "http://localhost:5002", ...health });
      if (url.endsWith("/anon-control") && method === "GET")
        return json({
          presidioConfigured: opts.configured ?? true,
          presidio: opts.presidio ?? true,
          version: "v-7",
        });
      if (url.endsWith("/anon-control") && method === "POST")
        return json({ presidio: false, version: "v-8" }, opts.postStatus ?? 200);
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
    resynthesize: () => {
      counters.resynth += 1;
    },
    loadAnonToggle: () => {
      counters.anonReload += 1;
    },
    ws: null,
  };
  const api = loadDashboardModule<AiStatusApi>("dashboard-ai-status.js", [], globals);
  return {
    api,
    calls,
    health,
    counters,
    retry: els.presidioRetryBtn as Btn,
    cont: els.presidioContinueBtn as Btn,
    status: els.status as { textContent: string },
  };
}

const settle = () => new Promise((r) => setTimeout(r, 0));
const ERROR = {
  status: "error",
  detail: "Presidio is not reachable at http://localhost:5002. The AI call did not run.",
};

describe("Presidio unreachable — the two actions on the error pill (#1945)", () => {
  it("shows Retry and Continue when the probe says the analyzer does not answer", async () => {
    const p = page({ reachable: false });
    p.api.applyAiStatus(ERROR);
    await settle();
    expect(p.retry.style.display).toBe("");
    expect(p.cont.style.display).toBe("");
    // The probe decided, not the error text.
    expect(p.calls.some((c) => c.url === "/system/presidio-health")).toBe(true);
  });

  it("shows nothing when the analyzer answers", async () => {
    const p = page({ reachable: true });
    p.api.applyAiStatus({ status: "error", detail: "provider rate limit" });
    await settle();
    expect(p.retry.style.display).toBe("none");
    expect(p.cont.style.display).toBe("none");
  });

  it("shows nothing when Presidio is already off for the case, and never probes", async () => {
    const p = page({ reachable: false, presidio: false });
    p.api.applyAiStatus(ERROR);
    await settle();
    expect(p.retry.style.display).toBe("none");
    expect(p.calls.some((c) => c.url === "/system/presidio-health")).toBe(false);
  });

  it("shows nothing when no analyzer is configured", async () => {
    const p = page({ reachable: false, configured: false });
    p.api.applyAiStatus(ERROR);
    await settle();
    expect(p.cont.style.display).toBe("none");
  });

  it("Continue posts presidio:false with the loaded version, then re-synthesizes", async () => {
    const p = page({ reachable: false });
    p.api.applyAiStatus(ERROR);
    await settle();
    await p.cont.onclick?.();
    await settle();
    const post = p.calls.find((c) => c.method === "POST");
    expect(post?.url).toBe("/cases/INC-1/anon-control");
    // Only the Presidio switch: the built-in masking settings are left as they are.
    expect(post?.body).toEqual({ presidio: false, version: "v-7" });
    expect(p.counters.resynth).toBe(1);
    expect(p.counters.anonReload, "the Anon toggle must re-read the saved control").toBe(1);
    expect(p.cont.style.display).toBe("none");
    expect(p.retry.style.display).toBe("none");
  });

  it("Continue changes nothing and runs nothing on a stale save", async () => {
    const p = page({ reachable: false, postStatus: 409 });
    p.api.applyAiStatus(ERROR);
    await settle();
    await p.cont.onclick?.();
    await settle();
    expect(p.counters.resynth).toBe(0);
    expect(p.status.textContent).toMatch(/another window/);
  });

  it("never continues on its own — the error alone posts nothing", async () => {
    const p = page({ reachable: false });
    p.api.applyAiStatus(ERROR);
    await settle();
    expect(p.calls.some((c) => c.method === "POST")).toBe(false);
    expect(p.counters.resynth).toBe(0);
  });

  it("Retry re-probes and re-synthesizes only once the analyzer answers", async () => {
    const p = page({ reachable: false });
    p.api.applyAiStatus(ERROR);
    await settle();
    await p.retry.onclick?.();
    await settle();
    expect(p.counters.resynth, "still down: no run").toBe(0);
    expect(p.status.textContent).toMatch(/still not reachable/);
    p.health.reachable = true;
    await p.retry.onclick?.();
    await settle();
    expect(p.counters.resynth).toBe(1);
    expect(p.retry.style.display).toBe("none");
  });

  it("hides the actions once the case goes back to idle", async () => {
    const p = page({ reachable: false });
    p.api.applyAiStatus(ERROR);
    await settle();
    p.api.applyAiStatus({ status: "idle", at: "2026-10-05T00:00:00Z" });
    expect(p.retry.style.display).toBe("none");
    expect(p.cont.style.display).toBe("none");
  });
});

describe("Presidio unreachable — markup and toolbar icons", () => {
  const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
  const css = dashboardStylesheet();

  it("has both buttons, hidden until the probe says so", () => {
    for (const id of ["presidioRetryBtn", "presidioContinueBtn"]) {
      const tag = html.match(new RegExp(`<button id="${id}"[^>]*>`))?.[0] ?? "";
      expect(tag, `${id} markup`).not.toBe("");
      expect(tag).toContain("display:none");
    }
    expect(html).toContain("Continue without Presidio for this case");
  });

  it("gives each button a ::before icon so it survives the icons-only collapse", () => {
    for (const id of ["presidioRetryBtn", "presidioContinueBtn"]) {
      expect(css, `${id} icon rule`).toMatch(new RegExp(`#${id}::before\\s*\\{[^}]*background-image`));
      // And in the shared sizing rule, or ::before has no box to paint into.
      expect(css).toMatch(
        new RegExp(`#${id}::before[,\\s][\\s\\S]{0,800}background: no-repeat center / contain;`),
      );
    }
  });
});
