// The AI-provider pre-flight banner must not move the page when it appears (#1827).
//
// The banner is filled by its own fetch of /diagnostics/preflight after load. As an in-flow block
// between the toolbar and <main>, a late answer pushed all of <main> down by the banner height —
// a load-time layout shift. Reserving a slot does not help: with a configured provider the slot
// must collapse, which is the same shift on the common path. So the banner is a fixed strip at
// the bottom of the viewport (an overlay is not a shift), and the page gets bottom padding of the
// banner's height so the end of the page stays reachable. Padding at the end of the document
// moves nothing above it.
import { describe, expect, it } from "vitest";
import { dashboardStylesheet, loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  initPreflightBanner: () => void;
}

interface FakeEl {
  id?: string;
  hidden: boolean;
  innerHTML: string;
  textContent: string;
  children: FakeEl[];
  offsetHeight: number;
  style: { cssText: string };
  title?: string;
  type?: string;
  onclick?: () => void;
  appendChild: (c: FakeEl) => void;
  setAttribute: (k: string, v: string) => void;
}

function el(): FakeEl {
  const e: FakeEl = {
    hidden: false,
    innerHTML: "",
    textContent: "",
    children: [],
    offsetHeight: 0,
    style: { cssText: "" },
    appendChild(c) {
      e.children.push(c);
    },
    setAttribute(k, v) {
      (e as unknown as Record<string, string>)[k] = v;
    },
  };
  return e;
}

const failing = {
  report: {
    disabled: false,
    anyCriticalFailed: true,
    items: [{ name: "AI provider", ok: false, critical: true, detail: "not configured" }],
  },
};
const passing = {
  report: {
    disabled: false,
    anyCriticalFailed: false,
    items: [{ name: "AI provider", ok: true, critical: true, detail: "reachable" }],
  },
};

function harness(report: unknown, controlOk: boolean | "reject" = true) {
  const banner = el();
  banner.hidden = true;
  banner.offsetHeight = 36;
  const rootVars = new Map<string, string>();
  const observed: FakeEl[] = [];
  let disconnected = 0;
  const calls: string[] = [];
  const toasts: Array<[string, string]> = [];
  class FakeResizeObserver {
    constructor(private cb: () => void) {}
    observe(t: FakeEl) {
      observed.push(t);
      this.cb();
    }
    disconnect() {
      disconnected++;
    }
  }
  const api = loadDashboardModule<Api>("dashboard-preflight-banner.js", ["dashboard-escape.js"], {
    document: {
      getElementById: (id: string) => (id === "preflightBanner" ? banner : null),
      createElement: () => el(),
      documentElement: {
        style: {
          setProperty: (k: string, v: string) => rootVars.set(k, v),
          removeProperty: (k: string) => rootVars.delete(k),
        },
      },
    },
    ResizeObserver: FakeResizeObserver,
    openSettingsTab: () => {},
    showToast: (text: string, kind: string) => toasts.push([text, kind]),
    fetch: async (url: string) => {
      calls.push(url);
      if (url === "/diagnostics/preflight") return { ok: true, json: async () => report };
      if (controlOk === "reject") throw new Error("network down");
      return {
        ok: controlOk,
        status: controlOk ? 200 : 500,
        json: async () => (controlOk ? {} : { error: "cases root is read-only" }),
      };
    },
  });
  return { api, banner, rootVars, observed, calls, toasts, disconnectedCount: () => disconnected };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

describe("pre-flight banner does not shift the page (#1827)", () => {
  it("the stylesheet takes the banner out of flow, fixed to the bottom of the viewport", () => {
    const css = dashboardStylesheet();
    const rule = css.match(/#preflightBanner\s*\{([^}]*)\}/);
    expect(rule, "no #preflightBanner rule").not.toBeNull();
    const decl = rule![1].replace(/\s+/g, "");
    expect(decl).toContain("position:fixed");
    expect(decl).toContain("bottom:0");
  });

  it("the stylesheet sits the banner below modal overlays (z-index 50+)", () => {
    const css = dashboardStylesheet();
    const decl = css.match(/#preflightBanner\s*\{([^}]*)\}/)![1];
    const z = Number(decl.match(/z-index:\s*(\d+)/)?.[1]);
    expect(z).toBeGreaterThan(20); // above the sticky filter bar
    expect(z).toBeLessThan(50); // below .comment-overlay and every other modal
  });

  it("the page's bottom padding follows the banner height", () => {
    const css = dashboardStylesheet().replace(/\s+/g, "");
    expect(css).toMatch(/body\{padding-bottom:var\(--preflight-banner-h,0px\);?\}/);
  });

  it("a toast rises above the banner instead of sitting under it", () => {
    const css = dashboardStylesheet().replace(/\s+/g, "");
    expect(css).toMatch(/\.toast\{[^}]*bottom:calc\(24px\+var\(--preflight-banner-h,0px\)\)/);
  });

  it("a critical failure shows the banner and reserves its height at the page end", async () => {
    const h = harness(failing);
    h.api.initPreflightBanner();
    await settle();
    await settle();
    expect(h.banner.hidden).toBe(false);
    expect(h.observed).toContain(h.banner);
    expect(h.rootVars.get("--preflight-banner-h")).toBe("36px");
  });

  it("dismissing the banner clears the reserved height", async () => {
    const h = harness(failing);
    h.api.initPreflightBanner();
    await settle();
    await settle();
    const dismiss = h.banner.children.find((c) => c.textContent === "✕");
    expect(dismiss).toBeDefined();
    dismiss!.onclick!();
    expect(h.banner.hidden).toBe(true);
    expect(h.rootVars.has("--preflight-banner-h")).toBe(false);
    expect(h.disconnectedCount()).toBe(1);
  });

  it("Disable checks hides the banner only when the server saved the setting", async () => {
    const refused = harness(failing, false);
    refused.api.initPreflightBanner();
    await settle();
    await settle();
    refused.banner.children.find((c) => c.textContent === "Disable checks")!.onclick!();
    await settle();
    await settle();
    expect(refused.banner.hidden).toBe(false);
    expect(refused.rootVars.get("--preflight-banner-h")).toBe("36px");
    expect(refused.toasts).toEqual([
      ["Could not disable the pre-flight checks: cases root is read-only", "warn"],
    ]);

    const offline = harness(failing, "reject");
    offline.api.initPreflightBanner();
    await settle();
    await settle();
    offline.banner.children.find((c) => c.textContent === "Disable checks")!.onclick!();
    await settle();
    await settle();
    expect(offline.banner.hidden).toBe(false);
    expect(offline.toasts).toEqual([["Could not disable the pre-flight checks: network down", "warn"]]);

    const saved = harness(failing, true);
    saved.api.initPreflightBanner();
    await settle();
    await settle();
    saved.banner.children.find((c) => c.textContent === "Disable checks")!.onclick!();
    await settle();
    await settle();
    expect(saved.banner.hidden).toBe(true);
    expect(saved.rootVars.has("--preflight-banner-h")).toBe(false);
    expect(saved.toasts).toHaveLength(0);
  });

  it("a configured provider shows nothing and reserves nothing", async () => {
    const h = harness(passing);
    h.api.initPreflightBanner();
    await settle();
    await settle();
    expect(h.banner.hidden).toBe(true);
    expect(h.rootVars.size).toBe(0);
    expect(h.observed).toHaveLength(0);
  });
});
