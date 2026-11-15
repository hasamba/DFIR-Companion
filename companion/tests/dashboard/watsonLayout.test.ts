// The Watson panel's width (drag the left edge, saved per browser) and the full-screen board's two
// collapsible columns: Key questions and Next steps. Runs the real module in a vm with a fake DOM.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

type Api = {
  watsonNextStepsHtml(steps: unknown[]): string;
  watsonSetWidth(px: number): number;
  initWatsonLayout(): void;
};

function setup(opts: { stored?: Record<string, string>; innerWidth?: number } = {}) {
  const vars: Record<string, string> = {};
  const written: Record<string, string> = { ...opts.stored };
  const document = {
    documentElement: { style: { setProperty: (k: string, v: string) => (vars[k] = v) } },
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => {},
  };
  const api = loadDashboardModule<Api>("dashboard-watson-layout.js", ["dashboard-escape.js"], {
    document,
    innerWidth: opts.innerWidth ?? 1600,
    localStorage: {
      getItem: (k: string) => written[k] ?? null,
      setItem: (k: string, v: string) => (written[k] = v),
    },
    DfirState: { onLastStateChange: () => {} },
  });
  return { api, vars, written };
}

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8").replace(/\r\n/g, "\n");

describe("Watson panel width", () => {
  it("sets and saves the width, kept between 300 px and 70% of the window", () => {
    const { api, vars, written } = setup({ innerWidth: 1000 });
    expect(api.watsonSetWidth(500)).toBe(500);
    expect(vars["--watson-width"]).toBe("500px");
    expect(written["dfir.watson.width"]).toBe("500");
    expect(api.watsonSetWidth(100)).toBe(300);
    expect(api.watsonSetWidth(5000)).toBe(700);
  });

  it("restores a saved width at start, and ignores a bad one", () => {
    const a = setup({ stored: { "dfir.watson.width": "480" } });
    a.api.initWatsonLayout();
    expect(a.vars["--watson-width"]).toBe("480px");
    const b = setup({ stored: { "dfir.watson.width": "abc" } });
    b.api.initWatsonLayout();
    expect(b.vars["--watson-width"]).toBeUndefined();
  });

  it("the panel and the page padding follow the width variable, and the panel has a resize handle", () => {
    const css = read("../../../public/css/dashboard-watson.css");
    expect(css).toContain("width: var(--watson-width, 360px)");
    expect(css).toContain("padding-right: var(--watson-width, 360px)");
    const view = read("../../../public/js/dashboard-watson-view.js");
    expect(view).toContain(
      'class="watson-resize" role="separator" aria-orientation="vertical" aria-label="Resize Watson"',
    );
    expect(read("../../../public/js/dashboard-data-act.js")).toContain("initWatsonLayout()");
  });
});

describe("the full-screen board", () => {
  it("lists the next steps, most important first as the case keeps them, escaped", () => {
    const { api } = setup();
    const html = api.watsonNextStepsHtml([
      { id: "n1", priority: "high", action: "Collect <script>", pointer: "WS-FAKE01", rationale: "why" },
      { id: "n2", priority: "medium", action: "Check sshd", pointer: "", rationale: "" },
    ]);
    expect(html).toContain("Collect &lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html.indexOf("Collect")).toBeLessThan(html.indexOf("Check sshd"));
    expect(html).toContain("→ WS-FAKE01");
    expect(api.watsonNextStepsHtml([])).toContain("There are no next steps.");
  });

  it("has two collapsible columns: Key questions and Next steps", () => {
    const view = read("../../../public/js/dashboard-watson-view.js");
    expect(view).toContain(
      '<details class="watson-board-sec" data-w-sec="questions" open><summary>Key questions',
    );
    expect(view).toContain('<details class="watson-board-sec" data-w-sec="steps" open><summary>Next steps');
    expect(view).toContain('data-w="boardnext"');
  });
});
