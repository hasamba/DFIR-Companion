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
  const resizers: (() => void)[] = [];
  const api = loadDashboardModule<Api>("dashboard-watson-layout.js", ["dashboard-escape.js"], {
    document,
    addEventListener: (t: string, cb: () => void) => {
      if (t === "resize") resizers.push(cb);
    },
    innerWidth: opts.innerWidth ?? 1600,
    localStorage: {
      getItem: (k: string) => written[k] ?? null,
      setItem: (k: string, v: string) => (written[k] = v),
    },
    DfirState: { onLastStateChange: () => {} },
  });
  return { api, vars, written, resizers };
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

  it("re-clamps the width when the window shrinks, and returns to the saved width when it grows", () => {
    const { api, vars, written, resizers } = setup({ innerWidth: 1600 });
    api.initWatsonLayout();
    api.watsonSetWidth(900);
    expect(vars["--watson-width"]).toBe("900px");
    const win = api as unknown as { innerWidth: number };
    win.innerWidth = 1000;
    resizers.forEach((cb) => cb());
    expect(vars["--watson-width"]).toBe("700px");
    expect(written["dfir.watson.width"]).toBe("900");
    win.innerWidth = 1600;
    resizers.forEach((cb) => cb());
    expect(vars["--watson-width"]).toBe("900px");
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

  it("has two columns, Key questions and Next steps, closed by default as book spines with counts", () => {
    const view = read("../../../public/js/dashboard-watson-view.js");
    expect(view).toContain('<details class="watson-board-sec" data-w-sec="questions"><summary');
    expect(view).toContain('<details class="watson-board-sec" data-w-sec="steps"><summary');
    expect(view).toContain('Key questions<span data-w="boardqcount"></span>');
    expect(view).toContain('Next steps<span data-w="boardnextcount"></span>');
    expect(view).toContain('data-w="boardnext"');
    const css = read("../../../public/css/dashboard-watson.css");
    expect(css).toContain(
      ".watson-board-sec:not([open]) > summary { list-style: none; writing-mode: vertical-rl;",
    );
  });

  it("restores a column the analyst opened, and counts both columns from the case state", () => {
    const sections = [
      { dataset: { wSec: "questions" }, open: false },
      { dataset: { wSec: "steps" }, open: false },
    ];
    const counts: Record<string, { textContent: string; innerHTML?: string }> = {
      boardqcount: { textContent: "" },
      boardnextcount: { textContent: "" },
      boardnext: { textContent: "", innerHTML: "" },
    };
    let onState: ((st: unknown) => void) | null = null;
    const document = {
      documentElement: { style: { setProperty: () => {} } },
      querySelector: () => null,
      querySelectorAll: (sel: string) => {
        if (sel === "[data-w-sec]") return sections;
        const m = /data-w="(\w+)"/.exec(sel);
        return m && counts[m[1]] ? [counts[m[1]]] : [];
      },
      addEventListener: () => {},
    };
    const api = loadDashboardModule<Api>("dashboard-watson-layout.js", ["dashboard-escape.js"], {
      document,
      addEventListener: () => {},
      innerWidth: 1600,
      localStorage: {
        getItem: (k: string) => (k === "dfir.watson.board.steps" ? "open" : null),
        setItem: () => {},
      },
      DfirState: { onLastStateChange: (fn: (st: unknown) => void) => (onState = fn) },
    });
    api.initWatsonLayout();
    expect(sections.map((d) => d.open)).toEqual([false, true]);
    onState!({ keyQuestions: [{}, {}, {}], nextSteps: [{ action: "a", priority: "high" }] });
    expect(counts.boardqcount.textContent).toBe(" (3)");
    expect(counts.boardnextcount.textContent).toBe(" (1)");
  });
});

describe("the jump-to-latest arrow", () => {
  it("shows when the chat is scrolled up, hides at the end, and scrolls to the end", () => {
    const log = {
      scrollHeight: 1000,
      clientHeight: 300,
      scrollTop: 100,
      scrollTo(o: { top: number }) {
        this.scrollTop = o.top;
      },
    };
    const btn = { hidden: true, closest: () => wrap };
    const wrap = { querySelector: (sel: string) => (sel === ".watson-log" ? log : btn) };
    const document = {
      documentElement: { style: { setProperty: () => {} } },
      querySelector: () => null,
      querySelectorAll: (sel: string) => (sel === ".watson-logwrap" ? [wrap] : []),
      addEventListener: () => {},
    };
    const api = loadDashboardModule<Api & { watsonJumpSync(): void; watsonJumpEnd(b: unknown): void }>(
      "dashboard-watson-layout.js",
      ["dashboard-escape.js"],
      {
        document,
        addEventListener: () => {},
        innerWidth: 1600,
        localStorage: { getItem: () => null, setItem: () => {} },
      },
    );
    api.watsonJumpSync();
    expect(btn.hidden).toBe(false);
    api.watsonJumpEnd(btn);
    expect(log.scrollTop).toBe(1000);
    expect(btn.hidden).toBe(true);
    log.scrollTop = 690; // within 40 px of the end
    api.watsonJumpSync();
    expect(btn.hidden).toBe(true);
  });

  it("sits at the bottom centre of the chat log", () => {
    const view = read("../../../public/js/dashboard-watson-view.js");
    expect(view).toContain(
      'class="watson-jump" data-act="watsonJumpEnd" aria-label="Jump to the latest message"',
    );
    expect(read("../../../public/js/dashboard-data-act.js")).toContain(
      "watsonJumpEnd: (el) => watsonJumpEnd(el)",
    );
    const css = read("../../../public/css/dashboard-watson.css");
    expect(css).toContain(
      ".watson-jump { position: absolute; left: 50%; bottom: 10px; transform: translateX(-50%);",
    );
  });
});
