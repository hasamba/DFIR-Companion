import { describe, expect, it } from "vitest";
import { dashboardStylesheet, loadDashboardModule } from "../helpers/dashboardModule.js";

interface Api {
  setPresidioPending(findings: { value: string; category: string }[]): void;
}

/** The two elements renderPresidioPending writes: the header badge and the list body. */
function stubDom() {
  const badge = { style: { display: "" }, textContent: "" };
  const el = { innerHTML: "", querySelectorAll: () => [] as unknown[] };
  const els: Record<string, unknown> = { presidioPendingBadge: badge, presidioPending: el };
  return { badge, el, document: { getElementById: (id: string) => els[id] ?? null } };
}

function render(findings: { value: string; category: string }[]) {
  const dom = stubDom();
  const api = loadDashboardModule<Api>("dashboard-presidio.js", ["dashboard-escape.js"], {
    document: dom.document,
  });
  api.setPresidioPending(findings);
  return dom;
}

// A real one. Presidio's PERSON detector is spaCy NER, and a YARA rule name splits into a run of
// capitalized unknown tokens that reads to the model exactly like a first name and a surname.
const LONG = {
  value: "SIGNATURE_BASE_CN_Hacktool_Ssport_Portscanner - C:\\pagefile.sys",
  category: "PERSON",
};
const SHORT = { value: "the Cobalt Strike", category: "PERSON" };

describe("presidio approval rows", () => {
  it("renders one row per finding, with both actions", () => {
    const { el } = render([LONG, SHORT]);
    expect([...el.innerHTML.matchAll(/class="presidio-row"/g)]).toHaveLength(2);
    expect([...el.innerHTML.matchAll(/data-presidio-approve=/g)]).toHaveLength(2);
    expect([...el.innerHTML.matchAll(/data-presidio-suppress=/g)]).toHaveLength(2);
  });

  // THE BUG. The row was an inline `display:flex` with no shrink control, so the buttons — the only
  // items in the line whose labels have a space to break at — soaked up every pixel a long value
  // overflowed by, and the same two buttons came out three lines tall on one row and one line tall
  // on the next. Sizing that has to hold across rows belongs in a rule, not in a style attribute
  // rebuilt per finding, so the assertion is that the row carries NO inline layout at all.
  it("takes its layout from the stylesheet, not from an inline style", () => {
    const { el } = render([LONG]);
    expect(el.innerHTML).not.toContain("display:flex");
    expect(el.innerHTML).toContain('<div class="presidio-row">');
    expect(el.innerHTML).toContain('<span class="presidio-cat">PERSON</span>');
  });

  // The pair is wrapped so it survives a wrap as one block: without it, a value long enough to push
  // the second button onto its own line would leave the two actions on different rows.
  it("keeps the two buttons together in one actions group", () => {
    const { el } = render([LONG]);
    const actions = /<span class="presidio-actions">(.*?)<\/span><\/div>/s.exec(el.innerHTML);
    expect(actions).not.toBeNull();
    expect(actions?.[1]).toContain("Hide from AI");
    expect(actions?.[1]).toContain("Leave visible");
  });

  it("escapes a hostile value in both the text and the attribute", () => {
    const { el } = render([{ value: `<img src=x onerror=alert(1)>"`, category: "PERSON" }]);
    expect(el.innerHTML).not.toContain("<img src=x");
    expect(el.innerHTML).toContain("&lt;img");
    expect(el.innerHTML).toContain('data-presidio-approve="&lt;img src=x onerror=alert(1)&gt;&quot;"');
  });
});

describe("presidio approval row CSS", () => {
  it("lets the value wrap and never shrinks the buttons", () => {
    const css = dashboardStylesheet();
    // The value is the item that must give: it takes the leftover space, is allowed to shrink below
    // its content width, and breaks mid-token because a path has nowhere else to break.
    expect(css).toContain(".presidio-row code { flex:1 1 200px; min-width:0; overflow-wrap:anywhere; }");
    // The buttons are the items that must not.
    expect(css).toContain(".presidio-row .presidio-actions button { flex:none; white-space:nowrap; }");
    expect(css).toContain(
      ".presidio-row .presidio-actions { flex:none; display:flex; gap:8px; margin-left:auto; }",
    );
  });
});
