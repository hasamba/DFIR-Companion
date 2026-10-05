import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1952: with anonymisation off for a case, no AI call is masked and Presidio never runs — there is
// no masked text for it to scan. The modal's Presidio row read only the Presidio switch, so it still
// said "Presidio is on … New values pause the AI call", which was false. The row now follows the
// anonymisation switch, live, as the analyst ticks it.

interface Api {
  loadAnonToggle(caseId: string): void;
  openAnonModal(): void;
}

function fakeDom() {
  const els: Record<string, Record<string, unknown>> = {};
  const el = (id: string) =>
    (els[id] ??= {
      id,
      value: id === "caseId" ? "INC-1" : "",
      checked: false,
      textContent: "",
      innerHTML: "",
      style: {},
      classList: { add() {}, remove() {}, toggle() {} },
      insertAdjacentHTML(_where: string, html: string) {
        this.innerHTML = String(this.innerHTML) + html;
      },
      querySelectorAll: () => [],
      setAttribute() {},
    });
  return { els, document: { getElementById: el, querySelectorAll: () => [] } };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

async function openWith(enabled: boolean) {
  const dom = fakeDom();
  const control = {
    enabled,
    categories: {},
    redactSecrets: true,
    presidio: true,
    presidioConfigured: true,
    version: "v1",
  };
  const reply = (body: unknown) =>
    Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
  const m = loadDashboardModule<Api>("dashboard-presidio.js", ["dashboard-escape.js"], {
    document: dom.document,
    refreshAiState() {},
    fetch: (url: string) => {
      if (url.endsWith("/anon-control")) return reply(control);
      if (url.endsWith("/anon-entities"))
        return reply({ auto: {}, custom: [], customVersion: 1, suppressed: [] });
      if (url.endsWith("/presidio-health")) return reply({ reachable: true });
      return reply({ pending: [] });
    },
  });
  m.loadAnonToggle("INC-1");
  await flush();
  m.openAnonModal();
  await flush();
  return dom;
}

describe("the Presidio row follows the anonymisation switch (#1952)", () => {
  it("says Presidio does not run when anonymisation is off for the case", async () => {
    const dom = await openWith(false);
    const note = String(dom.els.anonPresidioNote.innerHTML);
    expect(note).toContain("Anonymisation is off for this case");
    expect(note).toContain("Presidio does not run");
    expect(note).not.toContain("Presidio is on");
    expect(String(dom.els.anonPresidioStatus.innerHTML)).toMatch(/not running/i);
  });

  it("says Presidio is on when anonymisation is on", async () => {
    const dom = await openWith(true);
    expect(String(dom.els.anonPresidioNote.innerHTML)).toContain("Presidio is on");
  });

  it("updates live when the analyst ticks or unticks anonymisation", async () => {
    const dom = await openWith(true);
    const box = dom.els.anonEnabled as { checked: boolean; onchange?: () => void };
    expect(typeof box.onchange).toBe("function");
    box.checked = false;
    box.onchange!();
    expect(String(dom.els.anonPresidioNote.innerHTML)).toContain("Presidio does not run");
    box.checked = true;
    box.onchange!();
    expect(String(dom.els.anonPresidioNote.innerHTML)).toContain("Presidio is on");
  });
});
