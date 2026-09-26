import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

// #1691: confidence_control_changed and report_template_changed now re-read their controls. The hub
// echoes every push to its sender too, so each loader must never paint a response that is older
// than the analyst's own later edit, older than a later load, or for a case that is no longer open.
const read = (f: string) => readFileSync(new URL(`../../../public/js/${f}`, import.meta.url), "utf8");
const CONF = read("dashboard-confidence-control.js");
const PICKER = read("dashboard-case-template-picker.js");
const CONNECT = read("dashboard-case-connect.js");
const LIVE = read("dashboard-live-socket.js");

type Deferred = {
  url: string;
  init?: { method?: string };
  resolve: (body: unknown) => void;
  reject: (err: Error) => void;
};

function harness(src: string) {
  const els: Record<string, Record<string, unknown>> = {
    caseId: { value: "INC-1" },
    confFilter: { value: "0" },
    hideAutoFindings: { checked: false },
    hideGapFindings: { checked: false },
    "rm-reportTemplate": { value: "", innerHTML: "", addEventListener: () => {} },
  };
  const fetches: Deferred[] = [];
  const timers: Array<() => void> = [];
  const win: Record<string, unknown> = { addEventListener: () => {} };
  const sandbox = {
    window: win,
    document: { getElementById: (id: string) => els[id] ?? null },
    fetch: (url: string, init?: { method?: string }) =>
      new Promise((res, rej) =>
        fetches.push({
          url,
          init,
          resolve: (body) => res({ ok: true, json: async () => body }),
          reject: rej,
        }),
      ),
    setTimeout: (fn: () => void) => timers.push(fn),
    clearTimeout: () => {},
    DfirState: { lastState: () => null },
    esc: (s: unknown) => String(s),
    escAttr: (s: unknown) => String(s),
  };
  runInNewContext(src, sandbox);
  const fn = (name: string) => win[name] as (...a: unknown[]) => unknown;
  const gets = () => fetches.filter((f) => !f.init?.method);
  const puts = () => fetches.filter((f) => f.init?.method === "PUT");
  return { els, fetches, gets, puts, timers, fn };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

describe("confidence control re-read on push (#1691)", () => {
  it("paints the saved values for the open case", async () => {
    const h = harness(CONF);
    h.fn("loadConfidenceControl")("INC-1");
    h.gets()[0].resolve({ minConfidence: 40, hideAutoFindings: true, hideGapFindings: false });
    await settle();
    expect(h.els.confFilter.value).toBe(40);
    expect(h.els.hideAutoFindings.checked).toBe(true);
  });

  it("does not start a load while the analyst's own debounced edit is pending", () => {
    const h = harness(CONF);
    h.fn("saveConfidenceControl")("INC-1", 55);
    h.fn("loadConfidenceControl")("INC-1");
    expect(h.gets()).toHaveLength(0);
  });

  it("drops a response when the analyst typed after the load started", async () => {
    const h = harness(CONF);
    h.els.confFilter.value = "30";
    h.fn("loadConfidenceControl")("INC-1");
    h.els.confFilter.value = "70";
    h.fn("saveConfidenceControl")("INC-1", 70);
    h.gets()[0].resolve({ minConfidence: 30 });
    await settle();
    expect(h.els.confFilter.value).toBe("70");
  });

  it("drops a response when a lens checkbox was clicked after the load started", async () => {
    const h = harness(CONF);
    h.fn("loadConfidenceControl")("INC-1");
    h.els.hideGapFindings.checked = true;
    h.fn("saveFindingOriginFilters")("INC-1", { hideGapFindings: true });
    h.gets()[0].resolve({ minConfidence: 0, hideGapFindings: false });
    await settle();
    expect(h.els.hideGapFindings.checked).toBe(true);
  });

  it("keeps the newest load when two responses arrive in reverse order", async () => {
    const h = harness(CONF);
    h.fn("loadConfidenceControl")("INC-1");
    h.fn("loadConfidenceControl")("INC-1");
    const [older, newer] = h.gets();
    newer.resolve({ minConfidence: 80 });
    await settle();
    older.resolve({ minConfidence: 10 });
    await settle();
    expect(h.els.confFilter.value).toBe(80);
  });

  it("waits for a save still on its way, then re-reads once it lands", async () => {
    const h = harness(CONF);
    h.fn("saveFindingOriginFilters")("INC-1", { hideAutoFindings: true });
    h.fn("loadConfidenceControl")("INC-1");
    expect(h.gets()).toHaveLength(0);
    h.puts()[0].resolve({});
    await settle();
    expect(h.gets()).toHaveLength(1);
    h.gets()[0].resolve({ minConfidence: 0, hideAutoFindings: true });
    await settle();
    expect(h.els.hideAutoFindings.checked).toBe(true);
  });

  it("re-reads the server's value after a save fails", async () => {
    const h = harness(CONF);
    h.els.hideAutoFindings.checked = true;
    h.fn("saveFindingOriginFilters")("INC-1", { hideAutoFindings: true });
    h.fn("loadConfidenceControl")("INC-1");
    h.puts()[0].reject(new Error("offline"));
    await settle();
    h.gets()[0].resolve({ minConfidence: 0, hideAutoFindings: false });
    await settle();
    expect(h.els.hideAutoFindings.checked).toBe(false);
  });

  it("drops a response for a case that is no longer open", async () => {
    const h = harness(CONF);
    h.fn("loadConfidenceControl")("INC-1");
    h.els.caseId.value = "INC-2";
    h.gets()[0].resolve({ minConfidence: 90 });
    await settle();
    expect(h.els.confFilter.value).toBe("0");
  });
});

describe("report-template picker re-read on push (#1691)", () => {
  const list = [
    { id: "standard", name: "Standard" },
    { id: "exec", name: "Executive" },
  ];
  const answer = (h: ReturnType<typeof harness>, from: number, templateId: string) => {
    const pair = h.gets().slice(from, from + 2);
    pair.find((f) => f.url === "/report-templates")!.resolve(list);
    pair.find((f) => f.url !== "/report-templates")!.resolve({ templateId });
  };

  it("paints the saved template for the open case", async () => {
    const h = harness(PICKER);
    h.fn("loadCaseTemplatePicker")("INC-1");
    answer(h, 0, "exec");
    await settle();
    expect(h.els["rm-reportTemplate"].value).toBe("exec");
  });

  it("keeps the newest load when two responses arrive in reverse order", async () => {
    const h = harness(PICKER);
    h.fn("loadCaseTemplatePicker")("INC-1");
    h.fn("loadCaseTemplatePicker")("INC-1");
    answer(h, 2, "exec");
    await settle();
    answer(h, 0, "standard");
    await settle();
    expect(h.els["rm-reportTemplate"].value).toBe("exec");
  });

  it("drops a response when the analyst picked a template after the load started", async () => {
    const h = harness(PICKER);
    h.fn("loadCaseTemplatePicker")("INC-1");
    h.els["rm-reportTemplate"].value = "exec";
    h.fn("saveCaseTemplate")();
    answer(h, 0, "standard");
    await settle();
    expect(h.els["rm-reportTemplate"].value).toBe("exec");
  });

  it("waits for a pick still on its way, then re-reads once it lands", async () => {
    const h = harness(PICKER);
    h.els["rm-reportTemplate"].value = "exec";
    h.fn("saveCaseTemplate")();
    h.fn("loadCaseTemplatePicker")("INC-1");
    expect(h.gets()).toHaveLength(0);
    h.puts()[0].reject(new Error("offline"));
    await settle();
    answer(h, 0, "standard");
    await settle();
    expect(h.els["rm-reportTemplate"].value).toBe("standard");
  });

  it("drops a response for a case that is no longer open", async () => {
    const h = harness(PICKER);
    h.fn("loadCaseTemplatePicker")("INC-1");
    h.els.caseId.value = "INC-2";
    answer(h, 0, "exec");
    await settle();
    expect(h.els["rm-reportTemplate"].value).toBe("");
  });
});

describe("push wiring for the four case-settings events (#1691)", () => {
  const handler = CONNECT.slice(
    CONNECT.indexOf("function handleCaseMessage("),
    CONNECT.indexOf("// Case templates and incident types moved"),
  );

  it("routes the two visible settings to their loaders", () => {
    expect(handler).toMatch(/msg\.type === "confidence_control_changed"\)\s*loadConfidenceControl\(caseId\)/);
    expect(handler).toMatch(/msg\.type === "report_template_changed"\)\s*loadCaseTemplatePicker\(caseId\)/);
  });

  it("leaves the IOC-merge and forensic-gate events out of the reconnect catch-up", () => {
    const list = LIVE.match(/const CATCH_UP_TYPES = \[([\s\S]*?)\];/)![1];
    expect(list).not.toContain("ioc_merge_changed");
    expect(list).not.toContain("forensic_gate_changed");
  });
});
