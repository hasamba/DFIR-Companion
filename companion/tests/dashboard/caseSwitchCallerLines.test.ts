// #2937 (items 6 and 7): modules that own no case — whitelist and NSRL Apply, the false-positive
// modal, Synthesize, import undo — wrote their own status line and follow-up reads with no check.
// They now ask DfirPanelDefer.actionLive, which moves only when another case opens or a load is
// cancelled: a reopen of the same case keeps their answers.
import { describe, expect, it } from "vitest";
import { drainAll, fakePage } from "../helpers/caseSwitchPage.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

type Page = ReturnType<typeof fakePage>;
type Api = Record<string, (...args: unknown[]) => unknown> & { activeCaseId?: string | null };
const ESC = ["dashboard-escape.js", "dashboard-time.js", "dashboard-text.js", "dashboard-values.js"];
const last = (p: Page) => p.requests.length - 1;

/** Cancel, then open case A again (a full case open: reset listeners run). */
function cancelAndOpen(p: Page, api: object) {
  p.cancel(api);
  p.open("CASE-A", api);
}

describe.each([
  ["dashboard-ioc-whitelist.js", "wlApplyToCase", "wlApplyMsg", { matched: 1, added: 1 }, "matched"],
  [
    "dashboard-nsrl.js",
    "nsrlApplyToCase",
    "nsrlApplyMsg",
    { matchedIocs: 1, matchedEvents: 0, added: 1 },
    "matched",
  ],
])("%s Apply line (#2937)", (file, fn, msgId, answer, word) => {
  function load() {
    const p = fakePage();
    const api = loadDashboardModule<Api>(file, ESC, { ...p.globals, commitFalsePositives: () => {} });
    return { p, api };
  }

  it("a cancel clears 'applying…', and the old answer writes nothing", async () => {
    const { p, api } = load();
    api[fn]();
    const old = last(p);
    expect(p.el(msgId).textContent).toContain("applying");
    cancelAndOpen(p, api);
    expect(p.el(msgId).textContent).toBe("");
    p.requests[old].answer(answer);
    await drainAll();
    expect(p.el(msgId).textContent).not.toContain(word);
  });

  it("another case opening clears a finished line; reopening the same case keeps it", async () => {
    const { p, api } = load();
    api[fn]();
    p.open("CASE-A", api);
    p.requests[last(p)].answer(answer);
    await drainAll();
    expect(p.el(msgId).textContent).toContain(word);
    p.open("CASE-A", api);
    expect(p.el(msgId).textContent).toContain(word);
    p.open("CASE-B", api);
    expect(p.el(msgId).textContent).toBe("");
  });
});

describe("false-positive modal (#2937)", () => {
  function modal() {
    const p = fakePage();
    const done: string[] = [];
    const api = loadDashboardModule<Api>("dashboard-false-positive.js", ESC, {
      ...p.globals,
      commitFalsePositives: () => {},
      investigatorName: () => "analyst",
    });
    api.initFalsePositiveModal();
    return { p, api, done };
  }
  const confirm = (p: Page) => p.el("fpConfirmBtn").fire("click");

  it("a Save answering after a cancel closes nothing, runs no onDone and writes no status", async () => {
    const { p, api, done } = modal();
    api.openFalsePositiveModal("ioc", "IOC-ONE", "x", [], () => done.push("old"));
    confirm(p);
    await drainAll();
    const old = last(p);
    cancelAndOpen(p, api);
    api.openFalsePositiveModal("ioc", "IOC-TWO", "y", [], () => done.push("new"));
    p.requests[old].answer([]);
    await drainAll();
    expect(done).toEqual([]);
    expect(p.el("status").textContent).not.toContain("marked false positive");
    const before = p.requests.length;
    confirm(p);
    await drainAll();
    expect(p.requests.length, "the reopened modal was closed by the old answer").toBe(before + 1);
  });

  it("a Save answering after a same-case modal reopen leaves the new modal open", async () => {
    const { p, api, done } = modal();
    api.openFalsePositiveModal("ioc", "IOC-ONE", "x", [], () => done.push("old"));
    confirm(p);
    await drainAll();
    const old = last(p);
    api.openFalsePositiveModal("ioc", "IOC-TWO", "y");
    p.requests[old].answer([]);
    await drainAll();
    expect(p.el("status").textContent).toContain("marked false positive");
    const before = p.requests.length;
    confirm(p);
    await drainAll();
    expect(p.requests.length).toBe(before + 1);
  });

  it("a Save with no switch still closes, runs onDone and says so", async () => {
    const { p, api, done } = modal();
    api.openFalsePositiveModal("ioc", "IOC-ONE", "x", [], () => done.push("old"));
    confirm(p);
    await drainAll();
    p.open("CASE-A", api);
    p.requests[last(p)].answer([]);
    await drainAll();
    expect(done).toEqual(["old"]);
    expect(p.el("status").textContent).toContain("marked false positive");
  });

  it("the first similar-items answer does not fill a modal opened after it", async () => {
    const { p, api } = modal();
    api.openFalsePositiveModal("event", "e1", "x");
    const old = last(p);
    api.openFalsePositiveModal("event", "e2", "y");
    p.requests[last(p)].answer({ candidates: [] });
    await drainAll();
    p.requests[old].answer({ candidates: [{ id: "OLD-CANDIDATE", kind: "event", label: "OLD-CANDIDATE" }] });
    await drainAll();
    expect(p.el("fpCandidates").innerHTML).not.toContain("OLD-CANDIDATE");
  });
});

describe("Synthesize (#2937)", () => {
  function scope() {
    const p = fakePage();
    const rendered: unknown[] = [];
    const api = loadDashboardModule<Api>("dashboard-search-scope.js", ESC, {
      ...p.globals,
      setAi: () => {},
      refreshAiState: () => {},
      loadSynthMeta: () => {},
      render: (s: unknown) => rendered.push(s),
      confirm: () => true,
    });
    return { p, api, rendered };
  }
  const OK = { findings: 3, mitreTechniques: 1 };

  it("an answer after a cancel writes no status and reads no state", async () => {
    const { p, api } = scope();
    api.resynthesize();
    const old = last(p);
    cancelAndOpen(p, api);
    p.el("status").textContent = "REOPENED";
    p.requests[old].answer(OK);
    await drainAll();
    expect(p.el("status").textContent).toBe("REOPENED");
    expect(p.urls().slice(old + 1)).not.toContain("/cases/CASE-A/state");
  });

  it("a reopen of the same case keeps the answer, and its state read renders", async () => {
    const { p, api, rendered } = scope();
    api.resynthesize();
    const old = last(p);
    p.open("CASE-A", api);
    p.requests[old].answer(OK);
    await drainAll();
    expect(p.el("status").textContent).toContain("synthesized: 3 findings");
    p.requests[last(p)].answer({ caseId: "CASE-A" });
    await drainAll();
    expect(rendered).toHaveLength(1);
  });

  it("a state read answering after a cancel does not render", async () => {
    const { p, api, rendered } = scope();
    api.resynthesize();
    p.requests[last(p)].answer(OK);
    await drainAll();
    const read = last(p);
    expect(p.requests[read].url).toBe("/cases/CASE-A/state");
    cancelAndOpen(p, api);
    p.requests[read].answer({ caseId: "CASE-A" });
    await drainAll();
    expect(rendered).toEqual([]);
  });
});

describe("import undo (#2937)", () => {
  function undo() {
    const p = fakePage();
    const rendered: unknown[] = [];
    const api = loadDashboardModule<Api>("dashboard-import-undo.js", ESC, {
      ...p.globals,
      render: (s: unknown) => rendered.push(s),
      loadImportMeta: () => {},
    });
    return { p, api, rendered };
  }
  async function stackLoaded(p: Page, api: Api) {
    void api.loadUndoStack("CASE-A");
    p.requests[last(p)].answer({ canUndo: true, canRedo: false });
    await drainAll();
  }

  it("the follow-up state read answering after a cancel does not render", async () => {
    const { p, api, rendered } = undo();
    await stackLoaded(p, api);
    api.doImportUndoRedo("undo");
    p.requests[last(p)].answer({});
    await drainAll();
    const read = p.requests.findIndex((r) => r.url === "/cases/CASE-A/state");
    cancelAndOpen(p, api);
    p.requests[read].answer({ caseId: "CASE-A" });
    await drainAll();
    expect(rendered).toEqual([]);
  });

  it("an undo answering after cancel and reopen still re-reads the stack (#2413), but reads no state", async () => {
    const { p, api } = undo();
    await stackLoaded(p, api);
    api.doImportUndoRedo("undo");
    const old = last(p);
    cancelAndOpen(p, api);
    void api.loadUndoStack("CASE-A");
    const before = p.requests.length;
    p.requests[old].answer({});
    await drainAll();
    const after = p.urls().slice(before);
    expect(after).toContain("/cases/CASE-A/import/undo-stack");
    expect(after).not.toContain("/cases/CASE-A/state");
  });

  it("with no switch the state read renders", async () => {
    const { p, api, rendered } = undo();
    await stackLoaded(p, api);
    api.doImportUndoRedo("undo");
    p.requests[last(p)].answer({});
    await drainAll();
    p.requests.find((r) => r.url === "/cases/CASE-A/state")!.answer({ caseId: "CASE-A" });
    await drainAll();
    expect(rendered).toHaveLength(1);
  });
});
