// #2413: one click on Undo import undoes exactly one import.
//
// The Undo/Redo buttons had two writers: the undo click (disables both) and renderUndoStack, fed by
// the case load and by the import_undo_changed push. A push arriving while an undo was in flight
// re-enabled both buttons, so a second click rolled back a second import. The undo-stack read also
// had no case check, so an answer for the case being left could label the next case's buttons.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface UndoApi {
  loadUndoStack: (caseId: string) => void;
  doImportUndoRedo: (which: "undo" | "redo") => void;
}

interface Call {
  url: string;
  method: string;
  resolve: (v: unknown) => void;
}

const SUMMARY = {
  canUndo: true,
  canRedo: false,
  nextUndo: { label: "evtx", events: 1, iocs: 0, findings: 0 },
};

function harness() {
  const btn = () => ({
    disabled: false,
    textContent: "",
    style: { display: "" },
    dataset: {} as Record<string, string>,
  });
  const undoBtn = btn();
  const redoBtn = btn();
  const caseEl = { value: "A" };
  const elements: Record<string, unknown> = {
    importUndoBtn: undoBtn,
    importRedoBtn: redoBtn,
    caseId: caseEl,
  };
  const calls: Call[] = [];
  const alerts: string[] = [];
  const api = loadDashboardModule<UndoApi>("dashboard-import-undo.js", [], {
    document: { getElementById: (id: string) => elements[id] ?? null },
    fetch: (url: string, init?: { method?: string }) =>
      new Promise((resolve) => calls.push({ url, method: init?.method ?? "GET", resolve })),
    render: () => {},
    loadImportMeta: () => {},
    alert: (m: string) => alerts.push(m),
  });
  const ok = (c: Call, body: unknown) =>
    c.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
  const stackReads = () => calls.filter((c) => c.url.endsWith("/import/undo-stack"));
  const undos = () => calls.filter((c) => c.method === "POST");
  return { api, undoBtn, redoBtn, caseEl, calls, ok, stackReads, undos, alerts };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

describe("import undo/redo while an undo is in flight (#2413)", () => {
  it("a push mid-undo does not re-enable the buttons", async () => {
    const h = harness();
    h.api.loadUndoStack("A");
    h.ok(h.stackReads()[0], SUMMARY);
    await settle();
    expect(h.undoBtn.disabled).toBe(false);

    h.api.doImportUndoRedo("undo");
    expect(h.undoBtn.disabled).toBe(true);
    h.api.loadUndoStack("A"); // the import_undo_changed push the undo itself triggers
    h.ok(h.stackReads()[1], SUMMARY); // the server still has another import to undo
    await settle();
    expect(h.undoBtn.disabled).toBe(true);
    expect(h.redoBtn.disabled).toBe(true);
    h.api.doImportUndoRedo("undo"); // a second click while the first undo runs
    expect(h.undos()).toHaveLength(1);
  });

  it("the buttons come back, with their labels, once the undo finishes", async () => {
    const h = harness();
    h.api.loadUndoStack("A");
    h.ok(h.stackReads()[0], SUMMARY);
    await settle();
    h.api.doImportUndoRedo("undo");
    expect(h.undoBtn.textContent).toBe("undoing…");
    h.ok(h.undos()[0], { ...SUMMARY, canRedo: true, nextRedo: { label: "evtx" } });
    await settle();
    // Still disabled: the undo's own answer is not drawn — the stack is re-read first.
    expect(h.undoBtn.disabled).toBe(true);
    h.api.doImportUndoRedo("undo");
    expect(h.undos()).toHaveLength(1);
    h.ok(h.stackReads()[h.stackReads().length - 1], {
      ...SUMMARY,
      canRedo: true,
      nextRedo: { label: "evtx" },
    });
    await settle();
    expect(h.undoBtn.disabled).toBe(false);
    expect(h.redoBtn.disabled).toBe(false);
    expect(h.undoBtn.textContent).toBe("Undo import");
  });

  it("the buttons come back after a failed undo", async () => {
    const h = harness();
    h.api.loadUndoStack("A");
    h.ok(h.stackReads()[0], SUMMARY);
    await settle();
    h.api.doImportUndoRedo("undo");
    h.undos()[0].resolve(Promise.reject(new Error("network down")));
    await settle();
    expect(h.alerts).toHaveLength(1);
    h.ok(h.stackReads()[1], SUMMARY); // the re-read after the failure
    await settle();
    expect(h.undoBtn.textContent).toBe("Undo import");
    expect(h.undoBtn.disabled).toBe(false);
  });

  it("an undo-stack answer for the case being left does not label the next case's buttons", async () => {
    const h = harness();
    h.api.loadUndoStack("A");
    h.caseEl.value = "B";
    h.api.loadUndoStack("B");
    h.ok(h.stackReads()[1], { canUndo: false, canRedo: false });
    await settle();
    h.ok(h.stackReads()[0], SUMMARY); // A's answer lands late
    await settle();
    expect(h.undoBtn.disabled).toBe(true); // still B's "nothing to undo"
  });

  it("an undo that finishes after a case switch does not paint its answer onto the next case", async () => {
    const h = harness();
    h.api.loadUndoStack("A");
    h.ok(h.stackReads()[0], SUMMARY);
    await settle();
    h.api.doImportUndoRedo("undo");
    h.caseEl.value = "B";
    h.api.loadUndoStack("B");
    h.ok(h.stackReads()[1], { canUndo: false, canRedo: false });
    await settle();
    expect(h.undoBtn.disabled).toBe(true);
    h.ok(h.undos()[0], {
      canUndo: true,
      canRedo: true,
      nextUndo: SUMMARY.nextUndo,
      nextRedo: { label: "x" },
    });
    await settle();
    expect(h.undoBtn.disabled).toBe(true); // B has nothing to undo
    expect(h.redoBtn.disabled).toBe(true);
    expect(h.undoBtn.textContent).toBe("Undo import");
  });

  it("returning to a case whose undo is still running finds its buttons still disabled", async () => {
    const h = harness();
    h.api.loadUndoStack("A");
    h.ok(h.stackReads()[0], SUMMARY);
    await settle();
    h.api.doImportUndoRedo("undo"); // A's undo in flight
    h.caseEl.value = "B";
    h.api.loadUndoStack("B");
    h.ok(h.stackReads()[1], SUMMARY);
    await settle();
    h.api.doImportUndoRedo("redo"); // B's own action is not blocked by A's
    expect(h.undos()).toHaveLength(2);
    h.caseEl.value = "A";
    h.api.loadUndoStack("A");
    h.ok(h.stackReads()[2], SUMMARY);
    await settle();
    expect(h.undoBtn.disabled).toBe(true);
    h.api.doImportUndoRedo("undo");
    expect(h.undos()).toHaveLength(2); // no second undo for A
  });

  it("an older read that lands after a newer one is dropped", async () => {
    const h = harness();
    h.api.loadUndoStack("A");
    h.api.loadUndoStack("A");
    h.ok(h.stackReads()[1], { canUndo: false, canRedo: false });
    await settle();
    h.ok(h.stackReads()[0], SUMMARY);
    await settle();
    expect(h.undoBtn.disabled).toBe(true);
  });
});
