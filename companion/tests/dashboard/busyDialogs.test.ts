// #2494: a dialog with a request on the wire must not be dismissable — not by Escape, not by its
// Cancel button, not by a click on the backdrop. A failure that comes back after the dialog was
// dismissed is written into a hidden dialog, and the analyst never sees it (for Notion, the
// "finish the half-written page" hint is lost too, so the next export makes a duplicate page).
//
// #2463 fixed this for Close case only. These six dialogs had the same hole. Escape itself is
// pinned by modalBusyEscape.test.ts: the shared wiring ignores Escape on an aria-busy overlay, so
// here it is enough to pin the busy mark, the disabled Cancel and the inert backdrop.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { FakeDocument, type FakeEl, flush, type Route, routedFetch } from "./serverSetsFakeDom.js";

/** A route that answers only when the test says so: the request stays "on the wire" until then. */
function heldRoute() {
  let answer: (r: Route) => void = () => {};
  const route = () => new Promise<Route>((resolve) => (answer = resolve));
  return { route, answer: (r: Route) => answer(r) };
}

interface Dialog {
  name: string;
  overlay: string;
  cancel: string;
  msg: string;
  /** Builds the dialog, opens it and presses its action button; the request is then held. */
  start(held: () => Promise<Route>): Promise<{ el: (id: string) => FakeEl }>;
}

// ── Delete case ──────────────────────────────────────────────────────────────
async function startDeleteCase(held: () => Promise<Route>) {
  const doc = new FakeDocument();
  doc.add("div", "deleteCaseOverlay");
  doc.add("p", "dcCaseName", "dcPasswordFields");
  doc.add("input", "dcArchiveNone", "dcArchiveEncrypted", "dcPassword", "dcPasswordConfirm", "status");
  doc.add("button", "dcDelete", "dcCancel");
  doc.add("span", "dcMsg");
  doc.add("input", "caseId").caseId.value = "c1";
  // The fake DOM has no attribute-selector engine; the handler asks for the checked archive radio.
  const qs = doc.querySelector.bind(doc);
  doc.querySelector = (sel: string) =>
    sel.includes("dcArchiveFirst") ? ({ value: "none" } as unknown as FakeEl) : qs(sel);
  const net = routedFetch({ "POST /cases/c1/delete": held });
  const api = loadDashboardModule<{ initDeleteCase(): void; openDeleteCase(): void }>(
    "dashboard-delete-case.js",
    [],
    { document: doc, fetch: net.fetch, loadCaseLifecycle: () => {}, loadCaseList: () => {} },
  );
  api.initDeleteCase();
  api.openDeleteCase();
  const el = (id: string) => doc.getElementById(id) as FakeEl;
  el("dcDelete").click();
  await flush();
  return { el };
}

// ── Import case (encrypted .dfircase) ────────────────────────────────────────
async function startImportCase(held: () => Promise<Route>) {
  const doc = new FakeDocument();
  doc.add("div", "importCaseOverlay", "importPasswordOverlay");
  doc.add(
    "button",
    "importCaseBtn",
    "importCaseCancel",
    "importCaseEncrypted",
    "importCaseZip",
    "importCaseIris",
    "ipImport",
    "ipCancel",
  );
  doc.add("input", "zipImportFile", "encryptedImportFile", "ipPassword", "status");
  doc.add("span", "importCaseHint", "ipFilename", "ipMsg");
  doc.add("input", "caseId");
  const net = routedFetch({ "POST /cases/import/encrypted": held });
  const api = loadDashboardModule<{ initImportCase(): void }>("dashboard-import-case.js", [], {
    document: doc,
    fetch: net.fetch,
    arrayBufferToBase64: () => "AAAA",
    loadCaseList: () => {},
    connect: () => {},
    openIrisImportModal: () => {},
  });
  api.initImportCase();
  const el = (id: string) => doc.getElementById(id) as FakeEl;
  el("encryptedImportFile").onchange!({
    type: "change",
    target: {
      files: [{ name: "case.dfircase", size: 1024, arrayBuffer: async () => new ArrayBuffer(8) }],
      value: "",
    } as unknown as FakeEl,
    preventDefault: () => {},
  });
  el("ipPassword").value = "correct horse battery staple";
  el("ipImport").click();
  await flush();
  return { el };
}

// ── Ticket dialogs (Notion, ClickUp, DFIR-IRIS push, DFIR-IRIS import) ───────
function ticketsDom() {
  const doc = new FakeDocument();
  doc.add("select", "pushSelect");
  doc.add("span", "status", "reportLinks", "importCaseIris");
  doc.add("input", "caseId").caseId.value = "c1";
  doc.add("div", "notionOverlay", "notionNewRow", "notionExistingRow");
  doc.add("input", "notionNewTarget", "notionPageUrl");
  doc.add("button", "notionExportBtn", "notionCancel");
  doc.add("div", "irisImportOverlay");
  doc.add("select", "irisCaseSelect");
  doc.add("input", "irisCaseIdInput");
  doc.add("button", "irisImportRun", "irisImportCancel");
  doc.add("div", "clickupOverlay");
  doc.add("input", "clickupListId");
  doc.add("button", "clickupPushBtn", "clickupCancel");
  doc.add("div", "irisPushOverlay");
  doc.add("input", "irisPushCaseName");
  doc.add("button", "irisPushBtn", "irisPushCancel");
  doc.add("span", "notionMsg", "irisImportMsg", "clickupMsg", "irisPushMsg");
  return doc;
}

async function startTicketDialog(
  route: string,
  held: () => Promise<Route>,
  open: (el: (id: string) => FakeEl) => void,
  action: string,
) {
  const doc = ticketsDom();
  const net = routedFetch({ [route]: held });
  const api = loadDashboardModule<{ initTicketIntegrations(): void }>("dashboard-tickets.js", [], {
    document: doc,
    fetch: net.fetch,
    escAttr: (s: string) => s,
    esc: (s: string) => s,
    showToast: () => {},
    saveSettings: async () => true,
  });
  api.initTicketIntegrations();
  await flush();
  const el = (id: string) => doc.getElementById(id) as FakeEl;
  open(el);
  el(action).click();
  await flush();
  return { el };
}

/** Opens a Push-menu dialog the way the analyst does: by choosing the target in the menu. */
function choosePush(target: string) {
  return (el: (id: string) => FakeEl) => {
    el("pushSelect").value = target;
    el("pushSelect").fire("change");
  };
}

const DIALOGS: Dialog[] = [
  {
    name: "Delete case",
    overlay: "deleteCaseOverlay",
    cancel: "dcCancel",
    msg: "dcMsg",
    start: startDeleteCase,
  },
  {
    name: "Import case",
    overlay: "importPasswordOverlay",
    cancel: "ipCancel",
    msg: "ipMsg",
    start: startImportCase,
  },
  {
    name: "Notion export",
    overlay: "notionOverlay",
    cancel: "notionCancel",
    msg: "notionMsg",
    start: (held) =>
      startTicketDialog(
        "POST /cases/c1/push/notion",
        held,
        (el) => {
          choosePush("notion")(el);
          el("notionNewTarget").value = "db1";
        },
        "notionExportBtn",
      ),
  },
  {
    name: "ClickUp push",
    overlay: "clickupOverlay",
    cancel: "clickupCancel",
    msg: "clickupMsg",
    start: (held) =>
      startTicketDialog(
        "POST /cases/c1/push/clickup",
        held,
        (el) => {
          choosePush("clickup")(el);
          el("clickupListId").value = "list1";
        },
        "clickupPushBtn",
      ),
  },
  {
    name: "DFIR-IRIS push",
    overlay: "irisPushOverlay",
    cancel: "irisPushCancel",
    msg: "irisPushMsg",
    start: (held) => startTicketDialog("POST /cases/c1/push/iris", held, choosePush("iris"), "irisPushBtn"),
  },
  {
    name: "DFIR-IRIS import",
    overlay: "irisImportOverlay",
    cancel: "irisImportCancel",
    msg: "irisImportMsg",
    start: (held) =>
      startTicketDialog(
        "POST /cases/c1/iris-import",
        held,
        (el) => {
          el("irisImportOverlay").classList.add("open");
          el("irisCaseIdInput").value = "7";
        },
        "irisImportRun",
      ),
  },
];

describe.each(DIALOGS)("$name dialog while its request is on the wire (#2494)", (d) => {
  it("is marked busy, its Cancel is disabled and a backdrop click leaves it open", async () => {
    const held = heldRoute();
    const { el } = await d.start(held.route);
    const overlay = el(d.overlay);
    expect(overlay.classList.contains("open")).toBe(true);
    expect(overlay.getAttribute("aria-busy")).toBe("true");
    expect(el(d.cancel).disabled).toBe(true);
    overlay.fire("click"); // a click on the backdrop itself
    expect(overlay.classList.contains("open")).toBe(true);
    held.answer({ status: 500, body: { error: "boom" } });
    await flush();
  });

  it("after a failure the mark is gone, the error is shown and the dialog can be dismissed", async () => {
    const held = heldRoute();
    const { el } = await d.start(held.route);
    held.answer({ status: 500, body: { error: "boom" } });
    await flush();
    const overlay = el(d.overlay);
    expect(overlay.classList.contains("open")).toBe(true);
    expect(overlay.getAttribute("aria-busy")).toBeNull();
    expect(el(d.msg).textContent).toContain("boom");
    expect(el(d.cancel).disabled).toBe(false);
    overlay.fire("click");
    expect(overlay.classList.contains("open")).toBe(false);
  });
});

describe("a busy mark never outlives the request (#2494)", () => {
  it("ticket dialogs clear it when the request succeeds and they close", async () => {
    const held = heldRoute();
    const { el } = await DIALOGS[3].start(held.route); // ClickUp
    held.answer({ body: { created: 1, updated: 0 } });
    await flush();
    expect(el("clickupOverlay").classList.contains("open")).toBe(false);
    expect(el("clickupOverlay").getAttribute("aria-busy")).toBeNull();
    expect(el("clickupCancel").disabled).toBe(false);
  });

  it("opening a dialog clears a stale mark", async () => {
    const held = heldRoute();
    const { el } = await DIALOGS[4].start(held.route); // DFIR-IRIS push, still on the wire
    // Simulate a mark left behind by an earlier window, then reopen through the Push menu.
    el("irisPushOverlay").classList.remove("open");
    choosePush("iris")(el);
    expect(el("irisPushOverlay").getAttribute("aria-busy")).toBeNull();
    expect(el("irisPushCancel").disabled).toBe(false);
    held.answer({ status: 500, body: { error: "boom" } });
    await flush();
  });
});
