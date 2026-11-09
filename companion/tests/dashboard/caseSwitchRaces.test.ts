// #2442: switching case on the dashboard must never connect, unlock or write to a case the analyst
// has already moved away from.
//
//   - a lock-status answer for an abandoned switch is dropped (connect A, then B, A answers last);
//   - an unlock that lands after its prompt was cancelled, or after a newer switch, connects nothing;
//   - cancelling a password prompt leaves the case on screen unlocked: the case being left is only
//     forgotten once the new case actually starts loading;
//   - a case load that fails (non-OK answer, unreadable body) is abandoned like a cancelled one;
//   - the Notebook drops the old case's half-finished edit and entry list, and ignores late answers.
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
}
function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}
const settle = () => new Promise((r) => setTimeout(r, 0));

const read = (f: string) =>
  readFileSync(new URL(`../../../public/js/${f}`, import.meta.url), "utf8").replace(/\r\n/g, "\n");
const CONNECT = read("dashboard-case-connect.js");
const fnBody = (src: string, name: string) => {
  const start = src.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`no function ${name}`);
  return src.slice(start, src.indexOf("\n  }\n", start));
};

// ── the unlock module, loaded for real ────────────────────────────────────────────────────────
type Handler = (e: { key?: string; target?: { id: string } }) => void;
interface FakeEl {
  id: string;
  value: string;
  checked: boolean;
  textContent: string;
  dataset: Record<string, string>;
  handlers: Map<string, Handler>;
  classes: Set<string>;
  classList: { add(c: string): void; remove(c: string): void; contains(c: string): boolean };
  addEventListener(type: string, fn: Handler): void;
  focus(): void;
}
function el(id: string): FakeEl {
  const classes = new Set<string>();
  const e: FakeEl = {
    id,
    value: "",
    checked: false,
    textContent: "",
    dataset: {},
    handlers: new Map(),
    classes,
    classList: {
      add: (c) => void classes.add(c),
      remove: (c) => void classes.delete(c),
      contains: (c) => classes.has(c),
    },
    addEventListener: (type, fn) => void e.handlers.set(type, fn),
    focus: () => undefined,
  };
  return e;
}

interface UnlockApi {
  initCaseUnlock(): void;
  promptCaseUnlock(caseId: string): void;
  beginCaseSwitch(): number;
  isCurrentCaseSwitch(gen: number): boolean;
  adoptCaseUnlock(caseId: string | null, remembered: boolean): void;
  forgetActiveCaseIfNotRemembered(): void;
  activeUnlockedCaseId: string | null;
  activeUnlockRemembered: boolean;
}

type FetchFn = (url: string, init?: { method?: string }) => Promise<unknown>;

function unlockPage(fetchImpl: FetchFn, unlocked: string | null = null, remembered = true) {
  const ids = [
    "cuPassword",
    "cuRemember",
    "cuMsg",
    "cuCaseLabel",
    "caseUnlockOverlay",
    "cuUnlock",
    "cuCancel",
  ];
  const els = new Map(ids.map((id) => [id, el(id)]));
  const get = (id: string) => els.get(id)!;
  const proceedConnect = vi.fn();
  const clearCasePick = vi.fn();
  const fetch = vi.fn(fetchImpl);
  const mod = loadDashboardModule<UnlockApi>("dashboard-case-unlock.js", [], {
    document: { getElementById: (id: string) => els.get(id) ?? null },
    fetch,
    proceedConnect,
    clearCasePick,
    activeUnlockedCaseId: unlocked,
    activeUnlockRemembered: remembered,
  });
  mod.initCaseUnlock();
  const overlay = get("caseUnlockOverlay");
  return {
    mod,
    get,
    fetch,
    proceedConnect,
    clearCasePick,
    overlay,
    clickUnlock: () => get("cuUnlock").handlers.get("click")!({}),
    clickCancel: () => get("cuCancel").handlers.get("click")!({}),
    clickBackdrop: () => overlay.handlers.get("click")!({ target: { id: "caseUnlockOverlay" } }),
  };
}

const okUnlock = () => ({ ok: true, json: async () => ({}) });

describe("an unlock that lands late connects nothing (#2442)", () => {
  function unlockInFlight() {
    const post = deferred<unknown>();
    const p = unlockPage((url) => (url.endsWith("/unlock") ? post.promise : Promise.resolve(okUnlock())));
    p.mod.promptCaseUnlock("B");
    p.get("cuPassword").value = "pw";
    p.get("cuRemember").checked = true;
    p.clickUnlock();
    return { ...p, post };
  }

  it("a successful unlock connects the prompted case once, with its remember choice", async () => {
    const p = unlockInFlight();
    p.post.resolve(okUnlock());
    await settle();
    expect(p.proceedConnect).toHaveBeenCalledTimes(1);
    expect(p.proceedConnect).toHaveBeenCalledWith("B", { remembered: true });
    expect(p.overlay.classes.has("open")).toBe(false);
  });

  it("Cancel while the unlock is in flight: the late success connects nothing", async () => {
    const p = unlockInFlight();
    p.clickCancel();
    p.post.resolve(okUnlock());
    await settle();
    expect(p.proceedConnect).not.toHaveBeenCalled();
  });

  it("a click on the backdrop cancels the same way", async () => {
    const p = unlockInFlight();
    p.clickBackdrop();
    p.post.resolve(okUnlock());
    await settle();
    expect(p.proceedConnect).not.toHaveBeenCalled();
    expect(p.clearCasePick).toHaveBeenCalledTimes(1);
  });

  it("a newer case switch while the unlock is in flight: the late success connects nothing", async () => {
    const p = unlockInFlight();
    p.mod.beginCaseSwitch();
    p.post.resolve(okUnlock());
    await settle();
    expect(p.proceedConnect).not.toHaveBeenCalled();
  });

  it("a double submit connects once", async () => {
    const p = unlockInFlight();
    p.clickUnlock();
    p.post.resolve(okUnlock());
    await settle();
    expect(p.proceedConnect).toHaveBeenCalledTimes(1);
  });

  it("a new switch closes the prompt but keeps the pick, so the box does not flash the old case", () => {
    const p = unlockPage(async () => okUnlock());
    p.mod.promptCaseUnlock("B");
    p.mod.beginCaseSwitch();
    expect(p.overlay.classes.has("open")).toBe(false);
    expect(p.clearCasePick).not.toHaveBeenCalled();
  });
});

// ── connect(), the real source slice, against the real unlock module ──────────────────────────
function realConnect(env: Record<string, unknown>): () => void {
  const src = CONNECT.slice(
    CONNECT.indexOf("function connect("),
    CONNECT.indexOf("// Case loading overlay:"),
  );
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  return new Function("env", `with (env) { ${src}; return connect; }`)(env) as () => void;
}

const lockStatus = (body: Record<string, unknown>) => ({ ok: true, json: async () => body });

function connectHarness(fetchImpl: FetchFn, unlocked: string | null = null, remembered = true) {
  const page = unlockPage(fetchImpl, unlocked, remembered);
  const picks: string[] = [];
  const proceedConnect = vi.fn();
  const env: Record<string, unknown> = {
    document: { getElementById: () => ({ value: "" }) },
    pickedCaseId: () => picks.shift() ?? "",
    fetch: page.fetch,
    beginCaseSwitch: page.mod.beginCaseSwitch,
    isCurrentCaseSwitch: page.mod.isCurrentCaseSwitch,
    promptCaseUnlock: vi.fn((id: string) => page.mod.promptCaseUnlock(id)),
    proceedConnect,
    // The pre-#2442 connect read and wrote these by bare name; offered so the old code fails on
    // the assertions, not on a ReferenceError.
    get activeUnlockedCaseId() {
      return page.mod.activeUnlockedCaseId;
    },
    set activeUnlockedCaseId(v) {
      page.mod.activeUnlockedCaseId = v as string | null;
    },
    get activeUnlockRemembered() {
      return page.mod.activeUnlockRemembered;
    },
    set activeUnlockRemembered(v) {
      page.mod.activeUnlockRemembered = v as boolean;
    },
    forgetActiveCaseIfNotRemembered: () => page.mod.forgetActiveCaseIfNotRemembered?.(),
  };
  return { page, picks, proceedConnect, env, connect: realConnect(env) };
}

describe("a lock-status answer for an abandoned switch is dropped (#2442)", () => {
  it("connect A, then B; A answers last: only B connects", async () => {
    const answers = new Map<string, Deferred<unknown>>();
    const h = connectHarness((url) => {
      const d = deferred<unknown>();
      answers.set(url, d);
      return d.promise;
    });
    h.picks.push("A", "B");
    h.connect();
    h.connect();
    answers.get("/cases/B/lock-status")!.resolve(lockStatus({ hasPassword: false, unlocked: true }));
    await settle();
    answers.get("/cases/A/lock-status")!.resolve(lockStatus({ hasPassword: false, unlocked: true }));
    await settle();
    expect(h.proceedConnect.mock.calls.map((c) => c[0])).toEqual(["B"]);
  });

  it("the offline fallback for an abandoned switch is dropped too", async () => {
    const answers = new Map<string, Deferred<unknown>>();
    const h = connectHarness((url) => {
      const d = deferred<unknown>();
      answers.set(url, d);
      return d.promise;
    });
    h.picks.push("A", "B");
    h.connect();
    h.connect();
    answers.get("/cases/B/lock-status")!.reject(new Error("offline"));
    await settle();
    answers.get("/cases/A/lock-status")!.reject(new Error("offline"));
    await settle();
    expect(h.proceedConnect.mock.calls.map((c) => c[0])).toEqual(["B"]);
  });

  it("an unlocked case connects with what the server said about its unlock", async () => {
    const h = connectHarness(async () =>
      lockStatus({ hasPassword: true, unlocked: true, remembered: false }),
    );
    h.picks.push("A");
    h.connect();
    await settle();
    expect(h.proceedConnect).toHaveBeenCalledWith("A", { remembered: false });
  });

  it("a locked case's prompt is closed when the analyst connects to another case", async () => {
    const h = connectHarness(async (url) =>
      lockStatus(
        url.includes("/B/") ? { hasPassword: true, unlocked: false } : { hasPassword: false, unlocked: true },
      ),
    );
    h.picks.push("B");
    h.connect();
    await settle();
    expect(h.page.overlay.classes.has("open")).toBe(true);
    h.picks.push("C");
    h.connect();
    expect(h.page.overlay.classes.has("open")).toBe(false);
  });
});

describe("a cancelled password prompt leaves the case on screen unlocked (#2442)", () => {
  it("nothing is forgotten until the new case loads; Cancel restores the picker", async () => {
    const h = connectHarness(async () => lockStatus({ hasPassword: true, unlocked: false }), "A", false);
    h.picks.push("B");
    h.connect();
    await settle();
    expect(h.page.overlay.classes.has("open")).toBe(true);
    h.page.clickCancel();
    const locks = () => h.page.fetch.mock.calls.filter((c) => c[0] === "/cases/A/lock");
    expect(locks()).toHaveLength(0);
    expect(h.page.mod.activeUnlockedCaseId).toBe("A");
    expect(h.page.clearCasePick).toHaveBeenCalledTimes(1);
    expect(h.proceedConnect).not.toHaveBeenCalled();
  });

  it("the case being left is forgotten once, when the new case is adopted", () => {
    const p = unlockPage(async () => ({ ok: true }), "A", false);
    p.mod.adoptCaseUnlock("A", false); // a same-case reconnect keeps its unlock
    expect(p.fetch).not.toHaveBeenCalled();
    p.mod.adoptCaseUnlock("B", false);
    expect(p.fetch.mock.calls.map((c) => [c[0], (c[1] as { method?: string } | undefined)?.method])).toEqual([
      ["/cases/A/lock", "POST"],
    ]);
    expect(p.mod.activeUnlockedCaseId).toBe("B");
    expect(p.mod.activeUnlockRemembered).toBe(false);
  });

  it("a remembered unlock is not forgotten on leaving", () => {
    const p = unlockPage(async () => ({ ok: true }), "A", true);
    p.mod.adoptCaseUnlock("B", true);
    expect(p.fetch).not.toHaveBeenCalled();
  });

  it("connect() no longer forgets anything itself", () => {
    expect(fnBody(CONNECT, "connect")).not.toMatch(/forgetActiveCaseIfNotRemembered|activeUnlock/);
  });

  it("the load adopts the unlock right after it commits the case", () => {
    const body = fnBody(CONNECT, "proceedConnect");
    const commit = body.indexOf("commitLoadedCase(caseId)");
    const adopt = body.indexOf("adoptCaseUnlock(caseId, !!unlock.remembered)");
    expect(adopt).toBeGreaterThan(commit);
    expect(body).toMatch(/else if \(activeUnlockedCaseId !== caseId\) adoptCaseUnlock\(null, true\)/);
  });
});

describe("a failed case load is abandoned like a cancelled one (#2442)", () => {
  const body = fnBody(CONNECT, "proceedConnect");

  it("a non-OK answer is a failure, checked before the body is read", () => {
    const ok = body.indexOf('if (!res.ok) throw new Error("HTTP " + res.status)');
    expect(ok).toBeGreaterThan(-1);
    expect(ok).toBeLessThan(body.indexOf("readBodyWithProgress"));
  });

  it("the failure abandons the load unless a newer switch or a cancel already did", () => {
    expect(body).toMatch(
      /catch \(e\) \{[\s\S]*if \(!loadSignal\.aborted && activeCaseId === caseId\)\s*abandonCaseLoad\(/,
    );
  });

  it("Cancel goes through the same abandon path", () => {
    expect(fnBody(CONNECT, "dismissCaseLoading")).toMatch(/abandonCaseLoad\(/);
    expect(fnBody(CONNECT, "abandonCaseLoad")).toMatch(/statusEl\.textContent = statusText/);
  });
});

// ── the Notebook ──────────────────────────────────────────────────────────────────────────────
interface NotebookApi {
  loadNotebook(caseId: string): void;
  nbStartEdit(id: string): void;
  notebookEntry(id: string): unknown;
}

function notebookPage() {
  const els: Record<string, Record<string, unknown>> = {
    nbList: { innerHTML: "" },
    nbText: { value: "", focus: () => undefined },
    nbType: { value: "note" },
    nbAddBtn: { textContent: "Add entry" },
    nbMsg: { textContent: "" },
  };
  const answers = new Map<string, Deferred<unknown>>();
  const fetch = vi.fn((url: string) => {
    const d = deferred<unknown>();
    answers.set(url, d);
    return d.promise;
  });
  const mod = loadDashboardModule<NotebookApi>("dashboard-notebook.js", ["dashboard-escape.js"], {
    document: { getElementById: (id: string) => els[id] ?? null },
    fetch,
  });
  const answer = (caseId: string, list: unknown[]) =>
    answers.get(`/cases/${caseId}/notebook`)!.resolve({ json: async () => list });
  return { mod, els, answer };
}

describe("the Notebook keeps nothing from the case it left (#2442)", () => {
  it("a switch drops the half-finished edit and the old entry list before the new case answers", async () => {
    const p = notebookPage();
    p.mod.loadNotebook("A");
    p.answer("A", [{ id: "e1", type: "note", text: "case A note" }]);
    await settle();
    p.mod.nbStartEdit("e1");
    expect(p.els.nbAddBtn.textContent).toBe("Save edit");
    p.mod.loadNotebook("B");
    expect(p.els.nbText.value).toBe("");
    expect(p.els.nbAddBtn.textContent).toBe("Add entry");
    expect(String(p.els.nbList.innerHTML)).toContain("No entries yet.");
    expect(p.mod.notebookEntry("e1")).toBeUndefined();
  });

  it("a late answer for the case it left does not repaint the old entries", async () => {
    const p = notebookPage();
    p.mod.loadNotebook("A");
    p.mod.loadNotebook("B");
    p.answer("A", [{ id: "e1", type: "note", text: "case A note" }]);
    await settle();
    expect(String(p.els.nbList.innerHTML)).not.toContain("case A note");
    p.answer("B", [{ id: "e2", type: "note", text: "case B note" }]);
    await settle();
    expect(String(p.els.nbList.innerHTML)).toContain("case B note");
  });

  it("a reload of the same case keeps an edit in progress", async () => {
    const p = notebookPage();
    p.mod.loadNotebook("A");
    p.answer("A", [{ id: "e1", type: "note", text: "case A note" }]);
    await settle();
    p.mod.nbStartEdit("e1");
    p.mod.loadNotebook("A");
    expect(p.els.nbAddBtn.textContent).toBe("Save edit");
  });
});
