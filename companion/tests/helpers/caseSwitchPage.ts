// A fake dashboard page for the case-switch suites (#2900, #2904, #2915): stable elements, a #caseId
// that names the case on screen, a fetch the test answers by hand, in the order it chooses, and a
// DfirPanelDefer whose reset listeners the test fires (cancel()).

export interface Pending {
  url: string;
  init: { method?: string; body?: string } | undefined;
  answer(body: unknown, ok?: boolean, status?: number): void;
  fail(): void;
}

export interface FakeEl {
  id: string;
  value: string;
  checked: boolean;
  disabled: boolean;
  href: string;
  title: string;
  innerHTML: string;
  textContent: string;
  className: string;
  style: Record<string, string>;
  dataset: Record<string, string>;
  hidden?: boolean;
  children: unknown[];
  addEventListener(type?: string, fn?: (evt?: unknown) => void): void;
  /** Runs the listeners added for `type` (a click on a button the module built), with `evt` if given. */
  fire(type: string, evt?: unknown): void;
  setAttribute(name: string, value: string): void;
  removeAttribute(): void;
  appendChild(child: unknown): unknown;
  append(...kids: unknown[]): void;
  replaceChildren(...kids: unknown[]): void;
  querySelectorAll(): unknown[];
  querySelector(): null;
  focus(): void;
  classList: { add(): void; remove(): void; toggle(): void; contains(): boolean };
}

export const drain = () => new Promise((r) => setTimeout(r, 0));
export const drainAll = async () => {
  for (let i = 0; i < 6; i++) await drain();
};

export function fakePage(caseId = "CASE-A") {
  const els = new Map<string, FakeEl>();
  const el = (id: string): FakeEl => {
    let e = els.get(id);
    if (!e) {
      const listeners: Record<string, ((evt?: unknown) => void)[]> = {};
      const made: FakeEl = {
        id,
        value: "",
        checked: false,
        disabled: false,
        href: "",
        title: "",
        innerHTML: "",
        textContent: "",
        className: "",
        style: {},
        dataset: {},
        children: [],
        addEventListener: (type, fn) => {
          if (type && fn) (listeners[type] ??= []).push(fn);
        },
        fire: (type, evt) => (listeners[type] ?? []).forEach((fn) => fn(evt)),
        setAttribute: (name, value) => {
          if (name.startsWith("data-")) made.dataset[name.slice(5)] = value;
        },
        removeAttribute: () => {},
        appendChild: (child) => {
          made.children.push(child);
          return child;
        },
        append: (...kids) => {
          made.children.push(...kids);
        },
        replaceChildren: (...kids) => {
          made.children = [...kids];
          made.innerHTML = "";
        },
        querySelectorAll: () => [],
        querySelector: () => null,
        focus: () => {},
        classList: { add: () => {}, remove: () => {}, toggle: () => {}, contains: () => false },
      };
      // As in a browser, writing textContent replaces the markup and the child nodes.
      let text = "";
      Object.defineProperty(made, "textContent", {
        get: () => text,
        set: (v: string) => {
          text = v;
          made.innerHTML = v;
          made.children = [];
        },
      });
      els.set(id, made);
      e = made;
    }
    return e;
  };
  el("caseId").value = caseId;
  const requests: Pending[] = [];
  const fetch = (url: string, init?: { method?: string; body?: string }) =>
    new Promise((resolve, reject) => {
      requests.push({
        url,
        init,
        answer: (body, ok = true, status = ok ? 200 : 500) =>
          resolve({
            ok,
            status,
            headers: { get: () => null },
            json: async () => body,
          }),
        fail: () => reject(new Error("offline")),
      });
    });
  const timers: (() => void)[] = [];
  // The reset hook of js/dashboard-panel-defer.js: the same dedupe-by-identity contract.
  const resetListeners: ((caseId: string | null) => void)[] = [];
  // #2937: actionLive's open generation — moved by a cancel, or by open() of a different case.
  let openGen = 0;
  let lastOpen: string | null = caseId;
  const DfirPanelDefer = {
    stoppedText: "Not loaded — the case load was stopped. Open a case to load this panel.",
    onReset: (fn: (caseId: string | null) => void) => {
      if (!resetListeners.includes(fn)) resetListeners.push(fn);
    },
    actionLive: (id: string) => {
      const gen = openGen;
      return () => gen === openGen && el("caseId").value === id;
    },
  };
  const globals: Record<string, unknown> = {
    document: {
      getElementById: el,
      querySelectorAll: () => [],
      querySelector: () => null,
      createElement: () => el(`__new${els.size}`),
    },
    fetch,
    // Debounce timers are fired by the test; zero-delay ones run as usual.
    setTimeout: (fn: () => void, ms: number) => {
      if (ms > 0) {
        timers.push(fn);
        return timers.length;
      }
      return globalThis.setTimeout(fn, 0);
    },
    clearTimeout: () => {},
    setInterval: () => 0,
    clearInterval: () => {},
    localStorage: { getItem: () => null, setItem: () => {} },
    DfirTimelineView: { timeQuery: () => "", search: () => "", excludeTerms: () => [] },
    DfirState: { lastFt: () => null, lastState: () => null, lastSuperData: () => null },
    activeCaseId: caseId,
    DfirPanelDefer,
  };
  return {
    el,
    requests,
    globals,
    urls: () => requests.map((r) => r.url),
    fireTimers: () => timers.splice(0).forEach((fn) => fn()),
    // `sandbox` is the loaded module's global object: modules that read the page's activeCaseId
    // see the switch there (the globals above were copied into it at load).
    switchCase: (id: string, sandbox?: object) => {
      el("caseId").value = id;
      if (sandbox) (sandbox as { activeCaseId?: string }).activeCaseId = id;
    },
    // A cancelled (or failed) case load, as abandonCaseLoad runs it: #caseId is emptied
    // (clearLoadedCase), DfirPanelDefer.reset(null) tells every listener, activeCaseId goes last.
    cancel: (sandbox?: object) => {
      el("caseId").value = "";
      openGen++;
      lastOpen = null;
      resetListeners.forEach((fn) => fn(null));
      if (sandbox) (sandbox as { activeCaseId?: string | null }).activeCaseId = null;
    },
    // #2937: a full case open (proceedConnect): #caseId and activeCaseId change, then
    // DfirPanelDefer.reset(id) tells every listener. Another case (or one after a cancel) moves
    // actionLive's generation; reopening the case already open does not.
    open: (id: string, sandbox?: object) => {
      if (id !== lastOpen) openGen++;
      lastOpen = id;
      el("caseId").value = id;
      if (sandbox) (sandbox as { activeCaseId?: string }).activeCaseId = id;
      resetListeners.forEach((fn) => fn(id));
    },
    resetListenerCount: () => resetListeners.length,
  };
}
