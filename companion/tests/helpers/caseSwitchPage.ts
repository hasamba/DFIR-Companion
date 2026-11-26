// A fake dashboard page for the case-switch suites (#2900, #2904): stable elements, a #caseId
// that names the case on screen, and a fetch the test answers by hand, in the order it chooses.

export interface Pending {
  url: string;
  init: { method?: string; body?: string } | undefined;
  answer(body: unknown, ok?: boolean): void;
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
  addEventListener(): void;
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
        addEventListener: () => {},
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
      // As in a browser, writing textContent replaces the markup.
      let text = "";
      Object.defineProperty(made, "textContent", {
        get: () => text,
        set: (v: string) => {
          text = v;
          made.innerHTML = v;
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
        answer: (body, ok = true) =>
          resolve({
            ok,
            status: ok ? 200 : 500,
            headers: { get: () => null },
            json: async () => body,
          }),
        fail: () => reject(new Error("offline")),
      });
    });
  const timers: (() => void)[] = [];
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
  };
}
