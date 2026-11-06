// A small fake DOM for the server-set dashboard suites (serverSetsUi.test.ts).
//
// The dashboard modules are classic scripts run in a vm context (see helpers/dashboardModule.ts),
// and the repo carries no DOM library. This fake holds only what those two modules and the New Case
// form touch: an element tree, ids, text, classes, attributes, values and listeners.
//
// innerHTML is RECORDED, not parsed. A set name or an IRIS case name may come from an analyst or
// from IRIS, so the modules must write them with textContent. A test asserts that no element ever
// received an innerHTML write.

type Listener = (e: FakeEvent) => void;

export interface FakeEvent {
  type: string;
  key?: string;
  target?: FakeEl;
  preventDefault: () => void;
}

export class FakeEl {
  readonly tagName: string;
  id = "";
  className = "";
  value = "";
  checked = false;
  disabled = false;
  hidden = false;
  type = "";
  title = "";
  selected = false;
  style: Record<string, string> = {};
  dataset: Record<string, string> = {};
  children: FakeEl[] = [];
  parent: FakeEl | null = null;
  htmlWrites: string[] = [];
  onclick: Listener | null = null;
  onchange: Listener | null = null;
  private text = "";
  private readonly attrs = new Map<string, string>();
  private readonly listeners = new Map<string, Listener[]>();

  constructor(
    readonly doc: FakeDocument,
    tag: string,
  ) {
    this.tagName = tag.toUpperCase();
    doc.all.push(this);
  }

  get textContent(): string {
    return this.text + this.children.map((c) => c.textContent).join("");
  }
  set textContent(v: string) {
    for (const c of this.children) c.parent = null;
    this.children = [];
    this.text = String(v ?? "");
  }
  get innerHTML(): string {
    return "";
  }
  set innerHTML(v: string) {
    this.htmlWrites.push(String(v));
  }

  get classList() {
    const list = () => this.className.split(/\s+/).filter(Boolean);
    const set = (names: string[]) => (this.className = names.join(" "));
    return {
      add: (...n: string[]) => set([...new Set([...list(), ...n])]),
      remove: (...n: string[]) => set(list().filter((c) => !n.includes(c))),
      contains: (n: string) => list().includes(n),
      toggle: (n: string, force?: boolean) => {
        const on = force ?? !list().includes(n);
        if (on) set([...new Set([...list(), n])]);
        else set(list().filter((c) => c !== n));
        return on;
      },
    };
  }

  get options(): FakeEl[] {
    return this.children.filter((c) => c.tagName === "OPTION");
  }
  /** A select's chosen option: the one whose value is the select's, else the first (as a browser). */
  get selectedOptions(): FakeEl[] {
    const chosen = this.options.find((o) => o.value === this.value) ?? this.options[0];
    return chosen ? [chosen] : [];
  }
  /** The browser's replaceWith, for one node. */
  replaceWith(node: FakeEl): void {
    const parent = this.parent;
    if (!parent) return;
    node.parent?.removeChild(node);
    parent.children = parent.children.map((c) => (c === this ? node : c));
    node.parent = parent;
    this.parent = null;
  }

  appendChild(child: FakeEl): FakeEl {
    child.parent?.removeChild(child);
    child.parent = this;
    this.children.push(child);
    return child;
  }
  append(...items: Array<FakeEl | string>): void {
    for (const item of items) {
      if (typeof item === "string") {
        const t = new FakeEl(this.doc, "#text");
        t.textContent = item;
        this.appendChild(t);
      } else this.appendChild(item);
    }
  }
  replaceChildren(...items: Array<FakeEl | string>): void {
    this.textContent = "";
    this.append(...items);
  }
  removeChild(child: FakeEl): FakeEl {
    this.children = this.children.filter((c) => c !== child);
    child.parent = null;
    return child;
  }
  remove(): void {
    this.parent?.removeChild(this);
  }

  setAttribute(name: string, value: string): void {
    this.attrs.set(name, String(value));
    if (name === "id") this.id = String(value);
  }
  getAttribute(name: string): string | null {
    return this.attrs.get(name) ?? null;
  }
  hasAttribute(name: string): boolean {
    return this.attrs.has(name);
  }
  removeAttribute(name: string): void {
    this.attrs.delete(name);
  }

  addEventListener(type: string, fn: Listener): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }
  removeEventListener(type: string, fn: Listener): void {
    this.listeners.set(
      type,
      (this.listeners.get(type) ?? []).filter((f) => f !== fn),
    );
  }
  /** Runs the on<type> property and every listener, the way a browser event does. */
  fire(type: string, extra: Partial<FakeEvent> = {}): void {
    const e: FakeEvent = { type, target: this, preventDefault: () => {}, ...extra };
    const prop = type === "click" ? this.onclick : type === "change" ? this.onchange : null;
    if (prop) prop.call(this, e);
    for (const fn of this.listeners.get(type) ?? []) fn.call(this, e);
  }
  /** The browser's dispatchEvent, enough for `new Event(type)`. */
  dispatchEvent(e: { type: string }): boolean {
    this.fire(e.type);
    return true;
  }
  closest(sel: string): FakeEl | null {
    let node: FakeEl | null = this;
    while (node && !node.matches(sel)) node = node.parent;
    return node;
  }
  click(): void {
    if (!this.disabled) this.fire("click");
  }
  focus(): void {
    this.doc.activeElement = this;
  }
  select(): void {}

  matches(sel: string): boolean {
    if (sel.startsWith("#")) return this.id === sel.slice(1);
    if (sel.startsWith(".")) return this.classList.contains(sel.slice(1));
    const attr = /^\[([\w-]+)\]$/.exec(sel);
    if (attr) {
      const name = attr[1];
      if (name.startsWith("data-")) {
        const key = name.slice(5).replace(/-([a-z])/g, (_, c: string) => c.toUpperCase());
        return key in this.dataset || this.attrs.has(name);
      }
      return this.attrs.has(name);
    }
    return this.tagName === sel.toUpperCase();
  }
  descendants(): FakeEl[] {
    return this.children.flatMap((c) => [c, ...c.descendants()]);
  }
  querySelectorAll(sel: string): FakeEl[] {
    return this.descendants().filter((d) => d.matches(sel));
  }
  querySelector(sel: string): FakeEl | null {
    return this.querySelectorAll(sel)[0] ?? null;
  }
}

export class FakeDocument {
  readonly all: FakeEl[] = [];
  readonly body: FakeEl;
  readyState = "complete";
  activeElement: FakeEl | null = null;

  constructor() {
    this.body = new FakeEl(this, "body");
  }
  createElement(tag: string): FakeEl {
    return new FakeEl(this, tag);
  }
  getElementById(id: string): FakeEl | null {
    return this.body.descendants().find((d) => d.id === id) ?? null;
  }
  querySelectorAll(sel: string): FakeEl[] {
    return this.body.querySelectorAll(sel);
  }
  querySelector(sel: string): FakeEl | null {
    return this.body.querySelector(sel);
  }
  addEventListener(): void {}
  /** Adds `<tag id=…>` elements under body, one per id, and returns them by id. */
  add(tag: string, ...ids: string[]): Record<string, FakeEl> {
    const out: Record<string, FakeEl> = {};
    for (const id of ids) {
      const el = this.createElement(tag);
      el.id = id;
      this.body.appendChild(el);
      out[id] = el;
    }
    return out;
  }
  /** Every innerHTML write any element received. */
  htmlWrites(): string[] {
    return this.all.flatMap((e) => e.htmlWrites);
  }
}

export interface Route {
  status?: number;
  body?: unknown;
}

export interface FetchCall {
  method: string;
  url: string;
  body: Record<string, unknown> | undefined;
}

/**
 * A fetch that answers from a route table keyed "METHOD url". A route may be a function, so one
 * test can change the answer between calls or hold it back to simulate a slow response.
 */
export function routedFetch(routes: Record<string, Route | ((call: FetchCall) => Route | Promise<Route>)>) {
  const calls: FetchCall[] = [];
  const fetch = async (url: string, init: { method?: string; body?: string } = {}) => {
    const method = (init.method ?? "GET").toUpperCase();
    const call: FetchCall = {
      method,
      url,
      body: init.body ? (JSON.parse(init.body) as Record<string, unknown>) : undefined,
    };
    calls.push(call);
    const route = routes[`${method} ${url}`];
    const answer = typeof route === "function" ? await route(call) : route;
    const status = answer?.status ?? (answer ? 200 : 404);
    const body = answer?.body ?? (answer ? {} : { error: `no route for ${method} ${url}` });
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    };
  };
  return { fetch, calls };
}

/** Lets every pending promise chain in the vm context run to the end. */
export async function flush(): Promise<void> {
  for (let i = 0; i < 25; i++) await new Promise((r) => setImmediate(r));
}
