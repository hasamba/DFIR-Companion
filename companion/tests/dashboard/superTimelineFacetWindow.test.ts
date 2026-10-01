// A time window that hides every origin and host must not wipe the analyst's filter choices (#1911).
//
// The Origins and Hosts lists are computed from the time window. Set To earlier than every event,
// and both lists come back empty. The panel used to prune its checked sets against that empty list,
// so every origin and host lost its tick — while the "ever seen" sets still held them. After Clear
// time they came back as "seen before" and stayed unticked: the dropdown read 0 of 3, and the next
// filter change sent all three as exclusions and emptied the panel.
//
// The fixed shape: a value that leaves the window keeps the analyst's last choice, and the
// exclusions sent to the server come from every value the analyst has seen in this case — not only
// the ones the current window happens to show. The first query after widening is the one that
// proves it, because it is built while the panel still holds the empty lists.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface SuperTimelineApi {
  loadSuperTimeline: (caseId?: string) => void;
  initSuperTimeline: () => void;
  clearSuperTime: () => void;
  superPage: (delta: number) => void;
}

const PRELOAD = ["dashboard-state.js", "dashboard-escape.js", "dashboard-time.js", "dashboard-timeline-view.js"];

const answer = (origins: string[], hosts: string[]) => ({ events: [], total: 0, origins, hosts, labelsAvailable: [] });

function dropdownParts() {
  return {
    wrap: { style: { display: "" } },
    btn: { textContent: "", classList: { toggle: () => {} } },
    menu: { innerHTML: "", hidden: true },
  };
}

function harness() {
  const origin = dropdownParts();
  const host = dropdownParts();
  const elements: Record<string, unknown> = {
    caseId: { value: "INC-1" },
    superTimelineMsg: { textContent: "", style: { color: "" } },
    stFrom: { value: "" },
    stTo: { value: "" },
    stOriginWrap: origin.wrap,
    stOriginBtn: origin.btn,
    stOriginMenu: origin.menu,
    stHostWrap: host.wrap,
    stHostBtn: host.btn,
    stHostMenu: host.menu,
  };
  const urls: string[] = [];
  const replies: unknown[] = [];
  const listeners: Record<string, ((e: unknown) => void)[]> = {};
  const globals = {
    URLSearchParams,
    document: {
      getElementById: (id: string) => elements[id] ?? null,
      addEventListener: (type: string, fn: (e: unknown) => void) => {
        (listeners[type] ??= []).push(fn);
      },
      querySelectorAll: () => [],
    },
    // Every request answers with the next queued reply.
    fetch: (url: string) => {
      urls.push(url);
      const body = replies.shift() ?? answer([], []);
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
    },
  };
  const api = loadDashboardModule<SuperTimelineApi>("dashboard-super-timeline.js", PRELOAD, globals);
  api.initSuperTimeline();
  /** Tick or untick one box in a dropdown, the way the delegated change handler sees it. */
  const toggle = (kind: "origin" | "host", value: string, checked: boolean) => {
    const cb = { value, checked, getAttribute: () => kind, closest: () => cb };
    for (const fn of listeners.change ?? []) fn({ target: cb });
  };
  return { api, urls, replies, origin, host, elements, toggle };
}

const settle = () => new Promise((r) => setTimeout(r, 0));
const params = (url: string) => new URLSearchParams(url.split("?")[1]);

describe("super-timeline Origins and Hosts across a narrow time window (#1911)", () => {
  it("keeps every origin and host ticked after Clear time", async () => {
    const h = harness();
    h.replies.push(answer(["a", "b", "c"], ["H1", "H2"]));
    h.api.loadSuperTimeline();
    await settle();

    // To set earlier than every event: both lists come back empty.
    (h.elements.stTo as { value: string }).value = "2000-01-01T00:00";
    h.replies.push(answer([], []));
    h.api.superPage(0);
    await settle();

    h.replies.push(answer(["a", "b", "c"], ["H1", "H2"]));
    h.api.clearSuperTime();
    await settle();

    const widened = params(h.urls[h.urls.length - 1]);
    expect(widened.get("exclude")).toBeNull();
    expect(widened.get("excludeHosts")).toBeNull();
    expect(h.origin.btn.textContent).toBe("⛏ Origins"); // not "(0/3)"
    expect(h.host.btn.textContent).toBe("🖥 Hosts");
    expect(h.origin.menu.innerHTML.match(/ checked/g)).toHaveLength(3);

    // The next filter change must not turn the lost ticks into exclusions.
    h.api.superPage(0);
    await settle();
    const next = params(h.urls[h.urls.length - 1]);
    expect(next.get("exclude")).toBeNull();
    expect(next.get("excludeHosts")).toBeNull();
  });

  it("keeps an unticked origin and host excluded on the first query after widening", async () => {
    const h = harness();
    h.replies.push(answer(["a", "b", "c"], ["H1", "H2"]));
    h.api.loadSuperTimeline();
    await settle();

    h.replies.push(answer(["a", "b", "c"], ["H1", "H2"]));
    h.toggle("origin", "b", false);
    await settle();
    h.replies.push(answer(["a", "b", "c"], ["H1", "H2"]));
    h.toggle("host", "H2", false);
    await settle();

    (h.elements.stTo as { value: string }).value = "2000-01-01T00:00";
    h.replies.push(answer([], []));
    h.api.superPage(0);
    await settle();
    // Even the narrow query keeps them excluded — the server ignores names it does not hold.
    expect(params(h.urls[h.urls.length - 1]).get("exclude")).toBe("b");

    h.replies.push(answer(["a", "b", "c"], ["H1", "H2"]));
    h.api.clearSuperTime();
    await settle();

    // The widening request is built while the panel still holds the empty lists.
    const widened = params(h.urls[h.urls.length - 1]);
    expect(widened.get("exclude")).toBe("b");
    expect(widened.get("excludeHosts")).toBe("H2");
    expect(h.origin.btn.textContent).toBe("⛏ Origins (2/3)");
    expect(h.host.btn.textContent).toBe("🖥 Hosts (1/2)");
  });

  it("does not carry one case's unticked origins into another case", async () => {
    const h = harness();
    h.replies.push(answer(["a", "b"], []));
    h.api.loadSuperTimeline();
    await settle();
    h.replies.push(answer(["a", "b"], []));
    h.toggle("origin", "b", false);
    await settle();
    expect(params(h.urls[h.urls.length - 1]).get("exclude")).toBe("b");

    (h.elements.caseId as { value: string }).value = "INC-2";
    h.replies.push(answer(["a", "b"], []));
    h.api.loadSuperTimeline();
    await settle();

    expect(params(h.urls[h.urls.length - 1]).get("exclude")).toBeNull();
    expect(h.origin.btn.textContent).toBe("⛏ Origins");
  });

  it("still ticks a brand-new origin by default", async () => {
    const h = harness();
    h.replies.push(answer(["a"], []));
    h.api.loadSuperTimeline();
    await settle();
    h.replies.push(answer(["a", "fresh"], []));
    h.api.superPage(0);
    await settle();

    expect(h.origin.menu.innerHTML.match(/ checked/g)).toHaveLength(2);
    h.api.superPage(0);
    await settle();
    expect(params(h.urls[h.urls.length - 1]).get("exclude")).toBeNull();
  });
});
