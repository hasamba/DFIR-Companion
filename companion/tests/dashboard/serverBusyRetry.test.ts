// "Server busy" is not a broken panel (#1915).
//
// Under a burst the server answers heavy reads past its queue with 503 + Retry-After + the
// X-DFIR-Server-Busy marker. js/dashboard-busy-retry.js wraps fetch so a panel's GET is retried after
// Retry-After while a note says "retrying", and only a GET/HEAD carrying the marker is retried.
import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

class FakeEl {
  id = "";
  className = "";
  hidden = false;
  textContent = "";
  children: unknown[] = [];
  attrs: Record<string, string> = {};
  setAttribute(k: string, v: string) {
    this.attrs[k] = v;
  }
  appendChild(c: unknown) {
    this.children.push(c);
    return c;
  }
  addEventListener() {}
}

const busy = () =>
  new Response(JSON.stringify({ error: "server busy" }), {
    status: 503,
    headers: { "Retry-After": "2", "X-DFIR-Server-Busy": "1" },
  });
const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });

function harness(replies: Array<() => Response>) {
  const elements: Record<string, FakeEl> = {};
  const body = new FakeEl();
  const calls: Array<{ input: unknown; init?: RequestInit }> = [];
  const waits: number[] = [];
  const api = loadDashboardModule<{
    fetch: (input: unknown, init?: RequestInit) => Promise<Response>;
    dfirServerBusy: (r: Response) => boolean;
  }>("dashboard-busy-retry.js", [], {
    fetch: async (input: unknown, init?: RequestInit) => {
      calls.push({ input, init });
      const next = replies.shift();
      if (!next) throw new Error("no reply left");
      return next();
    },
    setTimeout: (fn: () => void, ms: number) => {
      waits.push(ms);
      fn();
      return 0;
    },
    clearTimeout: () => undefined,
    document: {
      body: Object.assign(body, {
        appendChild: (c: FakeEl) => {
          elements[c.id] = c;
          return c;
        },
      }),
      getElementById: (id: string) => elements[id] ?? null,
      createElement: () => new FakeEl(),
      createTextNode: (t: string) => t,
    },
    location: { reload: () => undefined },
  });
  return { api, calls, waits, note: () => elements.serverBusyNote };
}

describe("dashboard server-busy retry (#1915)", () => {
  it("retries a busy GET after Retry-After and hands the panel the real answer", async () => {
    const h = harness([busy, busy, () => ok({ lanes: [] })]);
    const res = await h.api.fetch("/cases/c1/swimlane");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ lanes: [] });
    expect(h.calls).toHaveLength(3);
    expect(h.waits).toEqual([2000, 2000]);
    expect(h.note().hidden).toBe(true); // the "retrying" note is gone once the data arrived
  });

  it("shows 'retrying' while waiting, and a reload offer if the server stays busy", async () => {
    const tries = 1 + 4;
    const h = harness(Array.from({ length: tries }, () => busy));
    const res = await h.api.fetch("/cases/c1/timeline-gaps");
    expect(res.status).toBe(503);
    expect(h.calls).toHaveLength(tries); // the first try and four retries, then the reload offer
    expect(h.api.dfirServerBusy(res)).toBe(true);
    expect(h.note().hidden).toBe(false);
    expect(h.note().textContent).toMatch(/server busy/i);
    expect(h.note().children.some((c) => (c as FakeEl).textContent === "Reload")).toBe(true);
    expect(h.note().attrs.role).toBe("status");
  });

  it("never retries a write, nor a 503 without the busy marker", async () => {
    const plain503 = () => new Response("{}", { status: 503 });
    const h = harness([busy, plain503]);
    expect((await h.api.fetch("/cases/c1/notes", { method: "POST" })).status).toBe(503);
    expect((await h.api.fetch("/cases/c1/state")).status).toBe(503);
    expect(h.calls).toHaveLength(2);
    expect(h.waits).toEqual([]);
  });

  it("a normal answer passes straight through with no note", async () => {
    const h = harness([() => ok([])]);
    expect((await h.api.fetch("/cases/c1/timeline-gaps")).status).toBe(200);
    expect(h.note()).toBeUndefined();
  });
});
