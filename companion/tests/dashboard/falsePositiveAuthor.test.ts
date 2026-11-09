import { describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #2466 — the Mark-false-positive modal never sent `markedBy`, so the server stamped every marker
// (and its Investigation Log entry) "anonymous" while the comment beside it named the investigator.

interface FpModalApi {
  initFalsePositiveModal(): void;
  openFalsePositiveModal(
    kind: string,
    ref: string,
    label: string,
    extraRefs?: { kind: string; ref: string; label: string }[],
  ): void;
}

type Handler = (e?: unknown) => unknown;

function fakeElement() {
  const handlers: Record<string, Handler> = {};
  return {
    handlers,
    value: "",
    checked: false,
    textContent: "",
    innerHTML: "",
    style: {} as Record<string, string>,
    classList: { add: () => {}, remove: () => {} },
    addEventListener: (type: string, fn: Handler) => {
      handlers[type] = fn;
    },
  };
}

function harness() {
  const els: Record<string, ReturnType<typeof fakeElement>> = {};
  const el = (id: string) => (els[id] ??= fakeElement());
  el("caseId").value = "c1";
  const fetch = vi.fn(async (_url: string, _init?: { body: string }) => ({
    ok: true,
    status: 200,
    json: async () => [],
  }));
  const api = loadDashboardModule<FpModalApi>("dashboard-false-positive.js", ["dashboard-escape.js"], {
    document: { getElementById: el, querySelectorAll: () => [] },
    fetch,
    investigatorName: () => "Alice",
    commitFalsePositives: () => {},
  });
  api.initFalsePositiveModal();
  const confirm = async () => {
    await el("fpConfirmBtn").handlers.click();
  };
  return { api, fetch, confirm };
}

describe("false-positive marks carry the investigator's name (#2466)", () => {
  it("a single mark sends markedBy", async () => {
    const h = harness();
    h.api.openFalsePositiveModal("ioc", "10.0.0.5", "10.0.0.5");
    await h.confirm();
    const [url, init] = h.fetch.mock.calls[0];
    expect(url).toBe("/cases/c1/false-positive");
    expect(JSON.parse(init!.body).markedBy).toBe("Alice");
  });

  it("a batch mark sends markedBy for the batch", async () => {
    const h = harness();
    h.api.openFalsePositiveModal("ioc", "10.0.0.5", "10.0.0.5", [
      { kind: "ioc", ref: "10.0.0.6", label: "10.0.0.6" },
    ]);
    await h.confirm();
    const [url, init] = h.fetch.mock.calls[0];
    expect(url).toBe("/cases/c1/false-positive/batch");
    expect(JSON.parse(init!.body).markedBy).toBe("Alice");
  });
});
