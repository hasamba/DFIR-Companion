import { describe, expect, it, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #3032 — finding false-positive markers are matched by TITLE (applyFalsePositive), but a ticked
// "similar item" was sent with its id as the ref. For a finding that wrote a marker nothing ever
// applied. A ticked finding candidate now goes out with its title; an event keeps its id.

interface FpModalApi {
  initFalsePositiveModal(): void;
  openFalsePositiveModal(kind: string, ref: string, label: string): void;
}

type Handler = (e?: unknown) => unknown;

function fakeElement() {
  const handlers: Record<string, Handler> = {};
  return {
    handlers,
    value: "",
    checked: false,
    disabled: false,
    textContent: "",
    innerHTML: "",
    style: {} as Record<string, string>,
    classList: { add: () => {}, remove: () => {}, contains: () => false },
    addEventListener: (type: string, fn: Handler) => {
      handlers[type] = fn;
    },
  };
}

function checkbox(kind: string, value: string, label: string) {
  return { value, dataset: { kind, label } };
}

function harness(ticked: ReturnType<typeof checkbox>[]) {
  const els: Record<string, ReturnType<typeof fakeElement>> = {};
  const el = (id: string) => (els[id] ??= fakeElement());
  el("caseId").value = "c1";
  const fetch = vi.fn(async (_url: string, _init?: { body: string }) => ({
    ok: true,
    status: 200,
    json: async () => ({ candidates: [] }),
  }));
  const api = loadDashboardModule<FpModalApi>("dashboard-false-positive.js", ["dashboard-escape.js"], {
    document: {
      getElementById: el,
      querySelectorAll: (sel: string) => (sel === ".fp-candidate:checked" ? ticked : []),
    },
    fetch,
    investigatorName: () => "Alice",
    commitFalsePositives: () => {},
  });
  api.initFalsePositiveModal();
  const confirmItems = async () => {
    fetch.mockClear();
    await el("fpConfirmBtn").handlers.click();
    const [url, init] = fetch.mock.calls[0];
    expect(url).toBe("/cases/c1/false-positive/batch");
    return JSON.parse(init!.body).items as { kind: string; ref: string; label: string }[];
  };
  return { api, confirmItems };
}

describe("ticked similar items are marked by the key their kind is matched on (#3032)", () => {
  it("a ticked finding candidate is sent with its title as the ref", async () => {
    const h = harness([checkbox("finding", "f2", "Lateral movement (second host)")]);
    h.api.openFalsePositiveModal("finding", "Lateral movement", "Lateral movement");
    const items = await h.confirmItems();
    expect(items[1]).toEqual({
      kind: "finding",
      ref: "Lateral movement (second host)",
      label: "Lateral movement (second host)",
    });
  });

  it("a ticked event candidate is still sent with its id", async () => {
    const h = harness([checkbox("event", "e2", "PsExec run again")]);
    h.api.openFalsePositiveModal("event", "e1", "PsExec run");
    const items = await h.confirmItems();
    expect(items[1]).toEqual({ kind: "event", ref: "e2", label: "PsExec run again" });
  });
});
