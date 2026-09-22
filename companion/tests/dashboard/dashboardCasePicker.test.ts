import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import type { CasePickerApi } from "./dashboardApi.js";

// The picker is a NAME box over a hidden id (#1523). Every other module keeps reading #caseId, so
// the contract under test is the translation: a pick lands the id in #caseId with the events its
// listeners expect, and a programmatic id lands the name in the box.

type Listener = (e: { type?: string; key?: string }) => void;

interface FakeInput {
  id: string;
  value: string;
  checked: boolean;
  listeners: Map<string, Listener[]>;
  fired: string[];
  addEventListener(type: string, fn: Listener): void;
  dispatchEvent(e: { type: string }): boolean;
  fire(type: string, e?: { key?: string }): void;
}

function fakeInput(id: string): FakeInput {
  const listeners = new Map<string, Listener[]>();
  const el: FakeInput = {
    id,
    value: "",
    checked: false,
    listeners,
    fired: [],
    addEventListener: (type, fn) => listeners.set(type, [...(listeners.get(type) ?? []), fn]),
    dispatchEvent: (e) => {
      el.fired.push(e.type);
      (listeners.get(e.type) ?? []).forEach((fn) => fn(e));
      return true;
    },
    fire: (type, e = {}) => (listeners.get(type) ?? []).forEach((fn) => fn(e)),
  };
  return el;
}

interface FakeOption {
  value: string;
  label?: string;
}

function harness(cases: Array<Record<string, unknown>>) {
  const picker = fakeInput("casePicker");
  const caseId = fakeInput("caseId");
  const archived = fakeInput("showArchivedToggle");
  const options: FakeOption[] = [];
  const datalist = {
    id: "caseList",
    set innerHTML(_: string) {
      options.length = 0;
    },
    appendChild: (o: FakeOption) => void options.push(o),
  };
  const demoBtn = { id: "seedDemoBtn", style: { display: "" } };
  const els = new Map<string, unknown>([
    ["casePicker", picker],
    ["caseId", caseId],
    ["showArchivedToggle", archived],
    ["caseList", datalist],
    ["seedDemoBtn", demoBtn],
  ]);
  let connected = 0;
  const mod = loadDashboardModule<CasePickerApi>("dashboard-case-picker.js", [], {
    document: {
      getElementById: (id: string) => els.get(id) ?? null,
      createElement: () => ({ value: "" }) as FakeOption,
    },
    fetch: async () => ({ ok: true, json: async () => cases }),
    Event: class {
      type: string;
      constructor(type: string) {
        this.type = type;
      }
    },
    connect: () => void connected++,
  });
  mod.initCasePicker();
  return { mod, picker, caseId, archived, options, demoBtn, connected: () => connected };
}

const CASES = [
  { caseId: "INC-2026-001", name: "Acme ransomware", status: "active" },
  { caseId: "INC-2026-002", name: "Payroll BEC", status: "active", hasPassword: true },
  { caseId: "INC-2026-003", name: "Old audit", status: "archived" },
  { caseId: "test9", name: "test9" },
];

describe("dashboard-case-picker.js", () => {
  it("lists case NAMES, keeps the archived ones out until asked, and annotates the locked ones", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    expect(h.options.map((o) => o.value)).toEqual(["Acme ransomware", "Payroll BEC", "test9"]);
    expect(h.options[1].label).toBe("\u{1F512} Payroll BEC");
    expect(h.options[0].label).toBeUndefined(); // nothing to annotate — the name stands alone
    h.archived.checked = true;
    await h.mod.loadCaseList();
    expect(h.options.map((o) => o.value)).toContain("Old audit");
    expect(h.options.find((o) => o.value === "Old audit")?.label).toBe("[Archived] Old audit");
  });

  it("a pick puts the ID in #caseId and replays input+change for its listeners", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.picker.value = "Payroll BEC";
    h.picker.fire("input");
    expect(h.caseId.value).toBe("INC-2026-002");
    expect(h.caseId.fired).toEqual(["input", "change"]);
    // the same value again is not a change — no second round of events
    h.picker.fire("change");
    expect(h.caseId.fired).toEqual(["input", "change"]);
  });

  it("text that matches no case passes through as the id, so Connect can create it", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.picker.value = "  brand-new-case ";
    h.picker.fire("input");
    expect(h.caseId.value).toBe("brand-new-case");
  });

  it("typing an id directly still works", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.picker.value = "INC-2026-001";
    h.picker.fire("input");
    expect(h.caseId.value).toBe("INC-2026-001");
  });

  it("two cases with one name are listed as `name (id)` and both resolve", async () => {
    const twins = [
      { caseId: "A-1", name: "Twin" },
      { caseId: "A-2", name: "Twin" },
    ];
    const h = harness(twins);
    await h.mod.loadCaseList();
    expect(h.options.map((o) => o.value)).toEqual(["Twin (A-1)", "Twin (A-2)"]);
    h.picker.value = "Twin (A-2)";
    h.picker.fire("input");
    expect(h.caseId.value).toBe("A-2");
  });

  it("a programmatic id shows its name in the box; an unknown id shows the id itself", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.caseId.value = "INC-2026-001";
    h.mod.syncCasePicker();
    expect(h.picker.value).toBe("Acme ransomware");
    h.caseId.value = "not-listed";
    h.mod.syncCasePicker();
    expect(h.picker.value).toBe("not-listed");
  });

  it("a remembered id set BEFORE the list arrives is named once it does", async () => {
    const h = harness(CASES);
    h.caseId.value = "INC-2026-001";
    h.mod.syncCasePicker();
    expect(h.picker.value).toBe("INC-2026-001"); // best it can do yet
    await h.mod.loadCaseList();
    expect(h.picker.value).toBe("Acme ransomware");
  });

  it("focus clears the box for the full dropdown; blur without a pick restores it, and #caseId never moves", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.caseId.value = "INC-2026-001";
    h.mod.syncCasePicker();
    h.picker.fire("focus");
    expect(h.picker.value).toBe("");
    expect(h.caseId.value).toBe("INC-2026-001");
    h.picker.fire("blur");
    expect(h.picker.value).toBe("Acme ransomware");
    expect(h.caseId.fired).toEqual([]);
  });

  it("Enter resolves the box and connects", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.picker.value = "Acme ransomware";
    h.picker.fire("keydown", { key: "Enter" });
    expect(h.caseId.value).toBe("INC-2026-001");
    expect(h.connected()).toBe(1);
    h.picker.fire("keydown", { key: "a" });
    expect(h.connected()).toBe(1);
  });

  it("the Demo case button shows only on an empty instance", async () => {
    const empty = harness([]);
    await empty.mod.loadCaseList();
    expect(empty.demoBtn.style.display).toBe("");
    const full = harness(CASES);
    await full.mod.loadCaseList();
    expect(full.demoBtn.style.display).toBe("none");
  });
});
