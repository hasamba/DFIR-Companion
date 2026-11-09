import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import type { CasePickerApi } from "./dashboardApi.js";

// The picker is a NAME box over a hidden id (#1523). Every other module keeps reading #caseId, which
// holds the LOADED case (#2399): a pick resolves to the id Connect will load (pickedCaseId) and
// leaves #caseId alone; the case load commits it, with the events #caseId's listeners expect.

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
    // the label is the line under the name in the dropdown: the case id, after any markers
    expect(h.options[0].label).toBe("INC-2026-001");
    expect(h.options[1].label).toBe("\u{1F512} INC-2026-002");
    expect(h.options[2].label).toBeUndefined(); // name == id — nothing to add under it
    h.archived.checked = true;
    await h.mod.loadCaseList();
    expect(h.options.map((o) => o.value)).toContain("Old audit");
    expect(h.options.find((o) => o.value === "Old audit")?.label).toBe("[Archived] INC-2026-003");
  });

  it("marks the open case in the list with a Current label", async () => {
    const h = harness(CASES);
    h.caseId.value = "INC-2026-002";
    await h.mod.loadCaseList();
    expect(h.options[0].label).toBe("INC-2026-001");
    expect(h.options[1].label).toBe("\u25CF Current \u00B7 \u{1F512} INC-2026-002");
    h.caseId.value = "test9"; // name == id: the marker still shows
    await h.mod.loadCaseList();
    expect(h.options[2].label).toBe("\u25CF Current \u00B7 test9");
  });

  it("the box tooltip carries the full name and the id", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.caseId.value = "INC-2026-001";
    h.mod.syncCasePicker();
    expect((h.picker as unknown as { title: string }).title).toBe("Acme ransomware\nINC-2026-001");
  });

  it("a case with no name keeps its markers on the id it already shows", async () => {
    const h = harness([{ caseId: "raw-1", hasPassword: true }]);
    await h.mod.loadCaseList();
    expect(h.options[0].value).toBe("raw-1");
    expect(h.options[0].label).toBe("\u{1F512} raw-1");
  });

  it("a pick chooses the case for Connect and leaves the loaded case alone (#2399)", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.caseId.value = "INC-2026-001"; // case A is loaded
    h.picker.value = "Payroll BEC";
    h.picker.fire("input");
    expect(h.mod.pickedCaseId()).toBe("INC-2026-002");
    expect(h.caseId.value).toBe("INC-2026-001"); // every action still targets the case on screen
    expect(h.caseId.fired).toEqual([]);
    expect(h.picker.value).toBe("Payroll BEC");
  });

  it("text that matches no case passes through as the pick on change, so Connect can create it", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.picker.value = "  brand-new-case ";
    h.picker.fire("change");
    expect(h.mod.pickedCaseId()).toBe("brand-new-case");
    expect(h.caseId.value).toBe("");
  });

  it("typing an unknown id changes no pick per keystroke; blur picks it once (#1962)", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.caseId.value = "INC-2026-001";
    for (const partial of ["n", "ne", "new", "new-", "new-c"]) {
      h.picker.value = partial;
      h.picker.fire("input");
    }
    expect(h.mod.pickedCaseId()).toBe("INC-2026-001"); // no pick yet: Connect would reload A
    h.picker.fire("change");
    expect(h.mod.pickedCaseId()).toBe("new-c");
    expect(h.caseId.value).toBe("INC-2026-001");
  });

  it("Enter on an unknown id picks it and connects (#1962)", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.picker.value = "brand-new-case";
    h.picker.fire("input");
    h.picker.fire("keydown", { key: "Enter" });
    expect(h.mod.pickedCaseId()).toBe("brand-new-case");
    expect(h.connected()).toBe(1);
  });

  it("typing an id directly still works", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.picker.value = "INC-2026-001";
    h.picker.fire("input");
    expect(h.mod.pickedCaseId()).toBe("INC-2026-001");
  });

  it("the case load commits the case to #caseId, once, with input+change for its listeners", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.picker.value = "Payroll BEC";
    h.picker.fire("input");
    h.mod.commitLoadedCase("INC-2026-002");
    expect(h.caseId.value).toBe("INC-2026-002");
    expect(h.caseId.fired).toEqual(["input", "change"]);
    h.mod.commitLoadedCase("INC-2026-002"); // a same-case reconnect is not a case change
    expect(h.caseId.fired).toEqual(["input", "change"]);
    expect(h.picker.value).toBe("Payroll BEC");
  });

  it("a newer pick made while a connect was probing survives that connect's commit", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.mod.setCasePick("INC-2026-002"); // connect to B starts its lock probe…
    h.mod.setCasePick("test9"); // …and the analyst picks another case meanwhile
    h.mod.commitLoadedCase("INC-2026-002");
    expect(h.caseId.value).toBe("INC-2026-002");
    expect(h.mod.pickedCaseId()).toBe("test9");
    expect(h.picker.value).toBe("test9");
  });

  it("a cancelled load leaves no case targeted, and keeps the cancelled case picked for a retry", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.mod.commitLoadedCase("INC-2026-001");
    h.mod.clearLoadedCase("INC-2026-001");
    expect(h.caseId.value).toBe("");
    expect(h.mod.pickedCaseId()).toBe("INC-2026-001");
    expect(h.picker.value).toBe("Acme ransomware");
  });

  it("a cancelled password prompt drops the pending pick: the box names the loaded case again (#2442)", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.mod.commitLoadedCase("INC-2026-001");
    h.mod.setCasePick("INC-2026-002");
    h.mod.clearCasePick();
    expect(h.mod.pickedCaseId()).toBe("INC-2026-001");
    expect(h.picker.value).toBe("Acme ransomware");
    expect(h.caseId.value).toBe("INC-2026-001");
  });

  it("with no case loaded, a cancelled prompt keeps the pick so Connect retries it (#2442)", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.mod.setCasePick("INC-2026-002"); // a deep link into a locked case, then Cancel
    h.mod.clearCasePick();
    expect(h.mod.pickedCaseId()).toBe("INC-2026-002");
    expect(h.picker.value).toBe("Payroll BEC");
  });

  it("the Current marker follows the loaded case, not the pick", async () => {
    const h = harness(CASES);
    await h.mod.loadCaseList();
    h.mod.commitLoadedCase("INC-2026-001");
    await new Promise((r) => setTimeout(r, 0));
    h.picker.value = "Payroll BEC";
    h.picker.fire("input");
    await h.mod.loadCaseList();
    const current = h.options.filter((o) => (o.label ?? "").includes("Current"));
    expect(current.map((o) => o.value)).toEqual(["Acme ransomware"]);
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
    expect(h.mod.pickedCaseId()).toBe("A-2");
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

  it("focus clears the box for the full dropdown; blur without a pick restores it, and nothing moves", async () => {
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
    expect(h.mod.pickedCaseId()).toBe("INC-2026-001");
    expect(h.connected()).toBe(1);
    h.picker.fire("keydown", { key: "a" });
    expect(h.connected()).toBe(1);
  });

  // The server set moved out of the toolbar into this second line: `<id> · <set name>`, after any
  // markers. A server with no server set store sends no serverSet field, and the line stays as it was.
  it("shows each case's server set on the line under its name", async () => {
    const h = harness([
      { caseId: "CASE-A", name: "Client A case", serverSet: { id: "s1", name: "Client A" } },
      { caseId: "CASE-B", name: "Other case", serverSet: null },
      { caseId: "CASE-C", name: "Old", status: "archived", serverSet: { id: "s1", name: "Client A" } },
      { caseId: "CASE-D", name: "CASE-D", serverSet: { id: "s2", name: "Lab" } },
    ]);
    h.archived.checked = true;
    await h.mod.loadCaseList();
    expect(h.options.map((o) => o.value)).toEqual(["Client A case", "Other case", "Old", "CASE-D"]);
    expect(h.options[0].label).toBe("CASE-A · Client A");
    expect(h.options[1].label).toBe("CASE-B · no server set");
    expect(h.options[2].label).toBe("[Archived] CASE-C · Client A");
    expect(h.options[3].label).toBe("CASE-D · Lab"); // name == id: the set still shows
  });

  it("writes a set name with markup into the label as plain text", async () => {
    const evil = '<img src=x onerror="alert(1)">';
    const h = harness([{ caseId: "CASE-A", name: "A", serverSet: { id: "s1", name: evil } }]);
    await h.mod.loadCaseList();
    expect(h.options[0].label).toBe(`CASE-A · ${evil}`);
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
