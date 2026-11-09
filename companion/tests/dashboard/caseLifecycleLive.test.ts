import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";

// #2443: another analyst's close, reopen, archive or restore arrives as a bare
// case_lifecycle_changed push. The dashboard re-reads its lifecycle controls and the case list,
// ignores an answer for a case that is no longer on screen, and hides an open lifecycle menu
// whose actions the change has made wrong.
const read = (f: string) =>
  readFileSync(new URL(`../../../public/js/${f}`, import.meta.url), "utf8").replace(/\r\n/g, "\n");
const LIFECYCLE = read("dashboard-case-lifecycle.js");
const CONNECT = read("dashboard-case-connect.js");
const LIVE = read("dashboard-live-socket.js");

type El = { style: { display: string }; dataset: Record<string, string>; classes: Set<string> };

function el(): El & { classList: { toggle: (c: string, on: boolean) => void } } {
  const classes = new Set<string>();
  return {
    style: { display: "" },
    dataset: {},
    classes,
    classList: { toggle: (c: string, on: boolean) => void (on ? classes.add(c) : classes.delete(c)) },
  };
}

function harness() {
  const ids = [
    "lifecycleBtn",
    "lifecycleMenu",
    "closeBtn",
    "reopenBtn",
    "archiveZipBtn",
    "archiveEncryptedBtn",
    "restoreCaseBtn",
    "deleteCaseBtn",
  ];
  const els: Record<string, ReturnType<typeof el>> = Object.fromEntries(ids.map((id) => [id, el()]));
  const pending: Array<(cases: unknown) => void> = [];
  const caseListLoads: number[] = [];
  const win: Record<string, unknown> = {};
  const sandbox: Record<string, unknown> = {
    window: win,
    activeCaseId: "INC-1",
    document: { getElementById: (id: string) => els[id] ?? null },
    fetch: () => new Promise((res) => pending.push((cases) => res({ ok: true, json: async () => cases }))),
    loadCaseList: () => caseListLoads.push(1),
  };
  runInNewContext(LIFECYCLE, sandbox);
  const load = win.loadCaseLifecycle as (caseId: string) => Promise<void>;
  const change = win.loadLifecycleChange as (caseId: string) => Promise<void>;
  /** Answers the oldest pending GET /cases. */
  const answer = async (cases: unknown) => {
    pending.shift()?.(cases);
    await new Promise((r) => setTimeout(r, 0));
  };
  return { els, sandbox, load, change, answer, pending, caseListLoads };
}

const shown = (e: El) => e.style.display === "block";

describe("case lifecycle controls repaint on a live push (#2443)", () => {
  it("shows Reopen, not Close, for a case another analyst closed", async () => {
    const h = harness();
    void h.change("INC-1");
    await h.answer([{ caseId: "INC-1", status: "closed" }]);
    expect(shown(h.els.closeBtn)).toBe(false);
    expect(shown(h.els.reopenBtn)).toBe(true);
    expect(h.els.lifecycleBtn.classes.has("lc-closed")).toBe(true);
    expect(h.caseListLoads).toHaveLength(1);
  });

  it("offers only Restore and Delete for an archived case", async () => {
    const h = harness();
    void h.change("INC-1");
    await h.answer([{ caseId: "INC-1", status: "archived" }]);
    const visible = Object.entries(h.els)
      .filter(([id, e]) => id !== "lifecycleBtn" && id !== "lifecycleMenu" && shown(e))
      .map(([id]) => id)
      .sort();
    expect(visible).toEqual(["deleteCaseBtn", "restoreCaseBtn"]);
    expect(h.els.lifecycleBtn.classes.has("lc-archived")).toBe(true);
  });

  it("drops an answer for a case that is no longer on screen", async () => {
    const h = harness();
    void h.load("INC-1");
    h.sandbox.activeCaseId = "INC-2";
    await h.answer([{ caseId: "INC-1", status: "closed" }]);
    expect(h.els.reopenBtn.style.display).toBe("");
    expect(h.els.lifecycleBtn.classes.has("lc-closed")).toBe(false);
  });

  it("drops an answer that lands after the load was cancelled", async () => {
    const h = harness();
    void h.load("INC-1");
    h.sandbox.activeCaseId = null;
    await h.answer([{ caseId: "INC-1", status: "closed" }]);
    expect(h.els.reopenBtn.style.display).toBe("");
  });

  it("hides an open lifecycle menu when the status changed under it", async () => {
    const h = harness();
    void h.load("INC-1");
    await h.answer([{ caseId: "INC-1", status: "open" }]);
    h.els.lifecycleMenu.style.display = "block";
    void h.change("INC-1");
    await h.answer([{ caseId: "INC-1", status: "closed" }]);
    expect(h.els.lifecycleMenu.style.display).toBe("none");
  });

  it("leaves an open menu alone when the status did not change", async () => {
    const h = harness();
    void h.load("INC-1");
    await h.answer([{ caseId: "INC-1", status: "open" }]);
    h.els.lifecycleMenu.style.display = "block";
    void h.change("INC-1");
    await h.answer([{ caseId: "INC-1", status: "open" }]);
    expect(h.els.lifecycleMenu.style.display).toBe("block");
  });
});

describe("the case socket routes case_lifecycle_changed (#2443)", () => {
  it("has a handleCaseMessage branch that calls loadLifecycleChange for the connected case", () => {
    const handler = CONNECT.slice(
      CONNECT.indexOf("function handleCaseMessage("),
      CONNECT.indexOf("// Case templates and incident types moved"),
    );
    const at = handler.indexOf('msg.type === "case_lifecycle_changed"');
    expect(at).toBeGreaterThan(-1);
    const next = handler.indexOf("msg.type ===", at + 1);
    expect(handler.slice(at, next)).toContain("loadLifecycleChange(caseId)");
  });

  it("re-reads lifecycle after a reconnect, since the server keeps no replay buffer", () => {
    const list = LIVE.slice(
      LIVE.indexOf("const CATCH_UP_TYPES"),
      LIVE.indexOf("];", LIVE.indexOf("const CATCH_UP_TYPES")),
    );
    expect(list).toContain('"case_lifecycle_changed"');
  });
});
