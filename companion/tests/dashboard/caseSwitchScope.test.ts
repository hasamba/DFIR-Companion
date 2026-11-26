// #2915: the case's time window (scope) after a case switch, a live push and a failed read.
//   1. A scope_changed push wins over a read that was already on its way when it arrived.
//   2. A cancelled case load forgets whose window is held, so reopening reads it again.
//   3. A failed read says so on the chip (with Retry) instead of "none (all events)".
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { drainAll, type FakeEl } from "../helpers/caseSwitchPage.js";
import { A_WINDOW, B_WINDOW, bState, scopePage } from "../helpers/scopePage.js";

type Page = ReturnType<typeof scopePage>;
const chipText = (t: Page) =>
  t.p.el("scopeInfo").textContent +
  (t.p.el("scopeInfo").children as FakeEl[]).map((c) => c.textContent).join("");
const unreadable = (t: Page) => chipText(t).includes("could not load the time window");

describe("a scope_changed push beats an older read (#2915)", () => {
  it("a read that started before the push is dropped when it answers", async () => {
    const t = scopePage();
    t.sb.loadScope("CASE-A");
    t.sb.receiveScopePush("CASE-A", B_WINDOW);
    t.p.requests[0].answer(A_WINDOW);
    await drainAll();
    expect(t.sb.DfirScope.get()).toEqual(B_WINDOW);
  });

  it("a read that started after the push is applied", async () => {
    const t = scopePage();
    t.sb.receiveScopePush("CASE-A", B_WINDOW);
    t.sb.loadScope("CASE-A");
    t.p.requests[0].answer(A_WINDOW);
    await drainAll();
    expect(t.sb.DfirScope.get()).toEqual(A_WINDOW);
  });

  it("an older read failing after the push does not paint the failure chip", async () => {
    const t = scopePage();
    t.sb.loadScope("CASE-A");
    t.sb.receiveScopePush("CASE-A", B_WINDOW);
    t.p.requests[0].fail();
    await drainAll();
    expect(unreadable(t)).toBe(false);
    expect(chipText(t)).toContain("active:");
  });

  it("the push redraws the held state", () => {
    const t = scopePage();
    t.hold(bState);
    t.sb.receiveScopePush("CASE-A", B_WINDOW);
    expect(t.renders).toEqual([bState]);
  });

  it("a push for a case no longer on screen commits nothing", async () => {
    const t = scopePage();
    t.p.switchCase("CASE-B");
    t.sb.loadScope("CASE-B");
    t.sb.receiveScopePush("CASE-A", A_WINDOW);
    t.p.requests[0].answer(B_WINDOW);
    await drainAll();
    expect(t.sb.DfirScope.get()).toEqual(B_WINDOW);
  });

  it("this analyst's accepted POST beats an older read too (no websocket echo needed)", async () => {
    const t = scopePage();
    t.sb.loadScope("CASE-A");
    expect(t.sb.noteScopeConfirmed("CASE-A")).toBe(true);
    t.sb.DfirScope.confirm(B_WINDOW.start, B_WINDOW.end);
    t.p.requests[0].answer(A_WINDOW);
    await drainAll();
    expect(t.sb.DfirScope.get()).toEqual(B_WINDOW);
  });

  it("a POST answer for a case the analyst has left (or cancelled) is not committed", () => {
    const t = scopePage();
    t.p.switchCase("CASE-B");
    expect(t.sb.noteScopeConfirmed("CASE-A")).toBe(false);
    t.p.cancel();
    expect(t.sb.noteScopeConfirmed("CASE-B")).toBe(false);
  });

  it("applyScope asks before it commits, and the catch-up reads instead of replaying a push", () => {
    const js = (f: string) => readFileSync(new URL(`../../../public/js/${f}`, import.meta.url), "utf8");
    const apply = js("dashboard-scope-apply.js");
    expect(apply.indexOf("noteScopeConfirmed(caseId)")).toBeGreaterThan(-1);
    expect(apply.indexOf("noteScopeConfirmed(caseId)")).toBeLessThan(apply.indexOf("DfirScope.confirm("));
    const socket = js("dashboard-live-socket.js");
    expect(socket).toContain("loadScope(caseId)");
    expect(socket).not.toMatch(/type:\s*"scope_changed"/);
    expect(js("dashboard-case-connect.js")).toContain("receiveScopePush(caseId, msg)");
  });
});

describe("a cancelled case load forgets whose window is held (#2915)", () => {
  it("reopening the same case clears and reads the window again", async () => {
    const t = scopePage();
    t.sb.loadScope("CASE-A");
    t.p.requests[0].answer(A_WINDOW);
    await drainAll();
    t.p.cancel();
    t.p.switchCase("CASE-A");
    t.sb.loadScope("CASE-A");
    expect(t.p.urls()).toEqual(["/cases/CASE-A/scope", "/cases/CASE-A/scope"]);
    expect(t.sb.DfirScope.isEmpty()).toBe(true);
    t.p.requests[1].answer(A_WINDOW);
    await drainAll();
    expect(t.sb.DfirScope.get()).toEqual(A_WINDOW);
  });

  it("an answer for the cancelled load lands nowhere", async () => {
    const t = scopePage();
    t.sb.loadScope("CASE-A");
    t.p.cancel();
    t.p.switchCase("CASE-A");
    t.sb.loadScope("CASE-A");
    t.p.requests[0].answer(B_WINDOW);
    await drainAll();
    expect(t.sb.DfirScope.isEmpty()).toBe(true);
  });

  it("after a cancel, a failed re-read of the same case says it could not load", async () => {
    const t = scopePage();
    t.sb.loadScope("CASE-A");
    t.p.requests[0].answer(A_WINDOW);
    await drainAll();
    t.p.cancel();
    t.p.switchCase("CASE-A");
    t.sb.loadScope("CASE-A");
    t.p.requests[1].fail();
    await drainAll();
    expect(unreadable(t)).toBe(true);
  });
});

describe("a failed scope read says so (#2915)", () => {
  it.each(["fail", "error"] as const)(
    "B's read (%s): the chip says it could not load, not 'none'",
    async (how) => {
      const t = scopePage();
      t.sb.loadScope("CASE-A");
      t.p.requests[0].answer(A_WINDOW);
      await drainAll();
      t.p.switchCase("CASE-B");
      t.sb.loadScope("CASE-B");
      if (how === "fail") t.p.requests[1].fail();
      else t.p.requests[1].answer({ error: "boom" }, false);
      await drainAll();
      expect(unreadable(t)).toBe(true);
      expect(chipText(t)).not.toContain("none (all events)");
      // The decision: the timeline stays unfiltered, and the chip says so.
      expect(t.sb.DfirScope.project(bState).forensicTimeline).toHaveLength(2);
      expect(chipText(t)).toContain("showing all events");
      const note = (t.p.el("scopeInfo").children as FakeEl[])[0];
      expect(note.title).toMatch(/NOT filtered/);
    },
  );

  it("Retry reads again, and a good answer puts the normal chip back", async () => {
    const t = scopePage();
    t.p.switchCase("CASE-B");
    t.sb.loadScope("CASE-B");
    t.p.requests[0].fail();
    await drainAll();
    const retry = (t.p.el("scopeInfo").children as FakeEl[])[1];
    expect(retry.textContent).toBe("Retry");
    retry.fire("click");
    expect(t.p.urls()).toEqual(["/cases/CASE-B/scope", "/cases/CASE-B/scope"]);
    t.p.requests[1].answer(B_WINDOW);
    await drainAll();
    expect(unreadable(t)).toBe(false);
    expect(t.p.el("scopeInfo").textContent).toContain("active:");
  });

  it("a failed re-read of a case whose window is held keeps it", async () => {
    const t = scopePage();
    t.p.switchCase("CASE-B");
    t.sb.loadScope("CASE-B");
    t.p.requests[0].answer(B_WINDOW);
    await drainAll();
    t.sb.loadScope("CASE-B");
    t.p.requests[1].fail();
    await drainAll();
    expect(unreadable(t)).toBe(false);
    expect(t.sb.DfirScope.get()).toEqual(B_WINDOW);
  });

  it("a superseded read, or one answering after a switch or a cancel, paints no failure", async () => {
    const t = scopePage();
    t.sb.loadScope("CASE-A");
    t.sb.loadScope("CASE-A");
    t.p.requests[0].fail();
    await drainAll();
    expect(unreadable(t)).toBe(false);
    t.p.switchCase("CASE-B");
    t.p.requests[1].fail();
    await drainAll();
    expect(unreadable(t)).toBe(false);
    t.sb.loadScope("CASE-B");
    t.p.cancel();
    t.p.requests[2].fail();
    await drainAll();
    expect(unreadable(t)).toBe(false);
  });
});
