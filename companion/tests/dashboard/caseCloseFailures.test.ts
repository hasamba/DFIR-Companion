// #2412: the Close case dialog must never stick, and Cancel must never hide a close that happened.
//
// A network error made the close request throw past the dialog, which stayed on "closing…" with its
// button disabled for good. And Cancel pressed while the close was on the wire resolved "not closed"
// — if the close then went through, the case was closed on the server while the dashboard still
// showed it open, because nothing refreshed the lifecycle or the case list.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { FakeDocument, type FakeEl, flush, type Route, routedFetch } from "./serverSetsFakeDom.js";

interface CloseApi {
  initCaseClose(): void;
  closeCaseWithCredentials(caseId: string): Promise<boolean>;
}

const ROW = { id: "a1", name: "AWS prod", provider: "aws", settings: {} };

function loadClose(
  routes: Record<string, Route | (() => Route | Promise<Route>)>,
  onScreen = "c1",
  timers: Array<() => void> = [],
) {
  const doc = new FakeDocument();
  doc.add("div", "closeCaseOverlay");
  doc.add("p", "ccaCaseName");
  doc.add("ul", "ccaList");
  doc.add("input", "ccaDelete", "ccaKeep");
  doc.add("button", "ccaConfirm", "ccaCancel");
  doc.add("span", "ccaMsg");
  doc.add("input", "caseId").caseId.value = onScreen;
  const net = routedFetch(routes);
  const alerts: string[] = [];
  const refreshed: string[] = [];
  const api = loadDashboardModule<CloseApi>("dashboard-case-close.js", [], {
    document: doc,
    fetch: net.fetch,
    alert: (m: string) => alerts.push(m),
    loadCaseLifecycle: (caseId: string) => refreshed.push(`lifecycle:${caseId}`),
    loadCaseList: () => refreshed.push("list"),
    setTimeout: (fn: () => void) => timers.push(fn),
    clearTimeout: () => {},
    AbortController,
  });
  api.initCaseClose();
  return { api, net, alerts, refreshed, el: (id: string) => doc.getElementById(id) as FakeEl };
}

describe("close case dialog failures (#2412)", () => {
  it("a network error shows a message and re-enables the dialog", async () => {
    const { api, el } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
      "PATCH /cases/c1/status": () => {
        throw new Error("Failed to fetch");
      },
    });
    const done = api.closeCaseWithCredentials("c1");
    await flush();
    el("ccaConfirm").click();
    await flush();
    expect(el("ccaConfirm").disabled).toBe(false);
    expect(el("ccaCancel").disabled).toBe(false);
    expect(el("ccaMsg").textContent).toContain("Failed to fetch");
    expect(el("ccaMsg").textContent).toContain("may have gone through"); // the status read failed too
    expect(el("closeCaseOverlay").classList.contains("open")).toBe(true);
    el("ccaCancel").click();
    expect(await done).toBe(false);
  });

  it("a network error on a case with no accounts is reported, not thrown", async () => {
    const { api, alerts } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [] } },
      "PATCH /cases/c1/status": () => {
        throw new Error("Failed to fetch");
      },
    });
    expect(await api.closeCaseWithCredentials("c1")).toBe(false);
    expect(alerts.join(" ")).toContain("Failed to fetch");
  });

  it("Cancel cannot be pressed while the close is on the wire", async () => {
    let answer: (r: Route) => void = () => {};
    const { api, el } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
      "PATCH /cases/c1/status": () => new Promise<Route>((r) => (answer = r)),
    });
    const done = api.closeCaseWithCredentials("c1");
    await flush();
    el("ccaConfirm").click();
    await flush();
    expect(el("ccaCancel").disabled).toBe(true);
    el("ccaCancel").click(); // ignored
    answer({ body: { status: "closed" } });
    expect(await done).toBe(true); // the caller learns the case closed, and refreshes
  });

  it("a close superseded while on the wire still refreshes the lifecycle when it succeeds", async () => {
    let answer: (r: Route) => void = () => {};
    const { api, el, refreshed } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
      "PATCH /cases/c1/status": () => new Promise<Route>((r) => (answer = r)),
      "GET /cases/c2/cloud-accounts": { body: { accounts: [ROW] } },
    });
    const first = api.closeCaseWithCredentials("c1");
    await flush();
    el("ccaConfirm").click();
    await flush();
    const second = api.closeCaseWithCredentials("c2"); // replaces the open dialog
    expect(await first).toBe(false);
    answer({ body: { status: "closed" } });
    await flush();
    expect(refreshed).toEqual(["lifecycle:c1", "list"]);
    void second;
  });

  it("a close the server made before the connection dropped counts as closed", async () => {
    const { api, el } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
      "PATCH /cases/c1/status": () => {
        throw new Error("Failed to fetch");
      },
      "GET /cases": { body: [{ caseId: "c1", status: "closed" }] },
    });
    const done = api.closeCaseWithCredentials("c1");
    await flush();
    el("ccaConfirm").click();
    expect(await done).toBe(true);
  });

  it("a dropped close on a case still open says so plainly", async () => {
    const { api, el } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
      "PATCH /cases/c1/status": () => {
        throw new Error("Failed to fetch");
      },
      "GET /cases": { body: [{ caseId: "c1", status: "open" }] },
    });
    void api.closeCaseWithCredentials("c1");
    await flush();
    el("ccaConfirm").click();
    await flush();
    expect(el("ccaMsg").textContent).toContain("still open");
    expect(el("ccaConfirm").disabled).toBe(false);
  });

  // #2463: the case list omits `status` for a case that was never closed — absent means open.
  it("a dropped close on a never-closed case (no status in the list) says it is still open", async () => {
    const { api, el } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
      "PATCH /cases/c1/status": () => {
        throw new Error("Failed to fetch");
      },
      "GET /cases": { body: [{ caseId: "c1" }] },
    });
    void api.closeCaseWithCredentials("c1");
    await flush();
    el("ccaConfirm").click();
    await flush();
    expect(el("ccaMsg").textContent).toContain("still open");
    expect(el("ccaMsg").textContent).not.toContain("could not be read");
  });

  // #2463: Escape must not dismiss the dialog while the close is on the wire — the shared modal
  // wiring honours aria-busy, so the dialog marks itself busy for exactly that window.
  it("the dialog is marked busy while the close is on the wire, and not after a failure", async () => {
    let answer: (r: Route) => void = () => {};
    const { api, el } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
      "PATCH /cases/c1/status": () => new Promise<Route>((r) => (answer = r)),
    });
    void api.closeCaseWithCredentials("c1");
    await flush();
    expect(el("closeCaseOverlay").getAttribute("aria-busy")).toBeNull();
    el("ccaConfirm").click();
    await flush();
    expect(el("closeCaseOverlay").getAttribute("aria-busy")).toBe("true");
    answer({ status: 409, body: { error: "collection running" } });
    await flush();
    expect(el("closeCaseOverlay").getAttribute("aria-busy")).toBeNull();
    expect(el("ccaMsg").textContent).toContain("collection running");
  });

  it("the busy mark is cleared when the close succeeds and when a close is superseded", async () => {
    let answer: (r: Route) => void = () => {};
    const { api, el } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
      "PATCH /cases/c1/status": () => new Promise<Route>((r) => (answer = r)),
      "GET /cases/c2/cloud-accounts": { body: { accounts: [ROW] } },
    });
    void api.closeCaseWithCredentials("c1");
    await flush();
    el("ccaConfirm").click();
    await flush();
    expect(el("closeCaseOverlay").getAttribute("aria-busy")).toBe("true");
    void api.closeCaseWithCredentials("c2"); // a fresh dialog is never busy
    await flush();
    expect(el("closeCaseOverlay").getAttribute("aria-busy")).toBeNull();
    answer({ body: { status: "closed" } });
    await flush();
    expect(el("closeCaseOverlay").getAttribute("aria-busy")).toBeNull();
  });

  it("a close that never answers, with a case list that never answers, still gives the dialog back", async () => {
    const timers: Array<() => void> = [];
    const { api, el } = loadClose(
      {
        "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
        "PATCH /cases/c1/status": () => new Promise<Route>(() => {}),
        "GET /cases": () => new Promise<Route>(() => {}),
      },
      "c1",
      timers,
    );
    const done = api.closeCaseWithCredentials("c1");
    await flush();
    el("ccaConfirm").click();
    await flush();
    expect(el("ccaCancel").disabled).toBe(true);
    timers.splice(0).forEach((fn) => fn()); // the close's 30 s deadline passes
    await flush();
    timers.splice(0).forEach((fn) => fn()); // the status read's deadline passes
    await flush();
    expect(el("ccaConfirm").disabled).toBe(false);
    expect(el("ccaCancel").disabled).toBe(false);
    expect(el("ccaMsg").textContent).toContain("may have gone through");
    el("ccaCancel").click();
    expect(await done).toBe(false);
  });

  it("a superseded close does not repaint the toolbar of a different case on screen", async () => {
    let answer: (r: Route) => void = () => {};
    const { api, el, refreshed } = loadClose(
      {
        "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
        "PATCH /cases/c1/status": () => new Promise<Route>((r) => (answer = r)),
        "GET /cases/c2/cloud-accounts": { body: { accounts: [ROW] } },
      },
      "c2",
    );
    const first = api.closeCaseWithCredentials("c1");
    await flush();
    el("ccaConfirm").click();
    await flush();
    void api.closeCaseWithCredentials("c2");
    expect(await first).toBe(false);
    answer({ body: { status: "closed" } });
    await flush();
    expect(refreshed).toEqual(["list"]);
  });
});
