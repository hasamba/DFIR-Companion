import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import {
  FakeDocument,
  type FakeEl,
  type FetchCall,
  flush,
  type Route,
  routedFetch,
} from "./serverSetsFakeDom.js";

// #2379: while a collection runs, the Cloud Collection panel polls its progress. A poll refreshes the
// collection rows only — it must not rebuild the start form, must not ask the account's regions
// again (a real ec2:DescribeRegions call and a team-audit entry), and must not reset what the
// analyst changed in the form. A full rebuild happens on open, case switch, start and resume.

interface CollectApi {
  loadCloudCollect(caseId?: string): Promise<void>;
}

const AWS = {
  provider: "aws",
  label: "AWS",
  available: true,
  regionPicker: true,
  sources: [{ id: "cloudtrail-lookup", label: "Event history" }],
};
const ACCOUNTS = [{ id: "a1", name: "AWS prod", provider: "aws" }];
const LISTING = {
  regions: ["eu-west-1", "af-south-1", "us-east-1"],
  home: "eu-west-1",
  source: "ec2:DescribeRegions",
};

function collection(id: string, status: string, pages: number) {
  return {
    checkpoint: {
      collectionId: id,
      provider: "aws",
      accountId: "a1",
      status,
      window: { start: "s", end: "e" },
      subWindows: [],
      imported: [],
    },
    header: { accountName: `AWS prod ${id}` },
    pages,
    bytes: 0,
  };
}

const listOf = (...collections: unknown[]): Route => ({ body: { providers: [AWS], collections } });

type RouteFn = (call: FetchCall) => Route | Promise<Route>;

/** setTimeout/clearTimeout the test drives by hand: `tick()` runs the pending poll. */
function fakeTimers() {
  let next = 1;
  const pending = new Map<number, () => void>();
  return {
    setTimeout: (fn: () => void) => {
      const id = next++;
      pending.set(id, fn);
      return id;
    },
    clearTimeout: (id: number) => {
      pending.delete(id);
    },
    count: () => pending.size,
    async tick() {
      const fns = [...pending.values()];
      pending.clear();
      for (const fn of fns) fn();
      await flush();
    },
  };
}

function load(routes: Record<string, Route | RouteFn>) {
  const doc = new FakeDocument();
  doc.add("div", "cloudCollect");
  doc.add("section", "sec-cloud-collect");
  doc.add("button", "cloudCollectBtn");
  const caseBox = doc.add("input", "caseId").caseId;
  caseBox.value = "c1";
  const net = routedFetch({
    "GET /cases/c1/cloud-collect": listOf(collection("cc-1", "running", 1)),
    "GET /cases/c1/cloud-accounts": { body: { accounts: ACCOUNTS } },
    "POST /cases/c1/cloud-collect/regions": { body: LISTING },
    "POST /cases/c1/cloud-collect/precheck": { body: { sources: [], quota: null } },
    "POST /cases/c1/cloud-collect": { status: 202, body: { collectionId: "cc-x", jobId: "j1" } },
    "GET /cases/c2/cloud-collect": listOf(collection("cc-9", "complete", 4)),
    "GET /cases/c2/cloud-accounts": { body: { accounts: ACCOUNTS } },
    "POST /cases/c2/cloud-collect/regions": { body: LISTING },
    ...routes,
  });
  const timers = fakeTimers();
  const api = loadDashboardModule<CollectApi>("dashboard-cloud-collect.js", [], {
    document: doc,
    fetch: net.fetch,
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
  });
  const box = () => doc.getElementById("cloudCollect") as FakeEl;
  const q = (sel: string) => box().querySelector(sel) as FakeEl;
  const qa = (sel: string) => box().querySelectorAll(sel);
  const count = (method: string, url: string) =>
    net.calls.filter((c) => c.method === method && c.url === url).length;
  const switchCase = (id: string) => (caseBox.value = id);
  return { api, net, doc, box, q, qa, timers, count, switchCase };
}

/** A list route whose answer the test changes between polls. */
function changing(first: Route) {
  let answer = first;
  return {
    route: (() => answer) as RouteFn,
    set: (next: Route) => (answer = next),
  };
}

describe("the Cloud Collection progress poll (#2379)", () => {
  it("refreshes the rows only: same form, no second region list, the analyst's edits kept", async () => {
    const list = changing(listOf(collection("cc-1", "running", 1)));
    const { api, q, qa, timers, count } = load({ "GET /cases/c1/cloud-collect": list.route });
    await api.loadCloudCollect("c1");
    await flush();
    const form = q(".cc-form");
    expect(count("POST", "/cases/c1/cloud-collect/regions")).toBe(1);
    // The analyst edits the form.
    qa(".cc-region").find((b) => b.value === "us-east-1")!.checked = false;
    q("#cloudCollectStart").value = "2026-01-02T03:04";
    q("#cloudCollectOverlap").value = "15";
    expect(timers.count()).toBe(1);

    list.set(listOf(collection("cc-1", "running", 7)));
    await timers.tick();

    expect(q(".cc-form") === form).toBe(true); // identity; never diff a FakeEl tree
    expect(count("POST", "/cases/c1/cloud-collect/regions")).toBe(1);
    expect(count("GET", "/cases/c1/cloud-accounts")).toBe(1);
    expect(qa(".cc-region").find((b) => b.value === "us-east-1")!.checked).toBe(false);
    expect(q("#cloudCollectStart").value).toBe("2026-01-02T03:04");
    expect(q("#cloudCollectOverlap").value).toBe("15");
    expect(q(".cc-row").textContent).toContain("7 page(s) saved");
    expect(timers.count()).toBe(1); // still running → still polling
  });

  it("keeps a shown pre-check through a poll, and its Confirm still starts", async () => {
    const { api, net, q, timers } = load({});
    await api.loadCloudCollect("c1");
    await flush();
    q(".cc-form").fire("submit");
    await flush();
    expect(q(".cc-precheck").textContent).toContain("Confirm and start");
    await timers.tick();
    expect(q(".cc-precheck").textContent).toContain("Confirm and start");
    q(".cc-precheck")
      .querySelectorAll("button")
      .find((b) => b.textContent === "Confirm and start")!
      .click();
    await flush();
    expect(net.calls.some((c) => c.method === "POST" && c.url === "/cases/c1/cloud-collect")).toBe(true);
  });

  it("stops polling once no collection is running", async () => {
    const list = changing(listOf(collection("cc-1", "running", 1), collection("cc-2", "running", 1)));
    const { api, q, qa, timers } = load({ "GET /cases/c1/cloud-collect": list.route });
    await api.loadCloudCollect("c1");
    await flush();
    list.set(listOf(collection("cc-1", "complete", 3), collection("cc-2", "running", 2)));
    await timers.tick();
    expect(timers.count()).toBe(1); // one is still running
    list.set(listOf(collection("cc-1", "complete", 3), collection("cc-2", "complete", 5)));
    await timers.tick();
    expect(timers.count()).toBe(0);
    expect(qa(".cc-row").length).toBe(2);
    expect(q(".cc-list").textContent).toContain("complete");
    expect(q(".cc-list").textContent).not.toContain("running");
  });

  it("a failed poll keeps the form, shows the error and stops polling", async () => {
    const list = changing(listOf(collection("cc-1", "running", 1)));
    const { api, q, timers } = load({ "GET /cases/c1/cloud-collect": list.route });
    await api.loadCloudCollect("c1");
    await flush();
    const form = q(".cc-form");
    list.set({ status: 500, body: { error: "The collections could not be read." } });
    await timers.tick();
    expect(q(".cc-form") === form).toBe(true); // identity; never diff a FakeEl tree
    expect(q(".cc-list").textContent).toContain("The collections could not be read.");
    expect(timers.count()).toBe(0);
  });

  it("a demo 403 on a poll hides the panel as the first load does", async () => {
    const list = changing(listOf(collection("cc-1", "running", 1)));
    const { api, doc, timers } = load({ "GET /cases/c1/cloud-collect": list.route });
    await api.loadCloudCollect("c1");
    await flush();
    list.set({ status: 403, body: { demo: true, error: "demo" } });
    await timers.tick();
    expect((doc.getElementById("sec-cloud-collect") as FakeEl).hidden).toBe(true);
    expect(timers.count()).toBe(0);
  });

  it("a case switch rebuilds the panel for the new case, and the old case's tick does nothing", async () => {
    const { api, q, timers, count, switchCase } = load({});
    await api.loadCloudCollect("c1");
    await flush();
    const form = q(".cc-form");
    switchCase("c2");
    await timers.tick(); // c1's pending tick, after the analyst left c1
    expect(count("GET", "/cases/c1/cloud-collect")).toBe(1);
    await api.loadCloudCollect("c2");
    await flush();
    expect(q(".cc-form") === form).toBe(false);
    expect(q(".cc-list").textContent).toContain("AWS prod cc-9");
    expect(count("POST", "/cases/c2/cloud-collect/regions")).toBe(1);
  });

  it("a full render started while a poll is in flight drops the poll's answer", async () => {
    let release: (r: Route) => void = () => {};
    let held = false;
    const { api, q, timers } = load({
      "GET /cases/c1/cloud-collect": () => {
        if (held) return new Promise<Route>((resolve) => (release = resolve));
        return listOf(collection("cc-1", "running", 2));
      },
    });
    await api.loadCloudCollect("c1");
    await flush();
    held = true;
    await timers.tick(); // the poll is now waiting
    held = false;
    await api.loadCloudCollect("c1"); // e.g. after Resume
    await flush();
    const form = q(".cc-form");
    release(listOf(collection("cc-1", "complete", 99)));
    await flush();
    expect(q(".cc-form") === form).toBe(true); // identity; never diff a FakeEl tree
    expect(q(".cc-row").textContent).toContain("2 page(s) saved");
    expect(timers.count()).toBe(1); // the full render's poll is still armed
  });

  it("a start answer that lands after a case switch neither rebuilds nor stops the new case's poll", async () => {
    let release: (r: Route) => void = () => {};
    const { api, q, timers, count, switchCase } = load({
      "POST /cases/c1/cloud-collect": () => new Promise<Route>((resolve) => (release = resolve)),
      "GET /cases/c2/cloud-collect": listOf(collection("cc-9", "running", 4)),
    });
    await api.loadCloudCollect("c1");
    await flush();
    q(".cc-form").fire("submit");
    await flush();
    q(".cc-precheck")
      .querySelectorAll("button")
      .find((b) => b.textContent === "Confirm and start")!
      .click();
    await flush();
    switchCase("c2");
    await api.loadCloudCollect("c2");
    await flush();
    const form = q(".cc-form");
    expect(timers.count()).toBe(1);
    release({ status: 202, body: { collectionId: "cc-x", jobId: "j1" } });
    await flush();
    expect(q(".cc-form") === form).toBe(true); // identity; never diff a FakeEl tree
    expect(timers.count()).toBe(1);
    expect(count("GET", "/cases/c1/cloud-collect")).toBe(1);
    expect(q("#cloudCollectMsg").textContent).toBe("");
  });
});

describe("the region checkbox layout (#2379)", () => {
  const css = readFileSync(new URL("../../../public/css/dashboard-panels.css", import.meta.url), "utf8");
  const rule = (sel: string) => {
    const esc = sel.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return css.match(new RegExp(`(^|\\n)${esc}\\s*\\{[^}]*\\}`))?.[0] ?? "";
  };

  it("lays the regions out as a wrapping grid that can shrink to a narrow panel", () => {
    const grid = rule(".cc-regions");
    expect(grid).toMatch(/display:\s*grid/);
    expect(grid).toMatch(/repeat\(auto-fill,\s*minmax\(min\(100%,/);
    expect(grid).toMatch(/min-width:\s*0/);
  });

  it("puts each checkbox next to its region name", () => {
    const field = rule(".cc-regions .cc-field");
    expect(field).toMatch(/flex-direction:\s*row-reverse/);
    expect(field).toMatch(/align-items:\s*center/);
  });

  it("gives the legend, the tick-all tools and the notes the whole row", () => {
    const span = css.match(/[^}]*\{[^}]*grid-column:\s*1\s*\/\s*-1[^}]*\}/g)?.join("\n") ?? "";
    for (const sel of [
      ".cc-regions > legend",
      ".cc-region-tools",
      ".cc-regions > .cc-note",
      ".cc-regions > .cc-missing",
    ])
      expect(span).toContain(sel);
  });
});

// #2492: the collection list is announced as a list only while it holds collection rows. An empty
// state or an error message inside role=list is a list with no list items (axe aria-required-children).
describe("the Cloud Collection list semantics (#2492)", () => {
  const list = (q: (sel: string) => FakeEl) => q(".cc-list");

  it("is a list while it holds rows", async () => {
    const { api, q } = load({});
    await api.loadCloudCollect("c1");
    await flush();
    expect(list(q).getAttribute("role")).toBe("list");
  });

  it("is not a list when there are no collections", async () => {
    const { api, q } = load({ "GET /cases/c1/cloud-collect": listOf() });
    await api.loadCloudCollect("c1");
    await flush();
    expect(list(q).getAttribute("role")).toBeNull();
    expect(list(q).getAttribute("aria-label")).toBeNull();
  });

  it("drops the list role when a poll empties it, and when a poll fails", async () => {
    const answers = changing(listOf(collection("cc-1", "running", 1)));
    const { api, q, timers } = load({ "GET /cases/c1/cloud-collect": answers.route });
    await api.loadCloudCollect("c1");
    await flush();
    expect(list(q).getAttribute("role")).toBe("list");
    answers.set({ status: 500, body: { error: "down" } });
    await timers.tick();
    expect(list(q).getAttribute("role")).toBeNull();
  });

  it("drops the list role when a poll returns no collections", async () => {
    const answers = changing(listOf(collection("cc-1", "running", 1)));
    const { api, q, timers } = load({ "GET /cases/c1/cloud-collect": answers.route });
    await api.loadCloudCollect("c1");
    await flush();
    answers.set(listOf());
    await timers.tick();
    expect(list(q).getAttribute("role")).toBeNull();
  });
});
