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

// Per-case server sets, the dashboard half (Task 9): the Settings list and editor
// (js/dashboard-server-sets.js), the header label + "Change…" flow (js/dashboard-case-servers.js)
// and the New Case "Servers" picker (js/dashboard-new-case.js).
//
// Each module runs in a vm context against a small fake DOM, the way the browser runs it.

const MASK = "••••••";

interface ServerSetsApi {
  initServerSets(): void;
  loadServerSets(): Promise<void>;
  fetchServerSets(): Promise<{ defaultId: string; sets: Array<Record<string, unknown>>; editable: boolean }>;
  openServerSetEditor(set: Record<string, unknown> | null, opts?: Record<string, unknown>): void;
}

interface CaseServersApi extends ServerSetsApi {
  initCaseServers(): void;
  refreshCaseServers(caseId?: string): Promise<void>;
  caseToolEnabled(tool: string, fallback?: boolean): boolean;
  setDefaultServerTools(health: Record<string, unknown>): void;
  veloEnabled: boolean;
  dfirAuthState?: unknown;
}

interface NewCaseApi extends ServerSetsApi {
  openNewCase(): Promise<void>;
  createNewCase(): Promise<void>;
  initNewCase(): void;
}

type Routes = Record<string, Route | ((call: FetchCall) => Route | Promise<Route>)>;

const TWO_SETS = {
  defaultId: "b",
  sets: [
    { id: "a", name: "Alpha", revision: 1, usedBy: 0 },
    {
      id: "b",
      name: "Beta",
      revision: 1,
      usedBy: 2,
      iris: { url: "https://iris.example.com", apiKey: MASK },
    },
  ],
};

const EDITOR_FIELDS = [
  "sseName",
  "sseIrisUrl",
  "sseIrisKey",
  "sseIrisCa",
  "sseIrisCustomer",
  "sseIrisClassification",
  "sseTsUrl",
  "sseTsUser",
  "sseTsPassword",
  "sseTsCa",
  "sseTsTimeline",
  "sseVeloConfig",
  "sseVeloOrg",
  "sseVeloGuiUrl",
];

/** The markup both server-set modules read, as the page provides it. */
function serverSetMarkup(doc: FakeDocument): void {
  doc.add("div", "serverSetsPanel", "serverSetsList", "serverSetsMsg", "sseMsg", "sseTestResult");
  doc.add("div", "serverSetEditorOverlay");
  doc.add("h3", "serverSetEditorTitle");
  doc.add("button", "serverSetAddBtn", "sseSave", "sseTest", "sseClose", "sseVeloBrowse");
  doc.add("span", "sseTestHint");
  doc.add("input", ...EDITOR_FIELDS);
  const boxes = doc.add("input", "sseIrisInsecure", "sseTsInsecure");
  for (const b of Object.values(boxes)) b.type = "checkbox";
  const label = doc.createElement("span");
  label.dataset.serverSetDefault = "";
  label.id = "veloDefaultLabel";
  doc.body.appendChild(label);
}

function caseServerMarkup(doc: FakeDocument): void {
  doc.add("span", "caseServersLabel", "caseServersPickMsg", "caseServersConfirmMsg");
  doc.add("button", "caseServersChangeBtn", "caseServersPickApply", "caseServersPickCancel");
  doc.add("button", "caseServersConfirmBtn", "caseServersConfirmCancel");
  doc.add("div", "caseServersPickOverlay", "caseServersConfirmOverlay", "caseServersConfirmList");
  doc.add("h3", "caseServersConfirmTitle");
  doc.add("p", "caseServersConfirmNote");
  doc.add("select", "caseServersPick");
  doc.add("input", "caseId");
  const { pushSelect } = doc.add("select", "pushSelect");
  const placeholder = doc.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Push to…";
  pushSelect.appendChild(placeholder);
}

function loadCaseServers(routes: Routes, globals: Record<string, unknown> = {}) {
  const doc = new FakeDocument();
  serverSetMarkup(doc);
  caseServerMarkup(doc);
  const net = routedFetch({ "GET /server-sets": { body: TWO_SETS }, ...routes });
  let veloApplied = 0;
  const api = loadDashboardModule<CaseServersApi>("dashboard-case-servers.js", ["dashboard-server-sets.js"], {
    document: doc,
    fetch: net.fetch,
    veloEnabled: false,
    applyVeloEnabled: () => void veloApplied++,
    ...globals,
  });
  api.initCaseServers();
  return { api, doc, net, el: (id: string) => doc.getElementById(id) as FakeEl, applied: () => veloApplied };
}

function pushValues(doc: FakeDocument): string[] {
  return (doc.getElementById("pushSelect") as FakeEl).options.map((o) => o.value);
}

describe("New Case form", () => {
  function newCaseHarness() {
    const doc = new FakeDocument();
    serverSetMarkup(doc);
    doc.add("input", "ncCaseId", "ncName", "ncInvestigator", "caseId");
    doc.add("div", "ncMsg", "ncTemplateDesc", "newCaseOverlay");
    doc.add("select", "ncServerSet", "ncTemplate");
    doc.add("button", "newCaseBtn", "seedDemoBtn", "ncCreate", "ncCancel");
    const net = routedFetch({
      "GET /server-sets": { body: TWO_SETS },
      "GET /api/next-case-id": { body: { caseId: "INC-2026-001" } },
      "POST /cases": { status: 201, body: {} },
    });
    const api = loadDashboardModule<NewCaseApi>("dashboard-new-case.js", ["dashboard-server-sets.js"], {
      document: doc,
      fetch: net.fetch,
      localStorage: { getItem: () => "", setItem: () => {} },
      populateTemplateSelect: () => {},
      selectedNewCasePlaybook: () => ({ kind: "none" }),
      onTemplateSelectChange: () => {},
      loadCaseList: () => {},
      connect: () => {},
    });
    api.initNewCase();
    return { api, doc, net, el: (id: string) => doc.getElementById(id) as FakeEl };
  }

  it("New Case form lists sets with default preselected", async () => {
    const { api, el } = newCaseHarness();
    await api.openNewCase();
    await flush();
    const select = el("ncServerSet");
    expect(select.options.map((o) => o.textContent)).toEqual(["Alpha", "Beta", "+ New server set…"]);
    expect(select.value).toBe("b");
  });

  it("sends the picked set with the new case", async () => {
    const { api, el, net } = newCaseHarness();
    await api.openNewCase();
    await flush();
    el("ncServerSet").value = "a";
    el("ncName").value = "Globex";
    await api.createNewCase();
    const post = net.calls.find((c) => c.method === "POST" && c.url === "/cases");
    expect(post?.body?.serverSetId).toBe("a");
  });

  it("opens the editor from '+ New server set…' and selects the new set on save", async () => {
    const h = newCaseHarnessWith({
      "POST /server-sets": { status: 201, body: { id: "c", name: "Gamma", revision: 1 } },
    });
    await h.api.openNewCase();
    await flush();
    const select = h.el("ncServerSet");
    select.value = "__new__";
    select.fire("change");
    expect(h.el("serverSetEditorOverlay").classList.contains("open")).toBe(true);
    expect(select.value, "the picker falls back while the editor is open").toBe("b");

    h.el("sseName").value = "Gamma";
    h.el("sseName").fire("input");
    h.listAfterCreate();
    h.el("sseSave").click();
    await flush();
    expect(h.net.calls.find((c) => c.method === "POST" && c.url === "/server-sets")?.body?.name).toBe(
      "Gamma",
    );
    expect(select.value).toBe("c");
    expect(h.el("serverSetEditorOverlay").classList.contains("open")).toBe(false);
  });

  function newCaseHarnessWith(extra: Routes) {
    let list: unknown = TWO_SETS;
    const doc = new FakeDocument();
    serverSetMarkup(doc);
    doc.add("input", "ncCaseId", "ncName", "ncInvestigator", "caseId");
    doc.add("div", "ncMsg", "ncTemplateDesc", "newCaseOverlay");
    doc.add("select", "ncServerSet", "ncTemplate");
    doc.add("button", "newCaseBtn", "seedDemoBtn", "ncCreate", "ncCancel");
    const net = routedFetch({
      "GET /server-sets": () => ({ body: list }),
      "GET /api/next-case-id": { body: { caseId: "INC-2026-001" } },
      ...extra,
    });
    const api = loadDashboardModule<NewCaseApi>("dashboard-new-case.js", ["dashboard-server-sets.js"], {
      document: doc,
      fetch: net.fetch,
      localStorage: { getItem: () => "", setItem: () => {} },
      populateTemplateSelect: () => {},
      selectedNewCasePlaybook: () => ({ kind: "none" }),
      onTemplateSelectChange: () => {},
      loadCaseList: () => {},
      connect: () => {},
    });
    api.initServerSets(); // the page runs both initializers
    api.initNewCase();
    return {
      api,
      net,
      el: (id: string) => doc.getElementById(id) as FakeEl,
      listAfterCreate: () => {
        list = { ...TWO_SETS, sets: [...TWO_SETS.sets, { id: "c", name: "Gamma", revision: 1, usedBy: 0 }] };
      },
    };
  }
});

describe("case header", () => {
  it("header shows the open case's set name and updates on case switch", async () => {
    const { api, el } = loadCaseServers({
      "GET /cases/C1/server-set": { body: { setId: "a", name: "Alpha", tools: ["iris"] } },
      "GET /cases/C2/server-set": { body: { setId: "b", name: "Beta", tools: [] } },
    });
    await api.refreshCaseServers("C1");
    expect(el("caseServersLabel").textContent).toBe("Servers: Alpha");
    expect(el("caseServersLabel").hidden).toBe(false);
    await api.refreshCaseServers("C2");
    expect(el("caseServersLabel").textContent).toBe("Servers: Beta");
  });

  it("ignores a late answer for the case the analyst already left", async () => {
    let release: (r: Route) => void = () => {};
    const slow = new Promise<Route>((r) => (release = r));
    const { api, el } = loadCaseServers({
      "GET /cases/C1/server-set": () => slow,
      "GET /cases/C2/server-set": { body: { setId: "b", name: "Beta", tools: [] } },
    });
    const first = api.refreshCaseServers("C1");
    await api.refreshCaseServers("C2");
    release({ body: { setId: "a", name: "Alpha", tools: ["iris"] } });
    await first;
    await flush();
    expect(el("caseServersLabel").textContent).toBe("Servers: Beta");
  });

  it("shows 'Servers: none' in the error style, with the resolver message as the tooltip", async () => {
    const message = "This case has no server set. Pick one with Change… in the case header.";
    const { api, el, doc } = loadCaseServers({
      "GET /cases/C1/server-set": { status: 409, body: { error: message } },
    });
    await api.refreshCaseServers("C1");
    const label = el("caseServersLabel");
    expect(label.textContent).toBe("Servers: none");
    expect(label.classList.contains("case-servers-error")).toBe(true);
    expect(label.title).toBe(message);
    expect(pushValues(doc)).toEqual([""]);
    expect(api.veloEnabled).toBe(false);
  });

  it("a set name with <img onerror> renders as text", async () => {
    const evil = '<img src=x onerror="alert(1)">';
    const { api, el, doc } = loadCaseServers({
      "GET /server-sets": {
        body: { defaultId: "a", sets: [{ id: "a", name: evil, revision: 1, usedBy: 1 }] },
      },
      "GET /cases/C1/server-set": { body: { setId: "a", name: evil, tools: [] } },
    });
    await api.refreshCaseServers("C1");
    await api.loadServerSets();
    expect(el("caseServersLabel").textContent).toBe(`Servers: ${evil}`);
    expect(el("serverSetsList").textContent).toContain(evil);
    expect(el("veloDefaultLabel").textContent).toBe(`Using server set: ${evil}`);
    expect(doc.htmlWrites()).toEqual([]);
  });
});

describe("tool gating follows the open case's set", () => {
  it("IRIS buttons hide when the case's set has no IRIS", async () => {
    const { api, doc } = loadCaseServers({
      "GET /cases/C1/server-set": { body: { setId: "a", name: "Alpha", tools: ["timesketch"] } },
      "GET /cases/C2/server-set": { body: { setId: "b", name: "Beta", tools: ["iris"] } },
    });
    // The Push menu as js/dashboard-tickets.js left it from the DEFAULT set's status check.
    const iris = doc.createElement("option");
    iris.value = "iris";
    (doc.getElementById("pushSelect") as FakeEl).appendChild(iris);

    await api.refreshCaseServers("C1");
    expect(pushValues(doc)).toEqual(["", "timesketch", "timesketch-super"]);
    await api.refreshCaseServers("C2");
    expect(pushValues(doc)).toEqual(["", "iris"]);
  });

  it("gates Run in Velociraptor on the case's set, and on the default set with no case open", async () => {
    const { api, applied } = loadCaseServers({
      "GET /cases/C1/server-set": { body: { setId: "a", name: "Alpha", tools: [] } },
      "GET /cases/C2/server-set": { body: { setId: "b", name: "Beta", tools: ["velociraptor"] } },
    });
    api.setDefaultServerTools({ velociraptorEnabled: true, irisEnabled: false, timesketchEnabled: false });
    expect(api.veloEnabled, "no case open: the default set decides").toBe(true);
    await api.refreshCaseServers("C1");
    expect(api.veloEnabled, "the case's set has no Velociraptor").toBe(false);
    api.setDefaultServerTools({ velociraptorEnabled: true });
    expect(api.veloEnabled, "a later /health answer does not override the case").toBe(false);
    await api.refreshCaseServers("C2");
    expect(api.veloEnabled).toBe(true);
    expect(api.caseToolEnabled("iris", true)).toBe(false);
    expect(applied()).toBeGreaterThan(0);
  });
});

describe("Change… flow", () => {
  const WORK = { needsConfirm: true, work: { monitors: 2, irisCase: "Globex ransomware", hunts: 3 } };

  function changeHarness(post: (call: FetchCall) => Route) {
    return loadCaseServers({
      "GET /cases/C1/server-set": { body: { setId: "a", name: "Alpha", tools: ["iris"] } },
      "POST /cases/C1/server-set": post,
    });
  }

  async function pickBeta(h: ReturnType<typeof changeHarness>) {
    await h.api.refreshCaseServers("C1");
    h.el("caseServersChangeBtn").click();
    await flush();
    expect(h.el("caseServersPickOverlay").classList.contains("open")).toBe(true);
    expect(h.el("caseServersPick").options.map((o) => o.textContent)).toEqual(["Alpha", "Beta"]);
    h.el("caseServersPick").value = "b";
    h.el("caseServersPickApply").click();
    await flush();
  }

  const posts = (h: ReturnType<typeof changeHarness>) =>
    h.net.calls.filter((c) => c.method === "POST" && c.url === "/cases/C1/server-set");

  it("change with work shows the confirm text and sends confirm:true only on Change servers", async () => {
    const h = changeHarness((call) =>
      call.body?.confirm === true ? { body: { changed: true } } : { status: 409, body: WORK },
    );
    await pickBeta(h);

    expect(h.el("caseServersConfirmOverlay").classList.contains("open")).toBe(true);
    expect(h.el("caseServersConfirmTitle").textContent).toBe("Change server set?");
    expect(h.el("caseServersConfirmList").children.map((c) => c.textContent)).toEqual([
      "2 live monitors will stop.",
      "The link to IRIS case 'Globex ransomware' will be forgotten.",
      "3 Velociraptor hunts will be forgotten.",
    ]);
    expect(h.el("caseServersConfirmNote").textContent).toBe(
      "Nothing on the old servers is deleted. Evidence in this case is kept.",
    );
    expect(h.el("caseServersConfirmBtn").textContent).toBe("Change servers");
    expect(h.el("caseServersConfirmCancel").textContent).toBe("Cancel");
    expect(posts(h).map((c) => c.body)).toEqual([{ setId: "b" }]);

    h.el("caseServersConfirmBtn").click();
    await flush();
    expect(posts(h).map((c) => c.body)).toEqual([{ setId: "b" }, { setId: "b", confirm: true }]);
    expect(h.el("caseServersConfirmOverlay").classList.contains("open")).toBe(false);
  });

  it("cancel sends nothing", async () => {
    const h = changeHarness(() => ({ status: 409, body: WORK }));
    await pickBeta(h);
    h.el("caseServersConfirmCancel").click();
    await flush();
    expect(h.el("caseServersConfirmOverlay").classList.contains("open")).toBe(false);
    expect(posts(h)).toHaveLength(1);
    expect(posts(h)[0].body?.confirm).toBeUndefined();
  });

  it("Escape on the confirm dialog cancels and sends nothing", async () => {
    const h = changeHarness(() => ({ status: 409, body: WORK }));
    await pickBeta(h);
    expect(h.doc.activeElement?.id, "focus moves into the dialog on open").toBe("caseServersConfirmCancel");
    h.el("caseServersConfirmOverlay").fire("keydown", { key: "Escape" });
    await flush();
    expect(h.el("caseServersConfirmOverlay").classList.contains("open")).toBe(false);
    expect(posts(h)).toHaveLength(1);
  });

  it("an IRIS case name from IRIS renders as text in the dialog", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    const h = changeHarness(() => ({
      status: 409,
      body: { needsConfirm: true, work: { monitors: 0, hunts: 0, irisCase: evil } },
    }));
    await pickBeta(h);
    expect(h.el("caseServersConfirmList").textContent).toBe(
      `The link to IRIS case '${evil}' will be forgotten.`,
    );
    expect(h.doc.htmlWrites()).toEqual([]);
  });

  it("a change with no work happens with no dialog", async () => {
    const h = changeHarness(() => ({ body: { changed: true } }));
    await pickBeta(h);
    expect(h.el("caseServersConfirmOverlay").classList.contains("open")).toBe(false);
    expect(h.el("caseServersPickOverlay").classList.contains("open")).toBe(false);
    expect(posts(h)).toHaveLength(1);
  });

  it("a 403 shows a plain error and keeps the picker usable", async () => {
    const h = changeHarness(() => ({ status: 403, body: { error: "forbidden" } }));
    await pickBeta(h);
    expect(h.el("caseServersConfirmOverlay").classList.contains("open")).toBe(false);
    expect(h.el("caseServersPickMsg").textContent).toContain("permission");
    expect(h.el("caseServersPickApply").disabled).toBe(false);
  });

  it("hides Change… from a member who does not administer the case", async () => {
    const h = loadCaseServers(
      { "GET /cases/C1/server-set": { body: { setId: "a", name: "Alpha", tools: [] } } },
      {
        dfirAuthState: {
          enabled: true,
          authenticated: true,
          identity: { globalRole: "member" },
          caseRoles: { C1: "investigator" },
        },
      },
    );
    await h.api.refreshCaseServers("C1");
    expect(h.el("caseServersLabel").textContent).toBe("Servers: Alpha");
    expect(h.el("caseServersChangeBtn").hidden).toBe(true);
  });
});

describe("Settings → Server sets", () => {
  function settingsHarness(routes: Routes, globals: Record<string, unknown> = {}) {
    const doc = new FakeDocument();
    serverSetMarkup(doc);
    const net = routedFetch(routes);
    const api = loadDashboardModule<ServerSetsApi>("dashboard-server-sets.js", [], {
      document: doc,
      fetch: net.fetch,
      confirm: () => true,
      ...globals,
    });
    api.initServerSets();
    return { api, doc, net, el: (id: string) => doc.getElementById(id) as FakeEl };
  }

  const STORED = {
    id: "b",
    name: "Beta",
    revision: 3,
    usedBy: 2,
    iris: { url: "https://iris.example.com", apiKey: MASK },
    timesketch: { url: "https://ts.example.com", user: "analyst", password: MASK },
    velociraptor: { apiConfigPath: "/srv/velo/api.config.yaml" },
  };

  it("marks the default set and counts the cases using each set", async () => {
    const { api, el } = settingsHarness({ "GET /server-sets": { body: TWO_SETS } });
    await api.loadServerSets();
    const rows = el("serverSetsList").children;
    expect(rows).toHaveLength(2);
    expect(rows[1].querySelector(".server-set-badge")?.textContent).toBe("default");
    expect(rows[0].querySelector(".server-set-badge")).toBeNull();
    expect(rows[1].textContent).toContain("Used by 2 cases");
    expect(rows[0].textContent).toContain("Used by 0 cases");
    expect(el("veloDefaultLabel").textContent).toBe("Using server set: Beta");
  });

  it("editor save without retyping a secret sends the mask", async () => {
    const { api, el, net } = settingsHarness({
      "GET /server-sets": { body: { defaultId: "b", sets: [STORED] } },
      "PUT /server-sets/b": { body: { ...STORED, name: "Beta lab" } },
    });
    await api.loadServerSets();
    api.openServerSetEditor(STORED);
    expect(el("sseIrisKey").value).toBe(MASK);
    expect(el("sseTsPassword").value).toBe(MASK);
    el("sseName").value = "Beta lab";
    el("sseName").fire("input");
    el("sseSave").click();
    await flush();
    const put = net.calls.find((c) => c.method === "PUT");
    expect(put?.url).toBe("/server-sets/b");
    expect(put?.body).toMatchObject({
      name: "Beta lab",
      iris: { url: "https://iris.example.com", apiKey: MASK },
      timesketch: { url: "https://ts.example.com", user: "analyst", password: MASK },
      velociraptor: { apiConfigPath: "/srv/velo/api.config.yaml" },
    });
  });

  it("tests only a saved set, and asks to save unsaved edits first", async () => {
    const { api, el, net } = settingsHarness({
      "GET /server-sets": { body: { defaultId: "b", sets: [STORED] } },
      "POST /server-sets/b/test": {
        body: { iris: { ok: true }, timesketch: { ok: false, error: "login failed" } },
      },
    });
    await api.loadServerSets();
    api.openServerSetEditor(null);
    expect(el("sseTest").disabled, "a new set cannot be tested").toBe(true);
    expect(el("sseTestHint").textContent).toBe("Save first to test");

    api.openServerSetEditor(STORED);
    expect(el("sseTest").disabled).toBe(false);
    el("sseIrisUrl").value = "https://iris2.example.com";
    el("sseIrisUrl").fire("input");
    expect(el("sseTest").disabled).toBe(true);
    expect(el("sseTestHint").textContent).toBe("Save first to test");

    api.openServerSetEditor(STORED);
    el("sseTest").click();
    await flush();
    expect(net.calls.some((c) => c.method === "POST" && c.url === "/server-sets/b/test")).toBe(true);
    expect(el("sseTestResult").textContent).toContain("IRIS: connected");
    expect(el("sseTestResult").textContent).toContain("Timesketch: login failed");
  });

  it("shows the case names when a set in use cannot be deleted", async () => {
    const { api, el } = settingsHarness({
      "GET /server-sets": { body: TWO_SETS },
      "DELETE /server-sets/a": {
        status: 409,
        body: {
          error: "Server set is in use",
          usedBy: [
            { id: "C1", name: "Globex <b>BEC</b>" },
            { id: "C2", name: "Initech" },
          ],
        },
      },
    });
    await api.loadServerSets();
    const del = el("serverSetsList")
      .children[0].querySelectorAll("button")
      .find((b) => b.textContent === "Delete");
    del?.click();
    await flush();
    expect(el("serverSetsMsg").textContent).toContain("Globex <b>BEC</b>, Initech");
  });

  it("shows the server's message when the default set cannot be deleted", async () => {
    const msg = "The default server set cannot be deleted. Make another set the default first.";
    const { api, el } = settingsHarness({
      "GET /server-sets": { body: TWO_SETS },
      "DELETE /server-sets/b": { status: 409, body: { error: msg } },
    });
    await api.loadServerSets();
    const del = el("serverSetsList")
      .children[1].querySelectorAll("button")
      .find((b) => b.textContent === "Delete");
    del?.click();
    await flush();
    expect(el("serverSetsMsg").textContent).toBe(msg);
  });

  it("shows members the list read-only", async () => {
    const { api, el } = settingsHarness(
      {
        "GET /server-sets": {
          body: {
            defaultId: "b",
            sets: [
              { id: "a", name: "Alpha" },
              { id: "b", name: "Beta" },
            ],
          },
        },
      },
      { dfirAuthState: { enabled: true, authenticated: true, identity: { globalRole: "member" } } },
    );
    await api.loadServerSets();
    const rows = el("serverSetsList").children;
    expect(rows.map((r) => r.querySelectorAll("button").length)).toEqual([0, 0]);
    expect(rows[1].querySelector(".server-set-badge")?.textContent).toBe("default");
    expect(el("serverSetAddBtn").hidden).toBe(true);
  });
});
