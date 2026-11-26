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

// Client Baseline panel → Edit client…, Archive / Unarchive client, Delete client…, Show archived
// clients (#2941). The instance administrator's only: a member sees none of them (nor New client…).
// Each acts on the client picked in the Client box; Delete asks first, naming the client, and a 409
// names the linked cases and suggests Archive.

interface PanelApi {
  loadClientBaseline(caseId: string): Promise<void>;
}
type Routes = Record<string, Route | ((call: FetchCall) => Route | Promise<Route>)>;

const CASE = "HUNT-1";
const ADMIN = { enabled: true, identity: { globalRole: "administrator" } };
const MEMBER = { enabled: true, identity: { globalRole: "member" } };
const ACTIVE = [
  { id: "client-a-1", name: "Client A", defaultServerSetId: "set-1" },
  { id: "client-b-2", name: "Client B" },
];
const WITH_ARCHIVED = [...ACTIVE, { id: "client-c-3", name: "Client C", archived: true }];

function harness(
  opts: { auth?: unknown; confirm?: boolean; linked?: Record<string, unknown> | null; extra?: Routes } = {},
) {
  const doc = new FakeDocument();
  doc.add("div", "clientBaselinePanel");
  const asked: string[] = [];
  const net = routedFetch({
    [`GET /cases/${CASE}/hunt/status`]: { body: { hunt: { id: CASE } } },
    [`GET /cases/${CASE}/hunt/client`]: {
      body: { client: opts.linked ?? null, currentVersion: 1, pinnedVersion: null, pending: 0 },
    },
    "GET /client-profiles": { body: ACTIVE },
    "GET /client-profiles?includeArchived=1": { body: WITH_ARCHIVED },
    [`GET /cases/${CASE}/hunt/candidates`]: { body: { candidates: [] } },
    "GET /client-profiles/client-c-3": { status: 200, body: { baseline: {} } },
    "GET /server-sets": {
      body: {
        defaultId: "set-1",
        sets: [
          { id: "set-1", name: "Alpha" },
          { id: "set-2", name: "Beta" },
        ],
      },
    },
    ...opts.extra,
  });
  const api = loadDashboardModule<PanelApi>("dashboard-client-baseline.js", ["dashboard-client-admin.js"], {
    document: doc,
    fetch: net.fetch,
    prompt: () => null,
    confirm: (m: string) => {
      asked.push(m);
      return opts.confirm ?? true;
    },
    dfirAuthState: opts.auth,
  });
  const panel = () => doc.getElementById("clientBaselinePanel") as FakeEl;
  const render = async () => {
    await api.loadClientBaseline(CASE);
    await flush();
  };
  const btn = (text: string) =>
    panel()
      .querySelectorAll("button")
      .find((b) => b.textContent === text);
  const select = () => doc.getElementById("cbClientSelect") as FakeEl;
  const pick = async (id: string) => {
    select().value = id;
    select().fire("change");
    await flush();
  };
  const status = () =>
    panel()
      .querySelectorAll("p")
      .map((p) => p.textContent)
      .join("\n");
  const sent = (method: string) => net.calls.filter((c) => c.method === method);
  return { doc, net, panel, render, btn, select, pick, status, asked, sent };
}

describe("client management buttons (#2941)", () => {
  it("shows Edit / Archive / Delete / Show archived and New client… to the administrator", async () => {
    const h = harness({ auth: ADMIN });
    await h.render();
    for (const t of ["New client…", "Edit client…", "Archive client", "Delete client…"])
      expect(h.btn(t), t).toBeDefined();
    expect(h.doc.getElementById("cbShowArchived")).not.toBeNull();
  });

  it("shows them in single-user mode, where the one operator is the administrator", async () => {
    const h = harness({ auth: { enabled: false } });
    await h.render();
    expect(h.btn("Delete client…")).toBeDefined();
  });

  it("shows a member none of them, nor New client…", async () => {
    const h = harness({ auth: MEMBER });
    await h.render();
    for (const t of ["New client…", "Edit client…", "Archive client", "Unarchive client", "Delete client…"])
      expect(h.btn(t), t).toBeUndefined();
    expect(h.doc.getElementById("cbShowArchived")).toBeNull();
    expect(h.btn("Link case to client")).toBeDefined();
  });

  it("asks for a pick before acting on nothing", async () => {
    const h = harness({ auth: ADMIN });
    await h.render();
    h.btn("Delete client…")?.click();
    await flush();
    expect(h.asked).toEqual([]);
    expect(h.status()).toContain("Pick a client in the Client box first.");
  });

  it("Delete asks first, naming the client; Cancel sends nothing", async () => {
    const h = harness({ auth: ADMIN, confirm: false });
    await h.render();
    await h.pick("client-b-2");
    h.btn("Delete client…")?.click();
    await flush();
    expect(h.asked).toHaveLength(1);
    expect(h.asked[0]).toContain("Client B");
    expect(h.sent("DELETE")).toEqual([]);
  });

  it("a confirmed delete calls the server and reloads with the result", async () => {
    const h = harness({
      auth: ADMIN,
      extra: { "DELETE /client-profiles/client-b-2": { body: { deleted: "client-b-2" } } },
    });
    await h.render();
    await h.pick("client-b-2");
    h.btn("Delete client…")?.click();
    await flush();
    expect(h.sent("DELETE").map((c) => c.url)).toEqual(["/client-profiles/client-b-2"]);
    expect(h.status()).toContain("Client “Client B” deleted.");
  });

  it("a 409 names every linked case and suggests Archive", async () => {
    const h = harness({
      auth: ADMIN,
      extra: {
        "DELETE /client-profiles/client-a-1": {
          status: 409,
          body: {
            error: "linked",
            linkedCases: [
              { caseId: "c1", name: "Hunt one" },
              { caseId: "c2", name: "Hunt two", unreadable: true },
            ],
          },
        },
      },
    });
    await h.render();
    await h.pick("client-a-1");
    h.btn("Delete client…")?.click();
    await flush();
    const said = h.status();
    expect(said).toContain(
      "Cannot delete “Client A”: it is linked to 2 case(s): Hunt one (c1), Hunt two (c2, link file unreadable).",
    );
    expect(said).toContain("Archive the client instead.");
  });

  it("Show archived lists archived clients marked (archived) and offers Unarchive for one", async () => {
    const h = harness({
      auth: ADMIN,
      extra: { "POST /client-profiles/client-c-3/unarchive": { body: { id: "client-c-3" } } },
    });
    await h.render();
    expect(h.select().options.map((o) => o.textContent)).not.toContain("Client C (archived)");
    const toggle = h.doc.getElementById("cbShowArchived") as FakeEl;
    toggle.checked = true;
    toggle.fire("change");
    await flush();
    expect(h.select().options.map((o) => o.textContent)).toContain("Client C (archived)");
    await h.pick("client-c-3");
    expect(h.btn("Unarchive client")).toBeDefined();
    h.btn("Unarchive client")?.click();
    await flush();
    expect(h.sent("POST").map((c) => c.url)).toEqual(["/client-profiles/client-c-3/unarchive"]);
    expect(h.status()).toContain("unarchived");
  });

  it("Archive posts for the picked client and says linked cases keep working", async () => {
    const h = harness({
      auth: ADMIN,
      extra: { "POST /client-profiles/client-a-1/archive": { body: { id: "client-a-1", archived: true } } },
    });
    await h.render();
    await h.pick("client-a-1");
    h.btn("Archive client")?.click();
    await flush();
    expect(h.sent("POST").map((c) => c.url)).toEqual(["/client-profiles/client-a-1/archive"]);
    expect(h.status()).toContain("linked cases keep working");
  });

  it("Edit client… saves the new name and the picked default server set", async () => {
    const h = harness({
      auth: ADMIN,
      extra: { "PUT /client-profiles/client-a-1": { body: { name: "Client A2" } } },
    });
    await h.render();
    await h.pick("client-a-1");
    h.btn("Edit client…")?.click();
    await flush();
    const name = h.doc.getElementById("cbEditClientName") as FakeEl;
    const set = h.doc.getElementById("cbEditClientServerSet") as FakeEl;
    expect(name.value).toBe("Client A");
    expect(set.value).toBe("set-1");
    name.value = "Client A2";
    set.value = "set-2";
    h.btn("Save client")?.click();
    await flush();
    expect(h.sent("PUT")).toEqual([
      {
        method: "PUT",
        url: "/client-profiles/client-a-1",
        body: { name: "Client A2", defaultServerSetId: "set-2" },
      },
    ]);
    expect(h.status()).toContain("Client “Client A2” saved.");
  });

  it("a linked archived client shows as (archived) and is not offered as a link target", async () => {
    const linked = { id: "client-c-3", name: "Client C", archived: true };
    const h = harness({ auth: MEMBER, linked });
    await h.render();
    expect(h.select().value).toBe("client-c-3");
    expect(h.select().options.map((o) => o.textContent)).toContain("Client C (archived)");
    expect(h.status()).toContain("Client C (archived) · baseline version 1");
    h.btn("Link case to client")?.click();
    await flush();
    expect(h.sent("POST")).toEqual([]);
    expect(h.status()).toContain("Unarchive it before linking");
  });

  it("writes nothing through innerHTML", async () => {
    const h = harness({ auth: ADMIN });
    await h.render();
    expect(h.doc.htmlWrites()).toEqual([]);
  });
});

describe("archived clients elsewhere (#2941)", () => {
  it("the Threat Hunt panel marks an archived client", async () => {
    const box = new FakeDocument();
    box.add("div", "huntCasePanel");
    const status = {
      hunt: true,
      coverage: { known: false },
      items: [],
      clientName: "Client C",
      clientArchived: true,
    };
    const api = loadDashboardModule<{ loadHuntCase: (id: string) => Promise<void> }>(
      "dashboard-hunt-case.js",
      [],
      {
        document: box,
        fetch: async () => ({ ok: true, status: 200, json: async () => status }),
      },
    );
    await api.loadHuntCase("c1");
    const text = (box.getElementById("huntCasePanel") as FakeEl)
      .querySelectorAll("p")
      .map((p) => p.textContent);
    expect(text).toContain("Client: Client C (archived)");
  });
});
