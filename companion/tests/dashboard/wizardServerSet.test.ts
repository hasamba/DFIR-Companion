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

// Fix round 1, item 2: the first-run wizard's IRIS, Timesketch and Velociraptor steps save into the
// DEFAULT server set. The seed reads .env once, so a wizard that kept writing DFIR_IRIS_* there was
// a dead end: the step said "saved" and nothing ever read the value.

const MASK = "••••••";

interface WizardField {
  key: string;
  set?: string;
}
interface WizardStep {
  id: string;
  serverSet?: boolean;
  reload?: string;
  fields: WizardField[];
}
interface Api {
  wizardStepById(id: string): WizardStep;
  wizSaveServerSetStep(step: WizardStep, resultEl: FakeEl, btn: FakeEl): Promise<void>;
  wizBindServerSetStep(step: WizardStep, resultEl: FakeEl, btn: FakeEl): Promise<void>;
}

type Routes = Record<string, Route | ((call: FetchCall) => Route | Promise<Route>)>;

const TESTING = {
  id: "t1",
  name: "Testing",
  revision: 2,
  usedBy: 3,
  iris: { url: "https://old-iris.example.com", apiKey: MASK, customerId: "1" },
  velociraptor: { apiConfigPath: "/srv/velo/api.config.yaml" },
};

function harness(routes: Routes, values: Record<string, string>) {
  const doc = new FakeDocument();
  for (const [key, value] of Object.entries(values)) {
    const input = doc.add("input", `wizf-${key}`)[`wizf-${key}`];
    input.value = value;
  }
  const { res, btn } = {
    res: doc.add("div", "res").res,
    btn: doc.add("button", "wizStepSaveBtn").wizStepSaveBtn,
  };
  const note = doc.add("span", "wizStepSaveNote").wizStepSaveNote;
  let statusReads = 0;
  const net = routedFetch({
    "POST /settings/env": { body: { ok: true } },
    "POST /settings/reload": { body: { ok: true } },
    "POST /iris/reconnect": { body: { configured: true, ok: true } },
    "POST /timesketch/reconnect": { body: { configured: true, ok: true } },
    "POST /velociraptor/reconnect": { body: { configured: true, ok: true } },
    ...routes,
  });
  const api = loadDashboardModule<Api>(
    "dashboard-wizard-server-set.js",
    ["dashboard-values.js", "dashboard-wizard-steps.js", "dashboard-server-sets.js"],
    {
      document: doc,
      fetch: net.fetch,
      wizRefreshStatus: async () => {
        statusReads++;
        await net.fetch("/setup/status");
      },
    },
  );
  const envKeys = () =>
    net.calls
      .filter((c) => c.url === "/settings/env")
      .flatMap((c) => Object.keys((c.body?.updates as Record<string, string>) ?? {}));
  return { api, net, res, btn, note, envKeys, statusReads: () => statusReads };
}

describe("the setup wizard saves server connections into the default server set", () => {
  it("marks the IRIS, Timesketch and Velociraptor steps, and maps every connection field", () => {
    const { api } = harness({}, {});
    for (const id of ["iris", "timesketch", "velociraptor"]) {
      expect(api.wizardStepById(id).serverSet, id).toBe(true);
    }
    const sets = (id: string) => api.wizardStepById(id).fields.map((f) => [f.key, f.set ?? null]);
    expect(sets("iris")).toContainEqual(["DFIR_IRIS_URL", "iris.url"]);
    expect(sets("iris")).toContainEqual(["DFIR_IRIS_KEY", "iris.apiKey"]);
    expect(sets("iris")).toContainEqual(["DFIR_TLS_ALLOW_INSECURE_EXTERNAL", null]);
    expect(sets("timesketch")).toContainEqual(["DFIR_TIMESKETCH_PASSWORD", "timesketch.password"]);
    expect(sets("velociraptor")).toContainEqual([
      "DFIR_VELOCIRAPTOR_API_CONFIG",
      "velociraptor.apiConfigPath",
    ]);
    expect(sets("velociraptor")).toContainEqual(["DFIR_VELOCIRAPTOR_BINARY", null]);
    expect(api.wizardStepById("iris").reload, "no .env family left to reload").toBeUndefined();
  });

  it("routes those steps' Save to the server-set path", () => {
    const wizard = readFileSync(
      new URL("../../../public/js/dashboard-setup-wizard.js", import.meta.url),
      "utf8",
    );
    expect(wizard).toMatch(/step\.serverSet[\s\S]{0,240}wizBindServerSetStep\(step, res, btn\)/);
    expect(wizard).toContain("Saved to the default server set. Edit sets in Settings → Server sets.");
  });

  it("with the server-set module missing, Save says so and writes nothing, never .env", async () => {
    const doc = new FakeDocument();
    const { res, btn } = { res: doc.add("div", "res").res, btn: doc.add("button", "btn").btn };
    const net = routedFetch({});
    const wiz = loadDashboardModule<{
      wizardStepById(id: string): WizardStep;
      wizBindStepSave(step: WizardStep, resultEl: FakeEl, btn: FakeEl): void;
    }>("dashboard-setup-wizard.js", ["dashboard-values.js", "dashboard-wizard-steps.js"], {
      document: doc,
      fetch: net.fetch,
    });
    wiz.wizBindStepSave(wiz.wizardStepById("iris"), res, btn);
    btn.onclick?.({ type: "click", preventDefault: () => undefined });
    await flush();
    expect(res.textContent).toBe("Server-set save is unavailable. Reload the page.");
    expect(net.calls).toEqual([]);
  });

  it("a retry after a failed make-default reuses the 'Default' set instead of creating a second", async () => {
    const earlier = { id: "n1", name: "Default", revision: 1, usedBy: 0 };
    const h = harness(
      {
        "GET /server-sets": { body: { defaultId: "", sets: [earlier] } },
        "PUT /server-sets/n1": (call) => ({ body: { ...earlier, ...call.body } }),
        "POST /server-sets/n1/default": { status: 204 },
      },
      { DFIR_IRIS_URL: "https://iris.example.com", DFIR_IRIS_KEY: "iris-key-sentinel-alpha" },
    );
    await h.api.wizSaveServerSetStep(h.api.wizardStepById("iris"), h.res, h.btn);
    await flush();
    const order = h.net.calls.map((c) => `${c.method} ${c.url}`);
    expect(order).not.toContain("POST /server-sets");
    expect(order).toContain("PUT /server-sets/n1");
    expect(order.indexOf("POST /server-sets/n1/default")).toBeGreaterThan(
      order.indexOf("PUT /server-sets/n1"),
    );
    expect(h.res.textContent).toContain("Saved to the default server set (Default).");
  });

  it("a 0.45.0 'Testing' set with no default is reused, not joined by a second 'Default'", async () => {
    const earlier = { id: "n1", name: "Testing", revision: 1, usedBy: 0 };
    const h = harness(
      {
        "GET /server-sets": { body: { defaultId: "", sets: [earlier] } },
        "PUT /server-sets/n1": (call) => ({ body: { ...earlier, ...call.body } }),
        "POST /server-sets/n1/default": { status: 204 },
      },
      { DFIR_IRIS_URL: "https://iris.example.com", DFIR_IRIS_KEY: "iris-key-sentinel-alpha" },
    );
    await h.api.wizSaveServerSetStep(h.api.wizardStepById("iris"), h.res, h.btn);
    await flush();
    const order = h.net.calls.map((c) => `${c.method} ${c.url}`);
    expect(order).not.toContain("POST /server-sets");
    expect(order).toContain("PUT /server-sets/n1");
    expect(order.indexOf("POST /server-sets/n1/default")).toBeGreaterThan(
      order.indexOf("PUT /server-sets/n1"),
    );
    expect(h.res.textContent).toContain("Saved to the default server set (Testing).");
  });

  it("a failed make-default after the create says what happened", async () => {
    const h = harness(
      {
        "GET /server-sets": { body: { defaultId: "", sets: [] } },
        "POST /server-sets": (call) => ({ status: 201, body: { id: "n1", revision: 1, ...call.body } }),
        "POST /server-sets/n1/default": { status: 500, body: { error: "disk full" } },
      },
      { DFIR_IRIS_URL: "https://iris.example.com", DFIR_IRIS_KEY: "iris-key-sentinel-alpha" },
    );
    await h.api.wizSaveServerSetStep(h.api.wizardStepById("iris"), h.res, h.btn);
    await flush();
    expect(h.res.textContent).toBe("Created set 'Default' but could not make it the default: disk full");
  });

  it("names the default set on the step line as soon as the step renders", async () => {
    const h = harness({ "GET /server-sets": { body: { defaultId: "t1", sets: [TESTING] } } }, {});
    await h.api.wizBindServerSetStep(h.api.wizardStepById("iris"), h.res, h.btn);
    expect(h.note.textContent).toBe(
      "Saved to the default server set (Testing). Edit sets in Settings → Server sets.",
    );
    expect(h.btn.disabled).toBe(false);
    expect(h.net.calls.some((c) => c.method !== "GET")).toBe(false);
  });

  it("for a member the step says only an administrator can change sets, and Save is disabled", async () => {
    const h = harness(
      { "GET /server-sets": { body: { defaultId: "t1", sets: [{ id: "t1", name: "Testing" }] } } },
      {},
    );
    await h.api.wizBindServerSetStep(h.api.wizardStepById("iris"), h.res, h.btn);
    expect(h.note.textContent).toBe("Only an administrator can change server sets.");
    expect(h.btn.disabled).toBe(true);
  });

  it("wizard IRIS step save → PUT to the default set with the typed values, no .env write for those keys", async () => {
    const h = harness(
      {
        "GET /server-sets": { body: { defaultId: "t1", sets: [TESTING] } },
        "PUT /server-sets/t1": (call) => ({ body: { ...TESTING, ...call.body, id: "t1" } }),
      },
      {
        DFIR_IRIS_URL: "https://iris.example.com",
        DFIR_IRIS_KEY: "",
        DFIR_IRIS_CLASSIFICATION_ID: "4",
        DFIR_IRIS_INSECURE: "true",
        DFIR_TLS_ALLOW_INSECURE_EXTERNAL: "true",
      },
    );
    await h.api.wizSaveServerSetStep(h.api.wizardStepById("iris"), h.res, h.btn);
    await flush();

    const put = h.net.calls.find((c) => c.method === "PUT");
    expect(put?.url).toBe("/server-sets/t1");
    expect(put?.body).toEqual({
      name: "Testing",
      iris: {
        url: "https://iris.example.com",
        apiKey: MASK, // not typed: the stored key stays
        customerId: "1",
        classificationId: "4",
        insecure: true,
      },
      velociraptor: { apiConfigPath: "/srv/velo/api.config.yaml" }, // the other tools are kept
    });
    expect(h.envKeys(), "only the global TLS opt-in still goes to .env").toEqual([
      "DFIR_TLS_ALLOW_INSECURE_EXTERNAL",
    ]);
    expect(h.res.textContent).toContain(
      "Saved to the default server set (Testing). Edit sets in Settings → Server sets.",
    );
    expect(h.btn.disabled).toBe(false);
  });

  it("creates a 'Default' set and makes it the default when there is no default set", async () => {
    const h = harness(
      {
        "GET /server-sets": { body: { defaultId: "", sets: [] } },
        "POST /server-sets": (call) => ({ status: 201, body: { id: "n1", revision: 1, ...call.body } }),
        "POST /server-sets/n1/default": { status: 204 },
      },
      {
        DFIR_TIMESKETCH_URL: "https://ts.example.com",
        DFIR_TIMESKETCH_USER: "analyst",
        DFIR_TIMESKETCH_PASSWORD: "word-like-password",
      },
    );
    await h.api.wizSaveServerSetStep(h.api.wizardStepById("timesketch"), h.res, h.btn);
    await flush();
    const order = h.net.calls.map((c) => `${c.method} ${c.url}`);
    expect(order).toContain("POST /server-sets");
    expect(order.indexOf("POST /server-sets/n1/default")).toBeGreaterThan(order.indexOf("POST /server-sets"));
    const post = h.net.calls.find((c) => c.method === "POST" && c.url === "/server-sets");
    expect(post?.body).toEqual({
      name: "Default",
      timesketch: { url: "https://ts.example.com", user: "analyst", password: "word-like-password" },
    });
    expect(h.envKeys()).toEqual([]);
  });

  it("a saved step is re-read from /setup/status afterwards, so the rail shows it configured", async () => {
    const h = harness(
      {
        "GET /server-sets": { body: { defaultId: "t1", sets: [TESTING] } },
        "PUT /server-sets/t1": { body: TESTING },
        "GET /setup/status": { body: { velociraptor: true } },
      },
      {
        DFIR_VELOCIRAPTOR_API_CONFIG: "/srv/velo/new.config.yaml",
        DFIR_VELOCIRAPTOR_BINARY: "/opt/velociraptor",
      },
    );
    await h.api.wizSaveServerSetStep(h.api.wizardStepById("velociraptor"), h.res, h.btn);
    await flush();
    const order = h.net.calls.map((c) => `${c.method} ${c.url}`);
    expect(order.indexOf("GET /setup/status")).toBeGreaterThan(order.indexOf("PUT /server-sets/t1"));
    expect(h.statusReads()).toBe(1);
    expect(h.envKeys(), "the binary is global and stays in .env").toEqual(["DFIR_VELOCIRAPTOR_BINARY"]);
    const put = h.net.calls.find((c) => c.method === "PUT");
    expect((put?.body?.velociraptor as Record<string, string>).apiConfigPath).toBe(
      "/srv/velo/new.config.yaml",
    );
  });

  it("refuses for a member, who gets set names only, instead of wiping the set", async () => {
    const h = harness(
      { "GET /server-sets": { body: { defaultId: "t1", sets: [{ id: "t1", name: "Testing" }] } } },
      { DFIR_IRIS_URL: "https://iris.example.com" },
    );
    await h.api.wizSaveServerSetStep(h.api.wizardStepById("iris"), h.res, h.btn);
    await flush();
    expect(h.net.calls.some((c) => c.method === "PUT" || c.method === "POST")).toBe(false);
    expect(h.res.textContent).toContain("administrator");
  });
});

describe("the setup wizard's intro", () => {
  it("says the IRIS, Timesketch and Velociraptor steps save to the default server set", () => {
    const html = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain(
      "The DFIR-IRIS, Timesketch and Velociraptor steps save to the default server set. The other steps save to your local <code>.env</code> (gitignored).",
    );
    expect(html).not.toContain("Each step saves to your local <code>.env</code>");
  });
});
