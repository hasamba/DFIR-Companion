import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { FakeDocument, type FakeEl, flush, type Route, routedFetch } from "./serverSetsFakeDom.js";

// Settings → Cloud accounts, per case (#2308): the list is the open case's accounts, the
// instance-wide list shows only for an administrator, and the panel hides itself on the demo.

interface CloudApi {
  initCloudAccounts(): void;
  loadCloudAccounts(): Promise<void>;
}

const ACCOUNT = {
  id: "a1",
  name: "AWS prod",
  provider: "aws",
  settings: { authMode: "access-key" },
  storedSecrets: ["secretAccessKey"],
  caseIds: ["c1"],
  otherCases: 1,
};

function load(routes: Record<string, Route>, caseId = "c1") {
  const doc = new FakeDocument();
  doc.add("div", "cloudAccountsPanel", "cloudAccountsHead", "cloudAccountsList", "cloudAccountsAll");
  doc.add("div", "cloudAccountsAllList");
  doc.add("p", "cloudVaultKeyLine", "caStoredSecrets");
  doc.add("span", "cloudAccountsMsg");
  doc.add("button", "cloudAccountAddBtn", "cloudVaultResetBtn", "caCancel");
  doc.add("form", "cloudAccountForm");
  doc.add("select", "caProvider");
  doc.add("input", "caName", "caMsPfx");
  doc.add("input", "caseId").caseId.value = caseId;
  const net = routedFetch(routes);
  const api = loadDashboardModule<CloudApi>("dashboard-cloud-accounts.js", [], {
    document: doc,
    fetch: net.fetch,
  });
  return { api, net, el: (id: string) => doc.getElementById(id) as FakeEl };
}

describe("cloud accounts panel", () => {
  it("lists the open case's accounts from the case route; a non-admin sees no instance list", async () => {
    const { api, net, el } = load({
      "GET /cases/c1/cloud-accounts": { body: { keyState: "present", accounts: [ACCOUNT] } },
      "GET /cloud-accounts": { status: 403, body: { error: "administrator permission required" } },
    });
    api.initCloudAccounts();
    await flush();
    expect(net.calls.map((c) => c.url)).toContain("/cases/c1/cloud-accounts");
    expect(el("cloudAccountsList").textContent).toContain("AWS prod");
    expect(el("cloudAccountsList").textContent).toContain("1 case you cannot write");
    expect(el("cloudAccountsList").textContent).toContain("Detach");
    expect(el("cloudAccountsAll").hidden).toBe(true);
    expect(el("cloudVaultResetBtn").hidden).toBe(true);
    expect(el("cloudAccountsPanel").hidden).toBe(false);
  });

  it("shows the administrator every account, an unattached one offered for the open case", async () => {
    const old = { ...ACCOUNT, id: "a2", name: "Before cases", caseIds: [] };
    const { api, el } = load({
      "GET /cases/c1/cloud-accounts": { body: { keyState: "present", accounts: [] } },
      "GET /cloud-accounts": { body: { keyState: "present", keyPath: "/k/vault.key", accounts: [old] } },
    });
    api.initCloudAccounts();
    await flush();
    expect(el("cloudAccountsAll").hidden).toBe(false);
    expect(el("cloudAccountsAllList").textContent).toContain("Not attached to a case");
    expect(el("cloudAccountsAllList").textContent).toContain("Attach to this case");
    expect(el("cloudAccountsList").textContent).toContain("No cloud accounts in this case yet.");
  });

  it("hides the whole panel on the public demo", async () => {
    const demo = { status: 403, body: { error: "Demo mode", demo: true } };
    const { api, el } = load({ "GET /cases/c1/cloud-accounts": demo, "GET /cloud-accounts": demo });
    api.initCloudAccounts();
    await flush();
    expect(el("cloudAccountsPanel").hidden).toBe(true);
    expect(el("cloudAccountsHead").hidden).toBe(true);
  });
});
