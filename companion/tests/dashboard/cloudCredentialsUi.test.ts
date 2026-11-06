import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { FakeDocument, type FakeEl, flush, type Route, routedFetch } from "./serverSetsFakeDom.js";

// #2347: the held-credentials list (the extended "All cloud accounts" list) shows each row's cases
// with their status, who added it and when, and when it was last used; rows can be deleted alone or
// together, and every delete confirmation and the close dialog remind the analyst to revoke the key
// in the cloud. Closing a case with accounts asks Delete (default) or Keep first.

interface CloudApi {
  initCloudAccounts(): void;
}
interface CloseApi {
  initCaseClose(): void;
  closeCaseWithCredentials(caseId: string): Promise<boolean>;
}

const HTML = readFileSync(new URL("../../../public/dashboard.html", import.meta.url), "utf8");

const ROW = {
  id: "a1",
  name: "AWS prod",
  provider: "aws",
  settings: { authMode: "assume-role", roleArn: "arn:aws:iam::123456789012:role/r" },
  storedSecrets: ["secretAccessKey"],
  caseIds: ["c1", "c2"],
  cases: [
    { caseId: "c1", status: "open" },
    { caseId: "c2", status: "closed" },
  ],
  otherCases: 0,
  createdAt: "2026-11-01T10:00:00.000Z",
  createdBy: { id: "u1", displayName: "Alice" },
  lastUsedAt: "2026-11-02T11:30:00.000Z",
};

function loadList(routes: Record<string, Route>, confirmAnswer = true) {
  const doc = new FakeDocument();
  doc.add("div", "cloudAccountsPanel", "cloudAccountsHead", "cloudAccountsList", "cloudAccountsAll");
  doc.add("div", "cloudAccountsAllList");
  doc.add("p", "cloudVaultKeyLine", "caStoredSecrets");
  doc.add("span", "cloudAccountsMsg");
  doc.add("button", "cloudAccountAddBtn", "cloudVaultResetBtn", "caCancel", "cloudAccountsDeleteSelected");
  doc.add("form", "cloudAccountForm");
  doc.add("select", "caProvider");
  doc.add("input", "caName", "caMsPfx");
  doc.add("input", "caseId").caseId.value = "c1";
  const confirms: string[] = [];
  const net = routedFetch(routes);
  const api = loadDashboardModule<CloudApi>("dashboard-cloud-accounts.js", [], {
    document: doc,
    fetch: net.fetch,
    confirm: (text: string) => {
      confirms.push(text);
      return confirmAnswer;
    },
  });
  return { api, net, confirms, el: (id: string) => doc.getElementById(id) as FakeEl };
}

const inputs = (root: FakeEl) => root.descendants().filter((d) => d.tagName === "INPUT");
function buttonIn(root: FakeEl, label: string): FakeEl | undefined {
  return root.descendants().find((d) => d.tagName === "BUTTON" && d.textContent === label);
}

describe("held credentials list", () => {
  it("shows cases with status, who added it, when, and last used", async () => {
    const { api, el } = loadList({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [] } },
      "GET /cloud-accounts": { body: { admin: false, keyState: "present", accounts: [ROW] } },
    });
    api.initCloudAccounts();
    await flush();
    const text = el("cloudAccountsAllList").textContent;
    expect(el("cloudAccountsAll").hidden).toBe(false);
    expect(text).toContain("c1 (open)");
    expect(text).toContain("c2 (closed — credentials kept)");
    expect(text).toContain("Added by Alice, 2026-11-01 10:00 UTC");
    expect(text).toContain("Last used: 2026-11-02 11:30 UTC");
    // An analyst gets no administrator actions.
    expect(buttonIn(el("cloudAccountsAllList"), "Edit")).toBeUndefined();
    expect(el("cloudVaultResetBtn").hidden).toBe(true);
  });

  it("says 'not recorded' for an old account, and a shared one an analyst cannot delete has no Delete", async () => {
    const old = { ...ROW, id: "a2", name: "Old", createdBy: undefined, lastUsedAt: undefined, otherCases: 1 };
    const { api, el } = loadList({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [] } },
      "GET /cloud-accounts": { body: { admin: false, accounts: [old] } },
    });
    api.initCloudAccounts();
    await flush();
    const list = el("cloudAccountsAllList");
    expect(list.textContent).toContain("Added by not recorded");
    expect(list.textContent).toContain("Last used: not recorded");
    expect(list.textContent).toContain("1 case you cannot write");
    expect(buttonIn(list, "Delete")).toBeUndefined();
    expect(inputs(list)).toHaveLength(0);
  });

  it("deletes one row with the revoke reminder in the confirmation", async () => {
    const { api, el, net, confirms } = loadList({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [] } },
      "GET /cloud-accounts": { body: { admin: true, accounts: [ROW] } },
      "DELETE /cloud-accounts/a1": { status: 204 },
    });
    api.initCloudAccounts();
    await flush();
    buttonIn(el("cloudAccountsAllList"), "Delete")?.click();
    await flush();
    expect(confirms[0]).toMatch(/revoke the key or app secret in AWS, Azure or GCP/);
    expect(net.calls.some((c) => c.method === "DELETE" && c.url === "/cloud-accounts/a1")).toBe(true);
  });

  it("deletes the ticked rows together, after a confirmation with the reminder", async () => {
    const unattached = { ...ROW, id: "a2", name: "Leftover", caseIds: [], cases: [] };
    const { api, el, net, confirms } = loadList({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [] } },
      "GET /cloud-accounts": { body: { admin: true, accounts: [ROW, unattached] } },
      "POST /cloud-accounts/delete": { body: { deleted: 2 } },
    });
    api.initCloudAccounts();
    await flush();
    const list = el("cloudAccountsAllList");
    expect(list.textContent).toContain("Not attached to a case");
    const btn = el("cloudAccountsDeleteSelected");
    expect(btn.disabled).toBe(true);
    for (const tick of inputs(list)) {
      tick.checked = true;
      tick.fire("change");
    }
    expect(btn.disabled).toBe(false);
    btn.click();
    await flush();
    expect(confirms[0]).toMatch(/Delete 2 cloud accounts/);
    expect(confirms[0]).toMatch(/revoke the key or app secret/);
    const call = net.calls.find((c) => c.url === "/cloud-accounts/delete");
    expect(call?.body).toEqual({ ids: ["a1", "a2"] });
    expect(el("cloudAccountsMsg").textContent).toContain("Deleted 2");
  });

  it("hides the section for an analyst with nothing to see", async () => {
    const { api, el } = loadList({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [] } },
      "GET /cloud-accounts": { body: { admin: false, accounts: [] } },
    });
    api.initCloudAccounts();
    await flush();
    expect(el("cloudAccountsAll").hidden).toBe(true);
  });
});

function loadClose(routes: Record<string, Route>) {
  const doc = new FakeDocument();
  doc.add("div", "closeCaseOverlay");
  doc.add("p", "ccaCaseName");
  doc.add("ul", "ccaList");
  doc.add("input", "ccaDelete", "ccaKeep");
  doc.add("button", "ccaConfirm", "ccaCancel");
  doc.add("span", "ccaMsg");
  const net = routedFetch(routes);
  const api = loadDashboardModule<CloseApi>("dashboard-case-close.js", [], {
    document: doc,
    fetch: net.fetch,
    alert: () => {},
  });
  api.initCaseClose();
  return { api, net, el: (id: string) => doc.getElementById(id) as FakeEl };
}

describe("close case dialog", () => {
  it("closes at once when the case has no cloud accounts", async () => {
    const { api, net, el } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [] } },
      "PATCH /cases/c1/status": { body: { status: "closed" } },
    });
    expect(await api.closeCaseWithCredentials("c1")).toBe(true);
    expect(el("closeCaseOverlay").classList.contains("open")).toBe(false);
    expect(net.calls.find((c) => c.method === "PATCH")?.body).toEqual({ status: "closed" });
  });

  it("lists the accounts, defaults to Delete, and sends Keep when picked", async () => {
    const { api, net, el } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
      "PATCH /cases/c1/status": { body: { status: "closed" } },
    });
    const done = api.closeCaseWithCredentials("c1");
    await flush();
    expect(el("closeCaseOverlay").classList.contains("open")).toBe(true);
    expect(el("ccaList").textContent).toContain("AWS — AWS prod — account 123456789012");
    expect(el("ccaDelete").checked).toBe(true);
    el("ccaDelete").checked = false;
    el("ccaKeep").checked = true;
    el("ccaConfirm").click();
    expect(await done).toBe(true);
    expect(net.calls.find((c) => c.method === "PATCH")?.body).toEqual({
      status: "closed",
      cloudCredentials: "keep",
    });
  });

  it("shows the server's refusal while a collection runs, and Cancel leaves the case open", async () => {
    const { api, net, el } = loadClose({
      "GET /cases/c1/cloud-accounts": { body: { accounts: [ROW] } },
      "PATCH /cases/c1/status": {
        status: 409,
        body: { error: "A cloud collection is running on this case." },
      },
    });
    const done = api.closeCaseWithCredentials("c1");
    await flush();
    el("ccaConfirm").click();
    await flush();
    expect(el("ccaMsg").textContent).toContain("A cloud collection is running");
    expect(net.calls.find((c) => c.method === "PATCH")?.body).toEqual({
      status: "closed",
      cloudCredentials: "delete",
    });
    el("ccaCancel").click();
    expect(await done).toBe(false);
  });
});

describe("revoke-in-the-cloud reminder in the markup", () => {
  const block = (id: string) => {
    const start = HTML.indexOf(`id="${id}"`);
    expect(start, id).toBeGreaterThan(-1);
    return HTML.slice(start, HTML.indexOf("</div>\n  </div>", start));
  };
  it("is in the close dialog and the delete-case dialog", () => {
    for (const id of ["closeCaseOverlay", "deleteCaseOverlay"])
      expect(block(id)).toMatch(/revoke the key or app secret in AWS, Azure or GCP/);
    expect(block("closeCaseOverlay")).toMatch(/id="ccaDelete"[^>]*checked/);
  });
});
