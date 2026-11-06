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
  doc.add("input", "caName", "caMsPfx", "ccS3Bucket", "ccS3Prefix");
  // #2309: the minimum-policy box in the form, and the Check access panel.
  doc.add("div", "caPolicyBox", "cloudCheckPanel", "ccSources", "ccS3Fields", "ccResult");
  doc.add("strong", "caPolicyTitle", "ccTitle");
  doc.add("pre", "caPolicyGrant");
  doc.add("ul", "caPolicyNotes");
  doc.add("button", "ccRun", "ccClose");
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
    const old = { ...ACCOUNT, id: "a2", name: "Before cases", caseIds: [], otherCases: 0 };
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

// #2309: the add form shows the provider's minimum policy, and Check access reports per source.
const POLICIES = {
  aws: {
    provider: "aws",
    title: "AWS: IAM policy",
    grant: '{"Action":["cloudtrail:LookupEvents"]}',
    notes: ["Keep KMS only when encrypted."],
  },
  gcp: { provider: "gcp", title: "GCP: IAM roles", grant: "roles/logging.viewer", notes: [] },
};

function buttonIn(root: FakeEl, label: string): FakeEl {
  const found = root.descendants().find((d) => d.tagName === "BUTTON" && d.textContent === label);
  if (!found) throw new Error(`no ${label} button`);
  return found;
}

describe("minimum policy and Check access", () => {
  it("shows the picked provider's minimum policy in the form", async () => {
    const { api, el } = load({
      "GET /cases/c1/cloud-accounts": {
        body: { keyState: "present", accounts: [], minimumPolicies: POLICIES },
      },
      "GET /cloud-accounts": { status: 403, body: {} },
    });
    api.initCloudAccounts();
    await flush();
    el("caProvider").fire("change", { target: Object.assign(el("caProvider"), { value: "gcp" }) });
    expect(el("caPolicyTitle").textContent).toBe("GCP: IAM roles");
    expect(el("caPolicyGrant").textContent).toBe("roles/logging.viewer");
    el("caProvider").fire("change", { target: Object.assign(el("caProvider"), { value: "aws" }) });
    expect(el("caPolicyGrant").textContent).toContain("cloudtrail:LookupEvents");
    expect(el("caPolicyNotes").textContent).toContain("Keep KMS only when encrypted.");
    expect(el("caPolicyBox").hidden).toBe(false);
  });

  it("runs the check for the picked sources and shows each result and the summary", async () => {
    const summary =
      "Tested reads succeeded for: CloudTrail event history. Failed: CloudTrail S3 bucket (HTTP 403 AccessDenied " +
      "<b>x</b>). The companion did not test whether this identity can also write. Use the minimum policy.";
    const report = {
      provider: "aws",
      signedInAs: "arn:aws:iam::123456789012:user/collector",
      results: [
        { id: "cloudtrail-lookup", label: "CloudTrail event history", status: "succeeded" },
        {
          id: "s3-trail",
          label: "CloudTrail S3 bucket",
          status: "failed",
          detail: "HTTP 403 AccessDenied <b>x</b>",
        },
      ],
      summary,
    };
    const { api, net, el } = load({
      "GET /cases/c1/cloud-accounts": { body: { keyState: "present", accounts: [ACCOUNT] } },
      "GET /cloud-accounts": { status: 403, body: {} },
      "POST /cases/c1/cloud-accounts/a1/check": { body: { report } },
    });
    api.initCloudAccounts();
    await flush();
    buttonIn(el("cloudAccountsList"), "Check access").click();
    expect(el("cloudCheckPanel").hidden).toBe(false);
    expect(el("ccS3Fields").hidden).toBe(false);
    expect(el("ccSources").textContent).toContain("CloudTrail S3 bucket");
    el("ccS3Bucket").value = "trail-bucket";
    el("ccRun").click();
    await flush();
    const call = net.calls.find((c) => c.method === "POST");
    expect(call?.body).toEqual({
      // #2363: the region list is tested too; #2361: and one GuardDuty read
      sources: ["cloudtrail-lookup", "s3-trail", "ec2-regions", "guardduty"],
      s3Bucket: "trail-bucket",
    });
    expect(el("ccSources").textContent).toContain("Enabled regions (ec2:DescribeRegions)");
    expect(el("ccResult").textContent).toContain("Signed in as arn:aws:iam::123456789012:user/collector");
    expect(el("ccResult").textContent).toContain(
      "Failed: CloudTrail S3 bucket — HTTP 403 AccessDenied <b>x</b>",
    );
    expect(el("ccResult").textContent).toContain(summary);
    expect(el("ccResult").htmlWrites).toEqual([]);
  });

  it("sends only the sources left ticked, and refuses none", async () => {
    const { api, net, el } = load({
      "GET /cases/c1/cloud-accounts": { body: { keyState: "present", accounts: [ACCOUNT] } },
      "GET /cloud-accounts": { status: 403, body: {} },
    });
    api.initCloudAccounts();
    await flush();
    buttonIn(el("cloudAccountsList"), "Check access").click();
    const boxes = el("ccSources")
      .descendants()
      .filter((d) => d.tagName === "INPUT");
    for (const b of boxes) b.checked = false;
    el("ccRun").click();
    await flush();
    expect(net.calls.some((c) => c.method === "POST")).toBe(false);
    expect(el("ccResult").textContent).toBe("Pick at least one source to check.");
    el("ccClose").click();
    expect(el("cloudCheckPanel").hidden).toBe(true);
  });
});
