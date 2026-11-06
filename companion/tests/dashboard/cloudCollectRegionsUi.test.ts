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

// #2363: the Cloud Collection panel's region picker for an AWS account — the regions enabled on the
// account, all ticked; unticked ones sent as excludeRegions and named in the pre-check; the fallback
// note in the picker, the pre-check and the result; stale answers dropped; edits clear the pre-check.

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
const GCP = {
  provider: "gcp",
  label: "GCP",
  available: true,
  sources: [{ id: "gcp-audit", label: "Audit logs" }],
};
const ACCOUNTS = [
  { id: "a1", name: "AWS prod", provider: "aws" },
  { id: "a2", name: "AWS dev", provider: "aws" },
  { id: "g1", name: "GCP lab", provider: "gcp" },
];
const LISTING = {
  regions: ["eu-west-1", "af-south-1", "us-east-1"],
  home: "eu-west-1",
  source: "ec2:DescribeRegions",
};
const FALLBACK = {
  regions: ["eu-west-1", "us-east-1"],
  home: "eu-west-1",
  source: "fallback",
  reason: "UnauthorizedOperation (HTTP 403)",
  note: "The regions enabled on this account could not be listed (UnauthorizedOperation (HTTP 403)) — grant ec2:DescribeRegions.",
};

type RouteFn = (call: FetchCall) => Route | Promise<Route>;

function load(routes: Record<string, Route | RouteFn>) {
  const doc = new FakeDocument();
  doc.add("div", "cloudCollect");
  doc.add("section", "sec-cloud-collect");
  doc.add("button", "cloudCollectBtn");
  doc.add("input", "caseId").caseId.value = "c1";
  const net = routedFetch({
    "GET /cases/c1/cloud-collect": { body: { providers: [AWS, GCP], collections: [] } },
    "GET /cases/c1/cloud-accounts": { body: { accounts: ACCOUNTS } },
    "POST /cases/c1/cloud-collect/precheck": { body: { sources: [], quota: null } },
    "POST /cases/c1/cloud-collect": { status: 202, body: { collectionId: "cc-x", jobId: "j1" } },
    ...routes,
  });
  const api = loadDashboardModule<CollectApi>("dashboard-cloud-collect.js", [], {
    document: doc,
    fetch: net.fetch,
  });
  const box = () => doc.getElementById("cloudCollect") as FakeEl;
  const q = (sel: string) => box().querySelector(sel) as FakeEl;
  const qa = (sel: string) => box().querySelectorAll(sel);
  return { api, net, doc, box, q, qa };
}

const regionsRoute = (answer: Route): Record<string, RouteFn> => ({
  "POST /cases/c1/cloud-collect/regions": () => answer,
});

async function submit(q: (sel: string) => FakeEl) {
  q(".cc-form").fire("submit");
  await flush();
}

describe("the AWS region picker (#2363)", () => {
  it("lists the account's regions, all ticked, the account region marked", async () => {
    const { api, net, q, qa } = load(regionsRoute({ body: LISTING }));
    await api.loadCloudCollect("c1");
    await flush();
    const call = net.calls.find((c) => c.url === "/cases/c1/cloud-collect/regions");
    expect(call?.body).toEqual({ accountId: "a1" });
    const boxes = qa(".cc-region");
    expect(boxes.map((b) => b.value)).toEqual(["eu-west-1", "af-south-1", "us-east-1"]);
    expect(boxes.every((b) => b.checked)).toBe(true);
    expect(q(".cc-regions").textContent).toContain("eu-west-1 (account region)");
    expect(q(".cc-regions").textContent).toContain("af-south-1");
  });

  it("a GCP account has no picker and asks for no regions", async () => {
    const { api, net, q, qa } = load(regionsRoute({ body: LISTING }));
    await api.loadCloudCollect("c1");
    await flush();
    const select = q("#cloudCollectAccount");
    select.value = "g1";
    select.fire("change");
    await flush();
    expect(qa(".cc-region")).toHaveLength(0);
    expect(net.calls.filter((c) => c.url.endsWith("/regions"))).toHaveLength(1); // only a1's
  });

  it("sends the ticked and the unticked regions, and the pre-check names what is skipped by choice", async () => {
    const { api, net, q, qa, box } = load(regionsRoute({ body: LISTING }));
    await api.loadCloudCollect("c1");
    await flush();
    qa(".cc-region").find((b) => b.value === "us-east-1")!.checked = false;
    await submit(q);
    const pre = net.calls.find((c) => c.url.endsWith("/precheck"));
    expect(pre?.body).toMatchObject({ regions: ["eu-west-1", "af-south-1"], excludeRegions: ["us-east-1"] });
    expect(q(".cc-precheck").textContent).toContain("Regions: 2 of 3 ticked — skipped by choice: us-east-1");
    const confirm = q(".cc-precheck")
      .querySelectorAll("button")
      .find((b) => b.textContent === "Confirm and start")!;
    confirm.click();
    await flush();
    const start = net.calls.find((c) => c.method === "POST" && c.url === "/cases/c1/cloud-collect");
    expect(start?.body).toMatchObject({
      regions: ["eu-west-1", "af-south-1"],
      excludeRegions: ["us-east-1"],
    });
    expect(box().htmlWrites).toEqual([]);
  });

  it("refuses to start with no region ticked", async () => {
    const { api, net, q } = load(regionsRoute({ body: LISTING }));
    await api.loadCloudCollect("c1");
    await flush();
    q(".cc-regions")
      .querySelectorAll("button")
      .find((b) => b.textContent === "Untick all")!
      .click();
    await submit(q);
    expect(net.calls.some((c) => c.url.endsWith("/precheck"))).toBe(false);
    expect(q("#cloudCollectMsg").textContent).toBe("Tick at least one region.");
  });

  it("shows the fallback disclosure in the picker and in the pre-check", async () => {
    const { api, q } = load(regionsRoute({ body: FALLBACK }));
    await api.loadCloudCollect("c1");
    await flush();
    expect(q(".cc-regions").textContent).toContain("could not be listed (UnauthorizedOperation (HTTP 403))");
    await submit(q);
    expect(q(".cc-precheck").textContent).toContain("could not be listed (UnauthorizedOperation (HTTP 403))");
  });

  it("when the list cannot be loaded, says so and starts without a choice", async () => {
    const { api, net, q } = load(
      regionsRoute({ status: 502, body: { error: "The regions could not be listed." } }),
    );
    await api.loadCloudCollect("c1");
    await flush();
    expect(q(".cc-regions").textContent).toContain("Regions could not be listed");
    await submit(q);
    expect(q(".cc-precheck").textContent).toContain("the result says which list was used");
    const pre = net.calls.find((c) => c.url.endsWith("/precheck"));
    expect(pre?.body).not.toHaveProperty("regions");
    expect(pre?.body).not.toHaveProperty("excludeRegions");
  });

  it("drops an answer for an account the analyst has already left", async () => {
    let releaseA1: (r: Route) => void = () => {};
    const { api, q, qa } = load({
      "POST /cases/c1/cloud-collect/regions": (call) =>
        call.body?.accountId === "a1"
          ? new Promise<Route>((resolve) => (releaseA1 = resolve))
          : { body: { regions: ["us-west-2"], home: "us-west-2", source: "ec2:DescribeRegions" } },
    });
    await api.loadCloudCollect("c1");
    await flush();
    const select = q("#cloudCollectAccount");
    select.value = "a2";
    select.fire("change");
    await flush();
    releaseA1({ body: LISTING });
    await flush();
    expect(qa(".cc-region").map((b) => b.value)).toEqual(["us-west-2"]);
  });

  it("any edit after the pre-check clears it, so Confirm cannot start the old choice", async () => {
    const { api, q, qa } = load(regionsRoute({ body: LISTING }));
    await api.loadCloudCollect("c1");
    await flush();
    await submit(q);
    expect(q(".cc-precheck").textContent).toContain("Confirm and start");
    qa(".cc-region")[1].checked = false;
    q(".cc-form").fire("change"); // the checkbox's change, bubbled to the form
    expect(q(".cc-precheck").textContent).toBe("");
  });

  it("an edit made while the pre-check is pending drops its answer: no Confirm for the old choice", async () => {
    let release: (r: Route) => void = () => {};
    const { api, net, q, qa } = load({
      ...regionsRoute({ body: LISTING }),
      "POST /cases/c1/cloud-collect/precheck": () => new Promise<Route>((resolve) => (release = resolve)),
    });
    await api.loadCloudCollect("c1");
    await flush();
    q(".cc-form").fire("submit");
    await flush();
    qa(".cc-region")[2].checked = false;
    q(".cc-form").fire("change");
    release({ body: { sources: [], quota: null } });
    await flush();
    expect(q(".cc-precheck").textContent).toBe("");
    expect(q("#cloudCollectMsg").textContent).toMatch(/form changed while it was checked/);
    expect(net.calls.some((c) => c.method === "POST" && c.url === "/cases/c1/cloud-collect")).toBe(false);
  });

  it("a collection's row shows the recorded region scope, skipped regions and the fallback", async () => {
    const collection = {
      checkpoint: {
        collectionId: "cc-1",
        provider: "aws",
        accountId: "a1",
        status: "complete",
        window: { start: "s", end: "e" },
        subWindows: [],
        imported: [],
      },
      header: {
        accountName: "AWS prod",
        filters: {
          regions: "eu-west-1,us-east-1",
          regionsSkippedByChoice: "af-south-1",
          regionList: "fallback",
          regionListReason: "UnauthorizedOperation (HTTP 403)",
        },
      },
      pages: 0,
      bytes: 0,
    };
    const { api, q } = load({
      ...regionsRoute({ body: LISTING }),
      "GET /cases/c1/cloud-collect": { body: { providers: [AWS], collections: [collection] } },
    });
    await api.loadCloudCollect("c1");
    await flush();
    const row = q(".cc-row").textContent;
    expect(row).toContain("Regions collected: eu-west-1, us-east-1");
    expect(row).toContain("Regions skipped by choice (unticked): af-south-1");
    expect(row).toContain("could not be listed (UnauthorizedOperation (HTTP 403))");
  });
});
