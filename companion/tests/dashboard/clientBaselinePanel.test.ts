import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { FakeDocument, type FakeEl, flush, type Route, routedFetch } from "./serverSetsFakeDom.js";

// The Client Baseline panel's layout (#2736): standard small buttons, labels above their boxes, and
// a titled Download policy block whose blocked categories are tick boxes built from the bundled
// download-categories list. Saving must send exactly the body the server stored before.

interface PanelApi {
  loadClientBaseline(caseId: string): Promise<void>;
}

const BUNDLED = JSON.parse(
  readFileSync(new URL("../../data/hunt/download-categories.json", import.meta.url), "utf8"),
) as { categories: Record<string, string[]> };

const CASE = "HUNT-1";
const PID = "client-a-1";
const BASELINE = {
  blockedCategories: ["torrent", "legacy-category"],
  blockedDomains: ["files.example"],
  approvedDomains: ["downloads.example", "updates.example"],
};

function harness(profile: Route = { body: { id: PID, name: "Client A", baseline: BASELINE } }) {
  const doc = new FakeDocument();
  doc.add("div", "clientBaselinePanel");
  const net = routedFetch({
    [`GET /cases/${CASE}/hunt/status`]: { body: { hunt: { id: CASE } } },
    [`GET /cases/${CASE}/hunt/client`]: {
      body: { client: { id: PID, name: "Client A" }, currentVersion: 3, pinnedVersion: null, pending: 1 },
    },
    "GET /client-profiles": { body: [{ id: PID, name: "Client A" }] },
    [`GET /cases/${CASE}/hunt/candidates`]: {
      body: {
        candidates: [
          {
            program: "tool.exe",
            pathPattern: "",
            hostCount: 1,
            hosts: ["H1"],
            evidence: ["prefetch"],
            publishers: [],
            reason: "rare",
            family: "program",
          },
          {
            program: "updater.exe",
            pathPattern: "\\program files\\vendor",
            hostCount: 2,
            hosts: ["H1", "H2"],
            evidence: ["presence"],
            publishers: [],
            sha256: [],
            sha1: ["a".repeat(40)],
            signers: ["Vendor Inc"],
            approvableSigner: "Vendor Inc",
            reason: "not in the reviewed baseline",
            family: "program",
          },
        ],
      },
    },
    [`GET /client-profiles/${PID}`]: profile,
    [`PUT /client-profiles/${PID}/domains`]: { body: { version: 4 } },
    [`POST /client-profiles/${PID}/marks`]: { body: { version: 5 } },
  });
  const api = loadDashboardModule<PanelApi>("dashboard-client-baseline.js", [], {
    document: doc,
    fetch: net.fetch,
    prompt: () => "client email 2026-11-20",
  });
  const panel = () => doc.getElementById("clientBaselinePanel") as FakeEl;
  const render = async () => {
    await api.loadClientBaseline(CASE);
    await flush();
  };
  return { doc, net, panel, render };
}

const buttons = (root: FakeEl) => root.querySelectorAll("button");
const byText = (root: FakeEl, tag: string, text: string) =>
  root.querySelectorAll(tag).find((n) => n.textContent === text) as FakeEl;
const categoryBoxes = (root: FakeEl) => (root.querySelector(".cb-cats") as FakeEl).querySelectorAll("input");

describe("Client Baseline panel layout (#2736)", () => {
  it("uses the dashboard's standard small button class for every button", async () => {
    const h = harness();
    await h.render();
    const all = buttons(h.panel());
    expect(all.map((b) => b.textContent)).toEqual(
      expect.arrayContaining([
        "Link case to client",
        "New client…",
        "Mark Approved",
        "Mark Not allowed",
        "Reset to Unknown",
        "Import the client's filled CSV…",
        "Save download policy",
      ]),
    );
    for (const b of all) expect(b.className).toBe("ev-bulk-btn");
  });

  it("styles the client select and puts its label above it", async () => {
    const h = harness();
    await h.render();
    const select = h.panel().querySelector("select") as FakeEl;
    expect(select.className).toBe("toolbar-select");
    const field = select.closest(".sfield") as FakeEl;
    const label = field.children[0];
    expect(label.tagName).toBe("LABEL");
    expect(label.textContent).toBe("Client");
  });

  it("builds a tick box for every bundled category, with a plain label, ticking the stored ones", async () => {
    const h = harness();
    await h.render();
    const boxes = categoryBoxes(h.panel());
    const bundled = Object.keys(BUNDLED.categories);
    expect(boxes.slice(0, bundled.length).map((b) => b.value)).toEqual(bundled);
    const labels = boxes.map((b) => (b.parent as FakeEl).textContent);
    expect(labels.slice(0, bundled.length)).toEqual([
      "Torrent",
      "File sharing",
      "Cloud storage",
      "Paste sites",
      "Remote access",
    ]);
    expect(boxes.filter((b) => b.checked).map((b) => b.value)).toEqual(["torrent", "legacy-category"]);
  });

  it("keeps a stored category the bundled list does not know as its own ticked box", async () => {
    const h = harness();
    await h.render();
    const extra = categoryBoxes(h.panel()).find((b) => b.value === "legacy-category") as FakeEl;
    expect(extra.checked).toBe(true);
    expect((extra.parent as FakeEl).textContent).toBe("legacy-category");
  });

  it("titles the block, explains it in plain words, and labels the domain boxes with the hint", async () => {
    const h = harness();
    await h.render();
    const policy = h.panel().querySelector(".cb-policy") as FakeEl;
    expect((policy.querySelector("h3") as FakeEl).textContent).toBe("Download policy");
    const note = (policy.querySelector(".cb-policy-note") as FakeEl).textContent;
    expect(note).toMatch(/blocked category or a blocked site are graded as policy violations/);
    expect(note).toMatch(/runnable or archive files .* other than an approved source/);
    for (const [id, label] of [
      ["cbBlockedSites", "Blocked sites"],
      ["cbApprovedSources", "Approved download sources"],
    ]) {
      const area = h.doc.getElementById(id) as FakeEl & { placeholder: string };
      const field = area.parent as FakeEl;
      expect(field.className).toBe("sfield");
      expect(field.children[0].textContent).toBe(label);
      expect(field.children[0].tagName).toBe("LABEL");
      expect((field.querySelector(".sfield-hint") as FakeEl).textContent).toBe(
        "One domain per line; subdomains are included.",
      );
      expect(area.placeholder).toMatch(/\.example/);
    }
  });

  it("saves the same body as before: category ids, domain lists and the audit source", async () => {
    const h = harness();
    await h.render();
    const p = h.panel();
    const cloud = categoryBoxes(p).find((b) => b.value === "cloud-storage") as FakeEl;
    cloud.checked = true;
    (h.doc.getElementById("cbBlockedSites") as FakeEl).value = "files.example\n share.example \n";
    byText(p, "button", "Save download policy").click();
    await flush();
    const put = h.net.calls.find((c) => c.method === "PUT");
    expect(put?.url).toBe(`/client-profiles/${PID}/domains`);
    expect(put?.body).toEqual({
      blockedCategories: ["torrent", "cloud-storage", "legacy-category"],
      blockedDomains: ["files.example", "share.example"],
      approvedDomains: ["downloads.example", "updates.example"],
      source: "client email 2026-11-20",
    });
    expect(p.textContent).toContain("Saved as baseline version 4.");
  });

  it("keeps the administrator-only message for a viewer who cannot read the profile", async () => {
    const h = harness({ status: 403, body: { error: "forbidden" } });
    await h.render();
    expect(h.panel().querySelector(".cb-policy")).toBeNull();
    expect(h.panel().textContent).toContain(
      "Blocked download categories and sites: editable by the instance administrator.",
    );
  });

  it("Mark Approved saves the SHA1, the SHA-256 and the verified signer, so the approval can match (#2731)", async () => {
    const h = harness();
    await h.render();
    const p = h.panel();
    const table = p.querySelector(".cb-candidates") as FakeEl;
    const boxes = table.querySelectorAll("input");
    boxes[1].checked = true;
    boxes[1].fire("change");
    byText(p, "button", "Mark Approved").click();
    await flush();
    const post = h.net.calls.find((c) => c.method === "POST");
    expect(post?.url).toBe(`/client-profiles/${PID}/marks`);
    expect(post?.body).toEqual({
      marks: [
        {
          verdict: "approved",
          family: "program",
          program: "updater.exe",
          pathPattern: "\\program files\\vendor",
          sha256: [],
          sha1: ["a".repeat(40)],
          signer: "Vendor Inc",
        },
      ],
      source: "client email 2026-11-20",
    });
  });

  it("writes nothing through innerHTML", async () => {
    const h = harness();
    await h.render();
    expect(h.doc.htmlWrites()).toEqual([]);
  });
});
