import { beforeEach, describe, expect, it } from "vitest";
import type { VeloCollectApi, VeloTriageApi } from "./dashboardApi.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-velo-collect.js — the Fleet Collection panel's run list.
//
// SETTINGS IS GLOBAL; RUNNING A BUNDLE IS NOT. Every Settings tab configures the application — except
// the Velociraptor tab, where "▶ Run" launched a hunt into the connected case from between Edit and
// Delete. The run list now lives on the dashboard, next to the hunts it feeds, and the Settings tab
// keeps only the shared bundle library. These tests pin both halves: the panel offers Run (or says
// why it cannot), and the library never does.

const picker = { value: "  remembered-case  " };
const runList = { innerHTML: "", querySelectorAll: () => [] as unknown[] };
const bundleList = { innerHTML: "", querySelectorAll: () => [] as unknown[] };
const BUNDLES = [
  { id: "best-practice", name: "Best Practice", artifacts: ["Windows.System.Pslist"], builtIn: true },
  { id: "custom-1", name: "Custom", artifacts: ["Linux.Sys.Pslist"], description: "mine" },
];

const document = {
  getElementById: (id: string) =>
    id === "veloRunList" ? runList : id === "veloBundleList" ? bundleList : id === "caseId" ? picker : null,
  querySelectorAll: () => [] as unknown[],
};

const collect = loadDashboardModule<VeloCollectApi>(
  "dashboard-velo-collect.js",
  ["dashboard-escape.js", "dashboard-velo-case.js"],
  { document, activeCaseId: null, veloEnabled: true },
);

// The triage module loads the bundles and fans out to BOTH lists; the collect module must be on the
// page for the run list to render at all.
const triage = loadDashboardModule<VeloTriageApi>(
  "dashboard-velo-triage.js",
  ["dashboard-escape.js", "dashboard-velo-case.js", "dashboard-velo-collect.js"],
  {
    document,
    fetch: async () => ({ ok: true, json: async () => BUNDLES }),
    activeCaseId: null,
    veloEnabled: true,
  },
);

beforeEach(() => {
  collect.activeCaseId = null;
  collect.veloEnabled = true;
  triage.activeCaseId = null;
  triage.veloEnabled = true;
  runList.innerHTML = "";
  bundleList.innerHTML = "";
});

describe("renderVeloRunList", () => {
  it("is disabled, and says why, with no case connected", () => {
    collect.renderVeloRunList(BUNDLES);
    expect(runList.innerHTML).toContain("Connect to a case first");
    expect(runList.innerHTML).not.toContain("velo-run-btn");
  });

  it("is live once a case is connected", () => {
    collect.activeCaseId = "c1";
    collect.renderVeloRunList(BUNDLES);
    expect(runList.innerHTML).toContain("velo-run-btn");
    expect(runList.innerHTML).not.toContain("Connect to a case first");
  });

  it("still names the unconfigured server when there is one", () => {
    collect.veloEnabled = false;
    collect.activeCaseId = "c1";
    collect.renderVeloRunList(BUNDLES);
    expect(runList.innerHTML).toContain("Velociraptor API not configured");
  });

  it("names every bundle and where to edit it, never the editing controls themselves", () => {
    collect.activeCaseId = "c1";
    collect.renderVeloRunList(BUNDLES);
    expect(runList.innerHTML).toContain("Best Practice");
    expect(runList.innerHTML).toContain("Custom");
    expect(runList.innerHTML).toContain("velo-run-form");
    for (const cls of ["velo-edit-btn", "velo-dup-btn", "velo-del-btn", "velo-reset-btn"]) {
      expect(runList.innerHTML, cls).not.toContain(cls);
    }
  });

  it("folds each bundle's artifact list into a collapsed toggle", () => {
    collect.activeCaseId = "c1";
    collect.renderVeloRunList(BUNDLES);
    const html = runList.innerHTML;
    // One <details> per bundle, never pre-opened, with the count as its summary and the names inside.
    expect(html.match(/<details class="velo-artifacts"/g)?.length).toBe(BUNDLES.length);
    expect(html).not.toMatch(/<details class="velo-artifacts"[^>]*\sopen/);
    expect(html).toMatch(/<summary[^>]*>1 artifact\(s\)<\/summary>/);
    const inner = html.slice(html.indexOf("<details"), html.indexOf("</details>"));
    expect(inner).toContain("Windows.System.Pslist");
  });

  it("points at the Settings library when there is nothing to run", () => {
    collect.renderVeloRunList([]);
    expect(runList.innerHTML).toContain("No bundles yet");
    expect(runList.innerHTML).toContain("velo-open-library");
  });

  it("survives a page without the panel", () => {
    const bare = loadDashboardModule<VeloCollectApi>(
      "dashboard-velo-collect.js",
      ["dashboard-escape.js", "dashboard-velo-case.js"],
      { document: { getElementById: () => null }, activeCaseId: "c1", veloEnabled: true },
    );
    expect(() => bare.renderVeloRunList(BUNDLES)).not.toThrow();
  });
});

// #1969 — the run form starts at the case scope window when one is set, so a collect is bounded to
// the incident window at the source and the row cap is spent there.
describe("veloPrefillTimeScope", () => {
  function fakeForm() {
    const el = (value = "") => ({ value, style: { display: "none" } });
    const parts: Record<string, ReturnType<typeof el>> = {
      ".velo-timescope": el(),
      ".velo-ts-start": el(),
      ".velo-ts-end": el(),
      ".velo-ts-custom": el(),
    };
    return { parts, querySelector: (sel: string) => parts[sel] ?? null };
  }

  it("selects a custom range and fills the case scope window, in UTC", () => {
    const form = fakeForm();
    const done = collect.veloPrefillTimeScope(form, {
      start: "2026-09-20T00:00:00.000Z",
      end: "2026-09-21T12:30:00.000Z",
    });
    expect(done).toBe(true);
    expect(form.parts[".velo-timescope"].value).toBe("custom");
    expect(form.parts[".velo-ts-start"].value).toBe("2026-09-20T00:00");
    expect(form.parts[".velo-ts-end"].value).toBe("2026-09-21T12:30");
    expect(form.parts[".velo-ts-custom"].style.display).toBe("inline-flex");
  });

  it("leaves the form at All time with no case scope start", () => {
    for (const scope of [null, { start: null, end: null }, { start: null, end: "2026-09-21T00:00:00Z" }]) {
      const form = fakeForm();
      expect(collect.veloPrefillTimeScope(form, scope)).toBe(false);
      expect(form.parts[".velo-timescope"].value).toBe("");
    }
  });

  it("ignores a bound that is not a date", () => {
    const form = fakeForm();
    expect(collect.veloPrefillTimeScope(form, { start: "nonsense", end: null })).toBe(false);
    expect(form.parts[".velo-ts-start"].value).toBe("");
  });
});

describe("the bundle load fans out", () => {
  it("renders the run list on the dashboard and the library in Settings from one fetch", async () => {
    triage.activeCaseId = "c1";
    await triage.loadVeloBundles();
    expect(runList.innerHTML).toContain("velo-run-btn");
    expect(bundleList.innerHTML).toContain("velo-edit-btn");
  });

  it("never puts a Run button in the Settings library, however live the case is", async () => {
    triage.activeCaseId = "c1";
    await triage.loadVeloBundles();
    expect(bundleList.innerHTML).not.toContain("velo-run-btn");
    expect(bundleList.innerHTML).not.toContain("velo-run-form");
    expect(bundleList.innerHTML).not.toContain("Connect to a case first");
  });
});

// #2970 — opening a run form refreshes the client list, so the label pickers offer what the fleet
// carries NOW rather than what it carried at the last manual Settings refresh.
describe("veloRefreshRunFormLabels (#2970)", () => {
  type Reply = { ok: boolean; status?: number; body: unknown } | Error;
  function harness(reply: Reply, enabled = true) {
    const calls: { url: string; body: unknown }[] = [];
    const accepted: unknown[] = [];
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const mod = loadDashboardModule<VeloCollectApi>(
      "dashboard-velo-collect.js",
      [
        "dashboard-escape.js",
        "dashboard-velo-case.js",
        "dashboard-velo-clients.js",
        "dashboard-velo-labels.js",
      ],
      {
        document,
        activeCaseId: "case-a",
        veloEnabled: enabled,
        acceptVeloClientInventory: (inv: unknown) => accepted.push(inv),
        fetch: async (url: string, init: { body: string }) => {
          calls.push({ url, body: JSON.parse(init.body) as unknown });
          await gate;
          if (reply instanceof Error) throw reply;
          return {
            ok: reply.ok,
            status: reply.status ?? (reply.ok ? 200 : 502),
            json: async () => reply.body,
          };
        },
      },
    );
    const wrap = { innerHTML: "" };
    const note = { textContent: "", title: "" };
    const form = {
      isConnected: true,
      style: { display: "block" },
      dataset: {} as Record<string, string>,
      querySelector: (sel: string) =>
        sel === ".velo-lbl-wrap" ? wrap : sel === ".velo-lbl-note" ? note : null,
    };
    return { mod, calls, accepted, release, form, wrap, note };
  }
  const INV = {
    updatedAt: new Date(2026, 10, 27, 9, 5).toISOString(),
    clients: [{ clientId: "C.1", hostname: "WS-EXAMPLE-01", labels: ["lab-b"] }],
  };

  it("refreshes the open case's client list and re-renders the pickers from it", async () => {
    const h = harness({ ok: true, body: INV });
    const done = h.mod.veloRefreshRunFormLabels(h.form);
    expect(h.note.textContent).toBe("refreshing labels…");
    h.release();
    await done;
    // The case's own refresh (case write), not Settings' administrator-only global one.
    expect(h.calls).toEqual([{ url: "/cases/case-a/ai-agent/endpoints/refresh", body: {} }]);
    expect(h.wrap.innerHTML).toContain('value="lab-b"');
    expect(h.note.textContent).toBe("labels as of 09:05");
    expect(h.accepted).toHaveLength(1); // the shared cache (Settings count, monitor picker) moves too
  });

  it("keeps the cached list and says why when the refresh fails", async () => {
    const h = harness({ ok: false, status: 502, body: { error: "connection refused" } });
    h.wrap.innerHTML = "CACHED";
    const done = h.mod.veloRefreshRunFormLabels(h.form);
    h.release();
    await done;
    expect(h.wrap.innerHTML).toBe("CACHED");
    expect(h.accepted).toHaveLength(0);
    expect(h.note.textContent).toBe("labels may be out of date — refresh failed (connection refused)");
  });

  it("survives a network error the same way", async () => {
    const h = harness(new Error("Failed to fetch"));
    h.wrap.innerHTML = "CACHED";
    const done = h.mod.veloRefreshRunFormLabels(h.form);
    h.release();
    await done;
    expect(h.wrap.innerHTML).toBe("CACHED");
    expect(h.note.textContent).toContain("refresh failed (Failed to fetch)");
  });

  it("drops a reply that lands after the form was closed, replaced or reopened", async () => {
    for (const change of [
      (f: { style: { display: string } }) => (f.style.display = "none"),
      (f: { isConnected: boolean }) => (f.isConnected = false),
      (f: { dataset: Record<string, string> }) => (f.dataset.lblSeq = "other"),
    ]) {
      const h = harness({ ok: true, body: INV });
      h.wrap.innerHTML = "CACHED";
      const done = h.mod.veloRefreshRunFormLabels(h.form);
      change(h.form);
      h.release();
      await done;
      expect(h.wrap.innerHTML).toBe("CACHED");
      expect(h.accepted).toHaveLength(0);
    }
  });

  it("drops a reply that lands after the case changed", async () => {
    const h = harness({ ok: true, body: INV });
    h.wrap.innerHTML = "CACHED";
    const done = h.mod.veloRefreshRunFormLabels(h.form);
    h.mod.activeCaseId = "case-b";
    h.release();
    await done;
    expect(h.wrap.innerHTML).toBe("CACHED");
    expect(h.accepted).toHaveLength(0);
  });

  it("asks nothing with no case connected", async () => {
    const h = harness({ ok: true, body: INV });
    h.mod.activeCaseId = null;
    await h.mod.veloRefreshRunFormLabels(h.form);
    expect(h.calls).toHaveLength(0);
  });

  it("asks nothing of a Velociraptor server that is not configured", async () => {
    const h = harness({ ok: true, body: INV }, false);
    await h.mod.veloRefreshRunFormLabels(h.form);
    expect(h.calls).toHaveLength(0);
    expect(h.note.textContent).toBe("");
  });
});
