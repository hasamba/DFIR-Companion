// #2937: the status lines and banners #2933 left behind. An answer (or a poll tick) from before a
// cancelled load or a switch must not write over the case on screen; a same-case reload still lets
// it paint. Modules that own no case use DfirPanelDefer.actionLive, which moves only when another
// case opens or a load is cancelled.
import { describe, expect, it } from "vitest";
import { drainAll, fakePage } from "../helpers/caseSwitchPage.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

type Page = ReturnType<typeof fakePage>;
type Api = Record<string, (...args: unknown[]) => unknown> & { activeCaseId?: string | null };
const ESC = [
  "dashboard-escape.js",
  "dashboard-time.js",
  "dashboard-text.js",
  "dashboard-glyphs.js",
  "dashboard-values.js",
];
const last = (p: Page) => p.requests.length - 1;
const onclick = (p: Page, id: string) => (p.el(id) as unknown as { onclick: () => void }).onclick();
const status = (p: Page) => p.el("status").textContent;

/** Cancel, then reopen case A and run its loader. */
function cancelAndReopen(p: Page, api: object, load: () => void) {
  p.cancel(api);
  p.switchCase("CASE-A", api);
  load();
}

describe("import changes (#2937)", () => {
  function importChanges() {
    const p = fakePage();
    const ticks: (() => Promise<void>)[] = [];
    const cleared: number[] = [];
    const api = loadDashboardModule<Api>("dashboard-import-changes.js", ESC, {
      ...p.globals,
      FileReader: class {
        result = "data:x;base64,QUFB";
        onload: () => void = () => {};
        readAsDataURL() {
          this.onload();
        }
      },
      openSettingsTab: () => {},
      renderTimelineEvents: () => {},
      renderIocs: () => {},
      confirm: () => true,
      setInterval: (fn: () => Promise<void>) => ticks.push(fn),
      clearInterval: (id: number) => cleared.push(id),
    });
    // The banner's ticked boxes: one file, one tool.
    const banner = p.el("rawToolBanner") as unknown as { querySelectorAll: () => unknown[] };
    banner.querySelectorAll = () => [{ getAttribute: () => "0", value: "socrates" }];
    return { p, api, ticks, cleared };
  }
  const FILES = [{ name: "a.pcap", size: 10 }];
  const TOOLS = { tools: [{ id: "socrates", label: "SO-CRATES", configured: true, extensions: [".pcap"] }] };
  async function banner(p: Page, api: Api, files = FILES) {
    api.askRunToolsOnImport("CASE-A", files);
    p.requests[last(p)].answer(TOOLS);
    await drainAll();
  }
  /** Raise the banner, press Run selected, and return the run-upload request's index. */
  async function upload(p: Page, api: Api) {
    api.loadImportMeta("CASE-A");
    await banner(p, api);
    onclick(p, "rawRunYes");
    await drainAll();
    return last(p);
  }

  it("SO-CRATES: a tick answering after a cancel writes nothing and ends the poll", async () => {
    const { p, api, ticks, cleared } = importChanges();
    const run = await upload(p, api);
    p.requests[run].answer({ jobIds: ["j1"] });
    await drainAll();
    expect(ticks).toHaveLength(1);
    void ticks[0]();
    const jobs = last(p);
    cancelAndReopen(p, api, () => api.loadImportMeta("CASE-A"));
    p.el("status").textContent = "B-LINE";
    p.requests[jobs].answer({ jobs: [{ jobId: "j1", status: "running" }] });
    await drainAll();
    expect(status(p)).toBe("B-LINE");
    const before = p.requests.length;
    await ticks[0]();
    expect(p.requests.length, "a stale poll kept fetching").toBe(before);
    expect(cleared.length).toBeGreaterThan(0);
  });

  it("SO-CRATES: a same-case reload keeps the poll writing", async () => {
    const { p, api, ticks } = importChanges();
    const run = await upload(p, api);
    p.requests[run].answer({ jobIds: ["j1"] });
    await drainAll();
    api.loadImportMeta("CASE-A");
    void ticks[0]();
    p.requests[last(p)].answer({ jobs: [{ jobId: "j1", status: "running" }] });
    await drainAll();
    expect(status(p)).toContain("SO-CRATES: analyzing");
  });

  it("upload: lines from before a cancel say nothing; a same-case reload still shows them", async () => {
    const { p, api } = importChanges();
    const run = await upload(p, api);
    cancelAndReopen(p, api, () => api.loadImportMeta("CASE-A"));
    p.el("status").textContent = "B-LINE";
    p.requests[run].answer({ addedEvents: 5 });
    await drainAll();
    expect(status(p)).toBe("B-LINE");

    const again = importChanges();
    const run2 = await upload(again.p, again.api);
    again.api.loadImportMeta("CASE-A");
    again.p.requests[run2].answer({ addedEvents: 5 });
    await drainAll();
    expect(status(again.p)).toContain("Ran 1 run(s)");
  });

  it("raw-tool banner: a cancel hides it, and an old tools answer does not raise it again", async () => {
    const { p, api } = importChanges();
    api.loadImportMeta("CASE-A");
    await banner(p, api);
    expect(p.el("rawToolBanner").style.display).toBe("block");
    api.askRunToolsOnImport("CASE-A", FILES);
    const old = last(p);
    p.cancel(api);
    expect(p.el("rawToolBanner").style.display).toBe("none");
    p.switchCase("CASE-A", api);
    api.loadImportMeta("CASE-A");
    p.requests[old].answer(TOOLS);
    await drainAll();
    expect(p.el("rawToolBanner").style.display).toBe("none");
  });

  it("raw-tool banner: an old tools answer does not overwrite a newer banner", async () => {
    const { p, api } = importChanges();
    api.loadImportMeta("CASE-A");
    api.askRunToolsOnImport("CASE-A", [{ name: "OLD.pcap", size: 1 }]);
    const old = last(p);
    cancelAndReopen(p, api, () => api.loadImportMeta("CASE-A"));
    await banner(p, api, [{ name: "NEW.pcap", size: 1 }]);
    p.requests[old].answer(TOOLS);
    await drainAll();
    expect(p.el("rawToolBanner").innerHTML).toContain("NEW.pcap");
    expect(p.el("rawToolBanner").innerHTML).not.toContain("OLD.pcap");
  });

  it("raw-tool banner: the case's first import-meta load keeps a banner raised for it", async () => {
    const { p, api } = importChanges();
    await banner(p, api);
    api.loadImportMeta("CASE-A");
    expect(p.el("rawToolBanner").style.display).toBe("block");
  });

  it("held files: a decision answering after a cancel says nothing; a same-case reload still does", async () => {
    for (const reopen of [true, false]) {
      const { p, api } = importChanges();
      api.loadDropStatus("CASE-A");
      p.requests[last(p)].answer({ files: [{ rel: "drop/_held/x.csv", size: 1 }] });
      await drainAll();
      onclick(p, "heldImportAll");
      await drainAll();
      const old = last(p);
      if (reopen) cancelAndReopen(p, api, () => api.loadDropStatus("CASE-A"));
      else api.loadDropStatus("CASE-A");
      p.requests[old].answer({});
      await drainAll();
      if (reopen) expect(status(p)).not.toContain("Held files");
      else expect(status(p)).toContain("Held files moved back");
    }
  });

  it("Run all: an answer after a cancel says nothing; a same-case reload still does", async () => {
    for (const reopen of [true, false]) {
      const { p, api } = importChanges();
      api.loadDropStatus("CASE-A");
      const pending = [{ relpath: "x.evtx", configured: true, suggestedTool: "hayabusa" }];
      p.requests
        .find((r) => r.url.endsWith("/drop-status"))!
        .answer({ status: { pendingRawInputs: pending } });
      await drainAll();
      onclick(p, "dropRunAll");
      const old = last(p);
      if (reopen) cancelAndReopen(p, api, () => api.loadDropStatus("CASE-A"));
      else api.loadDropStatus("CASE-A");
      p.requests[old].answer({ ran: 3 });
      await drainAll();
      if (reopen) expect(status(p)).not.toContain("Ran 3");
      else expect(status(p)).toContain("Ran 3");
    }
  });

  it("false-positive spread: the follow-up refresh reads the case on screen, never the case left", async () => {
    const { p, api } = importChanges();
    api.propagateFalsePositive(["e1"], "pattern");
    const old = last(p);
    p.switchCase("CASE-B", api);
    p.requests[old].answer({});
    await drainAll();
    const urls = p.urls().slice(old + 1);
    expect(urls).toContain("/cases/CASE-B/import-meta");
    expect(urls).not.toContain("/cases/CASE-A/import-meta");
  });
});

describe("velociraptor status lines (#2937)", () => {
  function velo() {
    const p = fakePage();
    const ref: { api?: Api } = {};
    const api = loadDashboardModule<Api>("dashboard-velo-triage.js", ESC, {
      ...p.globals,
      veloCaseId: () => ref.api?.activeCaseId ?? "",
      veloEnabled: true,
      saveSettings: async () => true,
      caseToolEnabled: (_t: string, v: boolean) => v,
      veloClientsAge: () => "now",
      veloClientsCutNotice: () => "",
      loadVeloMonitors: () => {},
      veloMonBrowse: () => {},
      veloPickedLabels: () => [],
      veloLaunchNotesHtml: () => "",
    });
    ref.api = api;
    api.loadVeloHuntJobs("CASE-A");
    return { p, api };
  }
  /** A run form: each class name maps to its own fake element. */
  function form(p: Page) {
    p.el("form.velo-timescope").value = "7d";
    return {
      style: { display: "block" },
      querySelector: (sel: string) => p.el(`form${sel}`),
    };
  }

  it("refresh clients: a cancel frees Refresh and clears 'querying…'; the old answer paints nothing", async () => {
    const { p, api } = velo();
    api.doRefreshVeloClients();
    const old = last(p);
    expect(p.el("veloRefreshClientsBtn").disabled).toBe(true);
    cancelAndReopen(p, api, () => api.loadVeloHuntJobs("CASE-A"));
    expect(p.el("veloRefreshClientsBtn").disabled).toBe(false);
    expect(p.el("veloClientsMsg").textContent).not.toContain("querying");
    p.requests[old].answer({ error: "OLD-ERROR" }, false);
    await drainAll();
    expect(p.el("veloClientsMsg").textContent).not.toContain("OLD-ERROR");
  });

  it("refresh clients: a same-case reload still shows the error", async () => {
    const { p, api } = velo();
    api.doRefreshVeloClients();
    const old = last(p);
    api.loadVeloHuntJobs("CASE-A");
    p.requests[old].answer({ error: "SHOWN-ERROR" }, false);
    await drainAll();
    expect(p.el("veloClientsMsg").textContent).toContain("SHOWN-ERROR");
  });

  it("reconnect: an answer after a cancel paints nothing; a same-case reload still does", async () => {
    for (const reopen of [true, false]) {
      const { p, api } = velo();
      void api.doVeloReconnect();
      await drainAll();
      const old = last(p);
      expect(p.requests[old].url).toBe("/velociraptor/reconnect");
      if (reopen) cancelAndReopen(p, api, () => api.loadVeloHuntJobs("CASE-A"));
      else api.loadVeloHuntJobs("CASE-A");
      p.requests[old].answer({ configured: true, ok: true, clients: 3 });
      await drainAll();
      if (reopen) expect(p.el("veloClientsMsg").textContent).not.toContain("connected");
      else expect(p.el("veloClientsMsg").textContent).toContain("connected");
    }
  });

  it("client list: the case left's late answer does not overwrite the newer one", async () => {
    const { p, api } = velo();
    api.loadVeloClients();
    const old = last(p);
    p.switchCase("CASE-B", api);
    api.loadVeloClients();
    p.requests[last(p)].answer({ updatedAt: "", clients: [{ clientId: "C.B" }] });
    await drainAll();
    p.requests[old].answer({ updatedAt: "", clients: [{ clientId: "C.A1" }, { clientId: "C.A2" }] });
    await drainAll();
    expect(p.el("veloClientsMsg").textContent).toContain("1 enrolled client");
  });

  it("time-scope preview: an answer after a cancel paints nothing; a same-case reload still does", async () => {
    for (const reopen of [true, false]) {
      const { p, api } = velo();
      api.veloTimeScopePreview("b1", form(p));
      const old = last(p);
      if (reopen) cancelAndReopen(p, api, () => api.loadVeloHuntJobs("CASE-A"));
      else api.loadVeloHuntJobs("CASE-A");
      p.requests[old].answer({ error: "PREVIEW-ERROR" }, false);
      await drainAll();
      const text = p.el("form.velo-ts-preview").textContent;
      if (reopen) expect(text).not.toContain("PREVIEW-ERROR");
      else expect(text).toContain("PREVIEW-ERROR");
    }
  });

  it("run bundle: an answer after a cancel paints nothing; a same-case reload still does", async () => {
    for (const reopen of [true, false]) {
      const { p, api } = velo();
      api.veloRunBundle("b1", form(p));
      const old = last(p);
      if (reopen) cancelAndReopen(p, api, () => api.loadVeloHuntJobs("CASE-A"));
      else api.loadVeloHuntJobs("CASE-A");
      p.requests[old].answer({ error: "RUN-ERROR" }, false);
      await drainAll();
      const text = p.el("form.velo-run-msg").textContent;
      if (reopen) expect(text).not.toContain("RUN-ERROR");
      else {
        expect(text).toContain("RUN-ERROR");
        expect(p.el("form.velo-run-go").disabled).toBe(false);
      }
    }
  });
});

describe("super-timeline saves (#2937)", () => {
  function superTimeline() {
    const p = fakePage();
    const api = loadDashboardModule<Api>("dashboard-super-timeline.js", ESC, {
      ...p.globals,
      DfirStarred: { count: () => 1, has: () => false },
      presidioHoldText: (s: string) => s,
      mdToHtml: (s: string) => s,
      prompt: () => "Attacker session",
      zoomToTimeWindow: () => {},
    });
    api.loadSavedTimeframes("CASE-A");
    p.requests[last(p)].answer([]);
    return { p, api };
  }

  it("starred report: an old answer after a cancel paints nothing; a same-case reload still does", async () => {
    for (const reopen of [true, false]) {
      const { p, api } = superTimeline();
      api.genStarredReport();
      const old = last(p);
      if (reopen) cancelAndReopen(p, api, () => api.loadSavedTimeframes("CASE-A"));
      p.requests[old].answer({ markdown: "OLD-REPORT", eventCount: 1 });
      await drainAll();
      if (reopen) expect(p.el("stAiPanel").innerHTML).not.toContain("OLD-REPORT");
      else expect(p.el("stAiPanel").innerHTML).toContain("OLD-REPORT");
    }
  });

  it("save starred report: 'saved' from before a cancel says nothing; a same-case reload still does", async () => {
    for (const reopen of [true, false]) {
      const { p, api } = superTimeline();
      api.genStarredReport();
      p.requests[last(p)].answer({ markdown: "R", eventCount: 1 });
      await drainAll();
      onclick(p, "stAiSave");
      const old = last(p);
      expect(p.requests[old].init?.method).toBe("PUT");
      if (reopen) cancelAndReopen(p, api, () => api.loadSavedTimeframes("CASE-A"));
      else api.loadSavedTimeframes("CASE-A");
      p.requests[old].answer({});
      await drainAll();
      if (reopen) expect(p.el("stAiMsg").textContent).not.toContain("saved");
      else expect(p.el("stAiMsg").textContent).toContain("saved to case");
    }
  });

  it("save timeframe: a message from before a cancel says nothing; a same-case reload still does", async () => {
    for (const reopen of [true, false]) {
      const { p, api } = superTimeline();
      p.el("stFrom").value = "2026-01-01T00:00";
      p.el("stTo").value = "2026-01-02T00:00";
      api.saveTimeframe();
      const old = last(p);
      expect(p.requests[old].init?.method).toBe("POST");
      if (reopen) cancelAndReopen(p, api, () => api.loadSavedTimeframes("CASE-A"));
      else api.loadSavedTimeframes("CASE-A");
      p.requests[old].answer({ error: "SAVE-REFUSED" }, false);
      await drainAll();
      if (reopen) expect(p.el("stSaveMsg").textContent).not.toContain("SAVE-REFUSED");
      else expect(p.el("stSaveMsg").textContent).toContain("SAVE-REFUSED");
    }
  });
});

describe("second opinion: the jump when the tab comes back (#2937)", () => {
  it("does not jump into a case reopened after a cancel; a same-case reload still jumps", async () => {
    for (const reopen of [true, false]) {
      const p = fakePage();
      const shown: (() => void)[] = [];
      const doc = p.globals.document as Record<string, unknown>;
      Object.assign(doc, {
        hidden: true,
        addEventListener: (_t: string, fn: () => void) => shown.push(fn),
        removeEventListener: () => {},
      });
      const jumps: string[] = [];
      const api = loadDashboardModule<Api>("dashboard-second-opinion.js", ESC, {
        ...p.globals,
        render: () => {},
        revealSection: (s: string) => jumps.push(s),
      });
      api.loadSecondOpinion("CASE-A");
      p.requests[last(p)].answer(null);
      await drainAll();
      api.runSecondOpinion();
      p.requests[last(p)].answer({ deltas: [], agreementCount: 2 });
      await drainAll();
      expect(shown).toHaveLength(1);
      if (reopen) cancelAndReopen(p, api, () => api.loadSecondOpinion("CASE-A"));
      else api.loadSecondOpinion("CASE-A");
      doc.hidden = false;
      shown[0]();
      expect(jumps).toEqual(reopen ? [] : ["sec-findings"]);
    }
  });
});
