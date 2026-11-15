// The Watson status pill and bar: what Watson does now, in one place (working, waiting for
// Velociraptor, waiting for the analyst, ready). Runs the real module in a vm with a small fake DOM.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

type Status = { state: string; pill: string; bar: string; pid: string };
type Api = {
  watsonEmptyCaseHtml(chat: unknown): string;
  watsonStatusOf(chat: unknown, localBusy: boolean): Status;
  watsonStatusSync(chat: unknown, localBusy: boolean): void;
};

class Slot {
  innerHTML = "";
  hidden = false;
  className = "";
}

function setup() {
  const slots: Record<string, Slot[]> = {
    status: [new Slot()],
    statusbar: [new Slot()],
    railstatus: [new Slot()],
  };
  const clicks: ((e: unknown) => void)[] = [];
  const document = {
    querySelectorAll: (sel: string) => slots[/data-w="(\w+)"/.exec(sel)?.[1] ?? ""] ?? [],
    querySelector: () => null,
    addEventListener: (t: string, cb: (e: unknown) => void) => {
      if (t === "click") clicks.push(cb);
    },
  };
  const api = loadDashboardModule<Api>(
    "dashboard-watson-status.js",
    ["dashboard-escape.js", "dashboard-watson-cards.js"],
    { document },
  );
  return { api, slots, clicks };
}

const chat = (proposals: unknown[] = [], extra: Record<string, unknown> = {}) => ({
  turns: [],
  proposals,
  running: null,
  ...extra,
});
const launch = (over: Record<string, unknown> = {}) => ({
  id: "wp-1",
  kind: "velo_launch",
  status: "pending",
  mode: "collection",
  hostname: "WS-FAKE01",
  title: "Network connections on WS-FAKE01",
  ...over,
});

describe("Watson status", () => {
  it("an empty case suggests the Best Practice bundle when Velociraptor is connected", () => {
    const { api } = setup();
    const withVelo = api.watsonEmptyCaseHtml({ veloConnected: true });
    expect(withVelo).toContain("This case has no forensic-timeline events or findings.");
    expect(withVelo).toContain("Run the Best Practice bundle");
    expect(withVelo).toContain('data-act="watsonBestPractice"');
    const noVelo = api.watsonEmptyCaseHtml({ veloConnected: false });
    expect(noVelo).toContain("Import evidence first.");
    expect(noVelo).not.toContain("watsonBestPractice");
  });

  it("is empty with no case open", () => {
    const { api } = setup();
    expect(api.watsonStatusOf(null, false).state).toBe("none");
  });

  it("says Ready when nothing runs and nothing waits", () => {
    const { api } = setup();
    const s = api.watsonStatusOf(chat(), false);
    expect(s.state).toBe("ready");
    expect(s.pill).toContain("Ready");
    expect(s.bar).toBe("");
  });

  it("says Working while a round runs, ahead of every other state", () => {
    const { api } = setup();
    const s = api.watsonStatusOf(
      chat([launch()], { running: { since: "t", kind: "message", queued: 0 } }),
      false,
    );
    expect(s.state).toBe("working");
    expect(s.pill).toContain("Working");
    expect(s.bar).toContain("Watson is working on an answer.");
    expect(api.watsonStatusOf(chat(), true).state).toBe("working");
    expect(
      api.watsonStatusOf(chat([], { running: { since: "t", kind: "reaction", queued: 0 } }), false).bar,
    ).toContain("Watson is working on the new case events.");
  });

  it("says Waiting for Velociraptor while a launched collection is still being watched", () => {
    const { api } = setup();
    const out = launch({
      status: "applied",
      launched: { at: "t", by: "fake.user" },
      watch: { deadline: "t", state: "watching" },
    });
    const s = api.watsonStatusOf(chat([out, launch({ id: "wp-2" })]), false);
    expect(s.state).toBe("velo");
    expect(s.pill).toContain("Waiting for Velociraptor");
    expect(s.bar).toContain('Velociraptor collects "Network connections on WS-FAKE01".');
    expect(s.bar).toContain("Watson reads the result when it arrives.");
    const done = launch({
      status: "applied",
      launched: { at: "t", by: "u" },
      watch: { deadline: "t", state: "finished", ingested: true },
    });
    expect(api.watsonStatusOf(chat([done]), false).state).toBe("ready");
  });

  it("says Waiting for you with the count, and names the first card's action in the bar", () => {
    const { api } = setup();
    const s = api.watsonStatusOf(
      chat([launch(), { id: "wp-9", kind: "next_step", status: "pending", title: "Collect event logs" }]),
      false,
    );
    expect(s.state).toBe("you");
    expect(s.pill).toContain("Waiting for you · 2");
    expect(s.bar).toContain('Launch "Network connections on WS-FAKE01".');
    expect(s.bar).toContain("1 more card waits for you.");
    expect(s.bar).toContain('data-w-status-show="wp-1"');
    expect(s.pid).toBe("wp-1");
  });

  it("puts the first card's own buttons in the bar, but never a launch with a risk warning", () => {
    const { api } = setup();
    const s = api.watsonStatusOf(chat([launch()]), false);
    expect(s.bar).toContain('data-w-verb="apply" data-pid="wp-1">Launch</button>');
    expect(s.bar).toContain('data-w-verb="reject" data-pid="wp-1">Reject</button>');
    const risky = api.watsonStatusOf(chat([launch({ risk: { reasons: ["r"], checks: ["c"] } })]), false);
    expect(risky.bar).not.toContain('data-w-verb="apply"');
    expect(risky.bar).toContain("Show card");
    const other = api.watsonStatusOf(
      chat([{ id: "wp-4", kind: "finding_new", status: "pending", title: "x" }]),
      false,
    );
    expect(other.bar).toContain('data-w-verb="apply" data-pid="wp-4">Add finding</button>');
  });

  it("names what Apply does for a card that is not a launch", () => {
    const { api } = setup();
    const s = api.watsonStatusOf(
      chat([{ id: "wp-3", kind: "finding_new", status: "pending", title: "Rundll32 from Temp" }]),
      false,
    );
    expect(s.bar).toContain('Add the finding "Rundll32 from Temp" to the case, or reject it.');
  });

  it("escapes a title that came from the model", () => {
    const { api } = setup();
    const s = api.watsonStatusOf(chat([launch({ title: '<img src=x onerror="a()">' })]), false);
    expect(s.bar).not.toContain("<img");
    expect(s.bar).toContain("&lt;img");
  });

  it("paints the pill, the bar and the rail dot, and hides the bar when there is nothing to say", () => {
    const { api, slots } = setup();
    api.watsonStatusSync(chat([launch()]), false);
    expect(slots.status[0].innerHTML).toContain("Waiting for you");
    expect(slots.statusbar[0].hidden).toBe(false);
    expect(slots.statusbar[0].innerHTML).toContain("Launch");
    expect(slots.railstatus[0].className).toContain("watson-status-you");
    api.watsonStatusSync(chat(), false);
    expect(slots.statusbar[0].hidden).toBe(true);
    expect(slots.railstatus[0].className).toContain("watson-status-ready");
  });

  it("the panel has the three status slots, and the running-state sync paints them", () => {
    const view = readFileSync(
      new URL("../../../public/js/dashboard-watson-view.js", import.meta.url),
      "utf8",
    ).replace(/\r\n/g, "\n");
    for (const slot of ["status", "statusbar", "railstatus"]) expect(view).toContain(`data-w="${slot}"`);
    const run = readFileSync(
      new URL("../../../public/js/dashboard-watson-run.js", import.meta.url),
      "utf8",
    ).replace(/\r\n/g, "\n");
    expect(run).toContain("watsonStatusSync(chat, localBusy)");
  });
});

// Codex branch review #3: a launch whose outcome is unknown (uncertain), or a launch no live request
// owns (launching + stalled), needs the analyst. It is never "Ready" or "Waiting for Velociraptor".
describe("Watson status: launches that need recovery", () => {
  const intent = { at: "t", by: "fake.user", fingerprint: "f", reserved: [] };

  it.each([
    ["uncertain", { status: "uncertain", launching: intent }],
    ["stalled launching", { status: "launching", launching: intent, stalled: true }],
  ])("a %s launch waits for the analyst, with a recovery line and Show card", (_name, over) => {
    const { api } = setup();
    const s = api.watsonStatusOf(chat([launch(over)]), false);
    expect(s.state).toBe("you");
    expect(s.pid).toBe("wp-1");
    expect(s.pill).toContain("Waiting for you · 1");
    expect(s.bar).toContain('Check "Network connections on WS-FAKE01": mark it as launched or try again.');
    expect(s.bar).toContain('data-w-status-show="wp-1"');
    expect(s.bar).not.toContain('data-w-verb="apply"');
  });

  it("comes before a collection Velociraptor still runs, and counts with the other waiting cards", () => {
    const { api } = setup();
    const out = launch({
      id: "wp-9",
      status: "applied",
      launched: { at: "t", by: "u" },
      watch: { deadline: "t", state: "watching" },
    });
    const stuck = launch({ id: "wp-2", status: "uncertain", launching: intent });
    const s = api.watsonStatusOf(chat([out, stuck, launch({ id: "wp-3" })]), false);
    expect(s.state).toBe("you");
    expect(s.pid).toBe("wp-2");
    expect(s.pill).toContain("· 2");
  });

  it("a launching request that is still live is Waiting for Velociraptor", () => {
    const { api } = setup();
    const s = api.watsonStatusOf(chat([launch({ status: "launching", launching: intent })]), false);
    expect(s.state).toBe("velo");
  });
});

// Codex branch review #4: "Run the Best Practice bundle" must reach the run form: leave full screen,
// show the Fleet Collection section, load the bundle list, open and focus the form, or say why not.
describe("Run the Best Practice bundle", () => {
  type BpApi = { watsonBestPractice(): Promise<string>; watsonEmptyCaseHtml(chat: unknown): string };
  function bpSetup(
    o: {
      full?: boolean;
      section?: boolean;
      viewHides?: boolean;
      formAfterLoad?: boolean;
      formNow?: boolean;
      bundleKnown?: boolean;
    } = {},
  ) {
    const calls: string[] = [];
    const note = { textContent: "", hidden: true };
    const field = { focus: () => calls.push("focus") };
    const form = {
      style: { display: "none" },
      scrollIntoView: () => calls.push("scroll"),
      querySelector: () => field,
    };
    let loaded = false;
    const sec = {
      hidden: false,
      style: { display: o.viewHides ? "none" : "" },
      classList: { remove: () => {} },
    };
    const document = {
      body: { classList: { contains: (c: string) => c === "watson-full-open" && !!o.full } },
      getElementById: (id: string) => (id === "sec-fleet-collection" && o.section !== false ? sec : null),
      querySelector: (sel: string) =>
        sel === '.velo-run-form[data-id="best-practice"]' && (o.formNow || (loaded && o.formAfterLoad))
          ? form
          : null,
      querySelectorAll: (sel: string) => (sel === '[data-w="bpnote"]' ? [note] : []),
      addEventListener: () => {},
    };
    const api = loadDashboardModule<BpApi>(
      "dashboard-watson-status.js",
      ["dashboard-escape.js", "dashboard-watson-cards.js"],
      {
        document,
        setWatsonPanelState: (s: string) => calls.push(`panel:${s}`),
        revealSection: (id: string) => calls.push(`reveal:${id}`),
        loadVeloBundles: async () => {
          calls.push("load");
          loaded = true;
        },
        toggleVeloRunForm: (id: string) => {
          calls.push(`toggle:${id}`);
          if (o.bundleKnown !== false) form.style.display = "block";
        },
      },
    );
    return { api, calls, note, form };
  }

  it("leaves full screen, shows the section, loads the bundles, then opens and focuses the form", async () => {
    const { api, calls, note } = bpSetup({ full: true, formAfterLoad: true });
    expect(await api.watsonBestPractice()).toBe("");
    expect(calls).toEqual([
      "panel:open",
      "reveal:sec-fleet-collection",
      "load",
      "toggle:best-practice",
      "scroll",
      "focus",
    ]);
    expect(note.hidden).toBe(true);
  });

  it("does not change the panel when it is not full screen, and does not reload a list that is there", async () => {
    const { api, calls } = bpSetup({ formNow: true });
    expect(await api.watsonBestPractice()).toBe("");
    expect(calls).not.toContain("panel:open");
    expect(calls).not.toContain("load");
  });

  it("does not close a form that is already open", async () => {
    const { api, calls, form } = bpSetup({ formNow: true });
    form.style.display = "block";
    await api.watsonBestPractice();
    expect(calls).not.toContain("toggle:best-practice");
    expect(calls).toContain("focus");
  });

  it("says so when there is no Fleet Collection section", async () => {
    const { api, note } = bpSetup({ section: false });
    expect(await api.watsonBestPractice()).toContain("cannot find the Fleet Collection section");
    expect(note.hidden).toBe(false);
  });

  it("says where the section is when the current view hides it", async () => {
    const { api, calls } = bpSetup({ viewHides: true, formNow: true });
    expect(await api.watsonBestPractice()).toContain("Show the section in Settings");
    expect(calls).not.toContain("toggle:best-practice");
  });

  it.each([
    ["the bundle list has no Best Practice form", { formAfterLoad: false }],
    ["the form does not open", { formNow: true, bundleKnown: false }],
  ])("shows a notice, and opens no other form, when %s", async (_n, o) => {
    const { api, calls } = bpSetup(o);
    expect(await api.watsonBestPractice()).toContain("cannot find the Best Practice bundle");
    expect(calls).not.toContain("focus");
  });

  it("keeps the notice across a re-render of the empty case, escaped", async () => {
    const { api } = bpSetup({ section: false });
    await api.watsonBestPractice();
    const html = api.watsonEmptyCaseHtml({ veloConnected: true });
    expect(html).toContain('data-w="bpnote"');
    expect(html).toContain("cannot find the Fleet Collection section");
    expect(html).not.toContain(" hidden>");
  });
});
