import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The second-look control (#1554), driven the way the browser drives it.
//
// Second look used to run itself after every synthesis and write rows into the forensic record
// unasked. The record is the product, so what enters it is the analyst's decision. This suite pins
// the three things that decision needs to be a real one:
//
//   1. THE PREVIEW ARRIVES BEFORE THE PRESS. It costs nothing, so making the analyst press the
//      button to find out what the button would do is a worse trade than telling them.
//   2. THE RESULT IS STATED IN THE ANALYST'S TERMS — rows promoted, repeats held back and still
//      searchable, questions that found nothing and became leads, and whether the conclusions moved.
//   3. THE BUSY FLAG COMES OFF ON EVERY PATH. A cancelled or errored load that leaves an in-flight
//      flag on wedges the control for the rest of the session; this codebase has shipped that bug.

interface Api {
  loadSecondLookPreview(caseId: string): Promise<void>;
  runSecondLook(): Promise<void> | undefined;
  initNarrativeTimeline(): void;
}

interface Deferred {
  url: string;
  method: string;
  body: string;
  resolve(body: unknown, init?: { ok?: boolean; status?: number }): void;
  reject(err: Error): void;
}

interface FakeEl {
  id: string;
  value: string;
  textContent: string;
  innerHTML: string;
  checked: boolean;
  disabled: boolean;
  title: string;
  dataset: Record<string, string>;
  style: Record<string, string>;
  addEventListener(type: string, fn: (e: unknown) => void): void;
  click(): void;
  focus(): void;
}

function harness() {
  const pending: Deferred[] = [];
  const els = new Map<string, FakeEl>();
  const el = (id: string): FakeEl => {
    let cur = els.get(id);
    if (!cur) {
      const handlers: Record<string, ((e: unknown) => void)[]> = {};
      cur = {
        id,
        value: "",
        textContent: "",
        innerHTML: "",
        checked: true,
        disabled: false,
        title: "",
        dataset: {},
        style: {},
        addEventListener: (type, fn) => {
          (handlers[type] ||= []).push(fn);
        },
        click: () => (handlers.click || []).forEach((f) => f({ stopPropagation: () => {} })),
        focus: () => {},
      };
      els.set(id, cur);
    }
    return cur;
  };
  const globals = {
    document: { getElementById: (id: string) => el(id), addEventListener: () => {} },
    fetch: (url: string, init?: { method?: string; body?: string }) =>
      new Promise((res, rej) => {
        pending.push({
          url,
          method: init?.method || "GET",
          body: init?.body || "",
          resolve: (body, i = {}) =>
            res({ ok: i.ok ?? true, status: i.status ?? 200, json: () => Promise.resolve(body) }),
          reject: rej,
        });
      }),
    relTime: (s: string) => String(s),
    proseHtml: (s: string) => String(s),
    isSectionVisible: () => true,
    loadSectionsVis: () => ({}),
  };
  const api = loadDashboardModule<Api>("dashboard-narrative.js", ["dashboard-escape.js"], globals);
  return { api, pending, el };
}

const FULL_PREVIEW = {
  configured: true,
  questions: 7,
  hypotheses: 3,
  iocs: 12,
  modelRequests: 4,
  requests: 26,
  wouldPromote: 140,
  leads: ["dns cache for evil.example.com", "srum for the 3rd"],
  truncated: false,
  shapeHeld: 38,
};

/** Let every queued microtask settle — the module chains .then/.finally several deep. */
const settle = () => new Promise((r) => setTimeout(r, 0));

async function withPreview(preview: unknown = FULL_PREVIEW) {
  const h = harness();
  h.api.initNarrativeTimeline();
  const load = h.api.loadSecondLookPreview("case-1");
  h.pending.shift()!.resolve(preview);
  await load;
  await settle();
  return h;
}

describe("the preview, before anything is pressed", () => {
  it("is fetched when the case loads, and asks the server to measure, not to run", async () => {
    const h = harness();
    h.api.initNarrativeTimeline();
    void h.api.loadSecondLookPreview("case-1");
    expect(h.pending).toHaveLength(1);
    expect(h.pending[0].url).toBe("/cases/case-1/second-look/preview");
    expect(h.pending[0].method).toBe("GET");
  });

  it("says what would be searched and roughly how much would land in the record", async () => {
    const h = await withPreview();
    const html = h.el("secondLookPreview").innerHTML;
    expect(html).toContain("7 open questions");
    expect(html).toContain("3 hypotheses");
    expect(html).toContain("12 IOCs");
    expect(html).toContain("4 evidence requests from the model");
    expect(html).toContain("26 searches in all");
    expect(html).toContain("About 140 rows");
    expect(html).toContain("written into this case's forensic timeline");
  });

  it("names the repeats it would hold back, and says they stay searchable", async () => {
    const html = (await withPreview()).el("secondLookPreview").innerHTML;
    expect(html).toContain("38 further rows are repeats");
    expect(html).toContain("They stay searchable in the archive");
  });

  it("says which searches would find nothing, and that those become leads", async () => {
    const html = (await withPreview()).el("secondLookPreview").innerHTML;
    expect(html).toContain("recorded as a collection lead");
  });

  it("warns when one sweep cannot read every matching row", async () => {
    const html = (await withPreview({ ...FULL_PREVIEW, truncated: true })).el("secondLookPreview").innerHTML;
    expect(html).toContain("not full coverage of the archive");
  });

  it("offers no button on a case with nothing to look for", async () => {
    const h = await withPreview({
      configured: true,
      questions: 0,
      hypotheses: 0,
      iocs: 0,
      modelRequests: 0,
      requests: 0,
    });
    expect(h.el("secondLookPreview").innerHTML).toContain("Nothing to look for yet");
    expect(h.el("secondLookRunBtn").disabled).toBe(true);
  });

  // A 501 IS an answer, not a request failure the analyst can do nothing with.
  it("turns a 501 into the reason, in the panel, with the button off", async () => {
    const h = harness();
    h.api.initNarrativeTimeline();
    const load = h.api.loadSecondLookPreview("case-1");
    h.pending
      .shift()!
      .resolve({ error: "No super-timeline archive for this case." }, { ok: false, status: 501 });
    await load;
    await settle();
    expect(h.el("secondLookPreview").innerHTML).toContain("No super-timeline archive for this case.");
    expect(h.el("secondLookRunBtn").disabled).toBe(true);
  });

  it("does not claim the archive is empty when it simply could not measure", async () => {
    const h = harness();
    h.api.initNarrativeTimeline();
    const load = h.api.loadSecondLookPreview("case-1");
    h.pending.shift()!.reject(new Error("network down"));
    await load;
    await settle();
    const html = h.el("secondLookPreview").innerHTML;
    expect(html).toContain("Could not measure");
    expect(html).toContain("Nothing here says the archive holds no answers");
  });
});

describe("the re-synthesis opt-out", () => {
  it("is on by default, and the request says so", async () => {
    const h = await withPreview();
    expect(h.el("secondLookResynth").checked).toBe(true);
    void h.api.runSecondLook();
    const req = h.pending.shift()!;
    expect(req.url).toBe("/cases/case-1/second-look");
    expect(req.method).toBe("POST");
    expect(JSON.parse(req.body)).toEqual({ resynthesize: true });
  });

  it("is a visible checkbox, not a hidden default", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    expect(html).toContain('id="secondLookResynth" checked');
    expect(html).toContain("Re-synthesise afterwards");
  });

  it("sends false when the analyst unticks it", async () => {
    const h = await withPreview();
    h.el("secondLookResynth").checked = false;
    void h.api.runSecondLook();
    expect(JSON.parse(h.pending.shift()!.body)).toEqual({ resynthesize: false });
  });

  it("says plainly that skipping it leaves the conclusions behind the record", async () => {
    const h = await withPreview();
    const run = h.api.runSecondLook();
    h.pending.shift()!.resolve({ promoted: 9, leads: [], summary: "", resynthesized: false, shapeCapped: 0 });
    await run;
    await settle();
    const html = h.el("secondLookResult").innerHTML;
    expect(html).toContain("conclusions were NOT written again");
    expect(html).toContain("still the ones from before these rows arrived");
  });
});

describe("what the run reports afterwards", () => {
  async function ran(body: Record<string, unknown>) {
    const h = await withPreview();
    const run = h.api.runSecondLook();
    h.pending.shift()!.resolve(body);
    await run;
    await settle();
    return h;
  }

  it("counts the rows promoted, the repeats held back and the questions that found nothing", async () => {
    const h = await ran({
      promoted: 142,
      shapeCapped: 38,
      leads: ["dns cache", "srum", "prefetch"],
      summary: "26 searches, 142 rows promoted",
      resynthesized: true,
      truncated: false,
    });
    const html = h.el("secondLookResult").innerHTML;
    expect(html).toContain("142 rows");
    expect(html).toContain("38 repeat rows were held back");
    expect(html).toContain("still in the archive and still searchable there");
    expect(html).toContain("3 questions found nothing");
    expect(html).toContain("recorded as a collection lead");
    expect(html).toContain("conclusions were written again");
  });

  it("says so when nothing matched, rather than showing an empty panel", async () => {
    const h = await ran({ promoted: 0, shapeCapped: 0, leads: [], summary: "", resynthesized: true });
    expect(h.el("secondLookResult").innerHTML).toContain("no row was written into the forensic timeline");
  });

  it("escapes every string the server sends — they are built from the host's own text", async () => {
    const h = await ran({
      promoted: 1,
      shapeCapped: 0,
      leads: ['<img src=x onerror="alert(1)">'],
      summary: "<script>alert(2)</script>",
      resynthesized: true,
    });
    const html = h.el("secondLookResult").innerHTML;
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;img");
  });

  it("surfaces a refusal as a reason, not as silence", async () => {
    const h = await withPreview();
    const run = h.api.runSecondLook();
    h.pending.shift()!.resolve({ error: "budget exceeded" }, { ok: false, status: 402 });
    await run;
    await settle();
    expect(h.el("secondLookStatus").textContent).toContain("budget exceeded");
    expect(h.el("secondLookRunBtn").disabled, "and the control is usable again").toBe(false);
  });
});

describe("the busy flag", () => {
  it("blocks a second press while a run is in flight", async () => {
    const h = await withPreview();
    void h.api.runSecondLook();
    expect(h.pending).toHaveLength(1);
    expect(h.el("secondLookRunBtn").disabled).toBe(true);
    // The flag is the lock, not the `disabled` attribute: forcing the attribute off must not let a
    // second run start.
    h.el("secondLookRunBtn").disabled = false;
    void h.api.runSecondLook();
    expect(h.pending, "a second run started while the first was still going").toHaveLength(1);
  });

  it("comes off when the request rejects — the wedge this codebase has shipped before", async () => {
    const h = await withPreview();
    const run = h.api.runSecondLook();
    h.pending.shift()!.reject(new Error("socket hang up"));
    await run;
    await settle();
    expect(h.el("secondLookRunBtn").disabled).toBe(false);
    expect(h.el("secondLookStatus").textContent).toContain("socket hang up");
    // And the control really works again, not merely looks enabled.
    void h.api.runSecondLook();
    expect(h.pending.some((p) => p.method === "POST")).toBe(true);
  });

  it("comes off when the analyst switches case mid-run, and the old run cannot re-lock it", async () => {
    const h = await withPreview();
    const run = h.api.runSecondLook();
    const inFlight = h.pending.shift()!;
    // The analyst moves on. The new case's preview is now the one in flight.
    const load = h.api.loadSecondLookPreview("case-2");
    expect(h.el("secondLookRunBtn").disabled).toBe(true); // still measuring case-2
    h.pending.shift()!.resolve(FULL_PREVIEW);
    await load;
    await settle();
    expect(h.el("secondLookRunBtn").disabled).toBe(false);
    // The abandoned run answers late. It must not paint case-1's result onto case-2, and must not
    // clear a flag it no longer owns.
    inFlight.resolve({ promoted: 999, shapeCapped: 0, leads: [], summary: "", resynthesized: true });
    await run;
    await settle();
    expect(h.el("secondLookResult").innerHTML).not.toContain("999");
    expect(h.el("secondLookRunBtn").disabled).toBe(false);
  });

  it("refreshes the synthesis strip and re-costs the preview once a run lands", async () => {
    const h = await withPreview();
    const run = h.api.runSecondLook();
    h.pending.shift()!.resolve({ promoted: 4, shapeCapped: 0, leads: [], summary: "", resynthesized: true });
    await run;
    await settle();
    const urls = h.pending.map((p) => p.url);
    expect(urls).toContain("/cases/case-1/synth-meta");
    expect(urls).toContain("/cases/case-1/second-look/preview");
  });
});

describe("where the control lives", () => {
  it("is in the findings card beside the synthesis strip, not a rival panel", async () => {
    const html = await readFile(new URL("../../../public/dashboard.html", import.meta.url), "utf8");
    const findings = html.slice(html.indexOf('id="sec-findings"'), html.indexOf('id="sec-timeline"'));
    expect(findings).toContain('id="secondLookCard"');
    expect(findings).toContain('id="secondLookRunBtn"');
    // No new section id: reusing the card is what keeps it out of the section registry, the
    // visibility editor and the seven built-in view profiles.
    expect(html).not.toContain('id="sec-second-look"');
  });

  it("uses inline markup for every question — a browser modal blocks the harness", async () => {
    const src = await readFile(new URL("../../../public/js/dashboard-narrative.js", import.meta.url), "utf8");
    const code = src
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"))
      .join("\n");
    expect(code).not.toMatch(/\bconfirm\s*\(/);
    expect(code).not.toMatch(/\balert\s*\(/);
  });

  it("is reachable from the command palette", async () => {
    const reg = await readFile(
      new URL("../../../public/js/dashboard-palette-registry.js", import.meta.url),
      "utf8",
    );
    expect(reg).toContain('btn: "secondLookRunBtn"');
  });

  it("is measured on case connect by the panel-loader fan-out", async () => {
    const connect = await readFile(
      new URL("../../../public/js/dashboard-case-connect.js", import.meta.url),
      "utf8",
    );
    expect(connect).toContain('["secondLook", () => loadSecondLookPreview(caseId)]');
  });
});
