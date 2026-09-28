// #1782: a Presidio approval hold on the Executive Summary / Narrative "✨ Generate" buttons is a
// question for the analyst, not a failure. It used to print, in red, "generate failed:
// presidio_approval_required — restart the companion server if this 404s".
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface PresidioApi {
  presidioHold: (status: number, body: unknown) => boolean;
  presidioHoldText: (what: string) => string;
}
interface ExecApi {
  genExecSummary: () => void;
}
interface NarrativeApi {
  genNarrative: () => void;
  initNarrativeTimeline: () => void;
}

const HOLD = { error: "presidio_approval_required", findings: [{ value: "alice", entityType: "PERSON" }] };
const settle = () => new Promise((r) => setTimeout(r, 10));

function el(id: string) {
  const handlers: Record<string, (e: unknown) => void> = {};
  return {
    id,
    value: "",
    textContent: "",
    innerHTML: "",
    disabled: false,
    dataset: {} as Record<string, string>,
    style: { display: "" } as Record<string, string>,
    addEventListener: (type: string, fn: (e: unknown) => void) => void (handlers[type] = fn),
    click: () => handlers.click?.({ stopPropagation: () => {} }),
    focus: () => {},
    querySelectorAll: () => [],
  };
}

/** The page globals the two generators read, a 409 fetch, and a record of the badge refresh. */
function page(fetchBody: unknown, status = 409) {
  const elements: Record<string, ReturnType<typeof el>> = {};
  const get = (id: string) => (elements[id] ??= el(id));
  get("caseId").value = "case-1";
  const pending: unknown[] = [];
  const urls: string[] = [];
  const globals = {
    document: { getElementById: get, querySelector: () => null, addEventListener: () => {} },
    fetch: (url: string) => {
      urls.push(url);
      if (url.endsWith("/presidio-pending"))
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ pending: HOLD.findings }),
        });
      return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(fetchBody) });
    },
    isSectionVisible: () => true,
    loadSectionsVis: () => ({}),
    setPresidioPending: (f: unknown) => pending.push(f),
    loadPresidioPending: () => pending.push("reloaded"),
    DfirState: { lastState: () => null },
  };
  return { get, pending, urls, globals };
}

describe("presidioHold", () => {
  const { globals, get, urls } = page({});
  const p = loadDashboardModule<PresidioApi>("dashboard-presidio.js", ["dashboard-escape.js"], globals);

  it("is true only for a 409 carrying the approval code", () => {
    expect(p.presidioHold(409, HOLD)).toBe(true);
    expect(p.presidioHold(500, HOLD)).toBe(false);
    expect(p.presidioHold(409, { error: "host_merge_decision_required" })).toBe(false);
    expect(p.presidioHold(409, null)).toBe(false);
  });

  it("names the hold neutrally and points at Anonymization", () => {
    const t = p.presidioHoldText("Narrative");
    expect(t).toBe("Narrative held for Presidio approval — review in Anonymization");
    expect(t).not.toMatch(/fail|restart|error/i);
  });

  // The badge is refreshed from the case's own pending store, never from the 409's findings: a late
  // answer for another case must not put that case's values in this case's panel.
  it("refreshes the ⚠ Presidio badge from the pending store of the case on screen", async () => {
    urls.length = 0;
    expect(p.presidioHold(409, HOLD)).toBe(true);
    expect(urls).toEqual(["/cases/case-1/presidio-pending"]);
    await new Promise((r) => setTimeout(r, 10));
    expect(get("presidioPendingBadge").textContent).toBe("⚠ Presidio: 1");
  });

  it("drops a pending-store answer that arrives after the analyst switched case", async () => {
    get("presidioPendingBadge").textContent = "";
    p.presidioHold(409, HOLD);
    get("caseId").value = "case-2";
    await new Promise((r) => setTimeout(r, 10));
    expect(get("presidioPendingBadge").textContent).toBe("");
    get("caseId").value = "case-1";
  });
});

// The generators get presidioHold/presidioHoldText as globals, as the page provides them; the
// predicate itself is pinned above against the real dashboard-presidio.js.
function loadWith<T>(file: string, g: ReturnType<typeof page>) {
  const globals = {
    ...g.globals,
    presidioHold: (status: number, body: { error?: string; findings?: unknown } | null) => {
      if (status !== 409 || !body || body.error !== "presidio_approval_required") return false;
      g.globals.setPresidioPending(body.findings);
      return true;
    },
    presidioHoldText: (what: string) => `${what} held for Presidio approval — review in Anonymization`,
  };
  return loadDashboardModule<T>(
    file,
    ["dashboard-escape.js", "dashboard-text.js", "dashboard-fragments.js"],
    globals,
  );
}

describe("Executive Summary ✨ Generate on a Presidio hold", () => {
  it("shows a muted hold message, never a red failure or a restart hint", async () => {
    const g = page(HOLD);
    const api = loadWith<ExecApi>("dashboard-exec-summary.js", g);
    api.genExecSummary();
    await settle();
    const out = g.get("execGenResult").innerHTML;
    expect(out).toContain("Executive summary held for Presidio approval — review in Anonymization");
    expect(out).toContain("var(--text-muted)");
    expect(out).not.toMatch(/generate failed|restart the companion|sev-high/);
    expect(g.pending).toEqual([HOLD.findings]);
    expect(g.get("genExecBtn").disabled).toBe(false);
  });

  it("still reports a real failure as one", async () => {
    const g = page({ error: "Budget limit exceeded" }, 500);
    const api = loadWith<ExecApi>("dashboard-exec-summary.js", g);
    api.genExecSummary();
    await settle();
    expect(g.get("execGenResult").innerHTML).toContain("generate failed: Budget limit exceeded");
  });
});

describe("Narrative ✨ Generate on a Presidio hold", () => {
  it("shows the neutral hold message in the status line", async () => {
    const g = page(HOLD);
    const api = loadWith<NarrativeApi>("dashboard-narrative.js", g);
    api.genNarrative();
    await settle();
    const msg = g.get("genNarrativeMsg").textContent;
    expect(msg).toBe("Narrative held for Presidio approval — review in Anonymization");
    expect(g.pending).toEqual([HOLD.findings]);
  });
});

// The trap in #1765: the editor treats "—" as "nothing written yet". The view now shows a sentence
// for it, and that sentence must never become the editor's text.
describe("Narrative editor on an empty case", () => {
  it("opens empty, whatever the view is showing", () => {
    for (const raw of ["—", "", undefined]) {
      const g = page({}, 200);
      const api = loadWith<NarrativeApi>("dashboard-narrative.js", g);
      api.initNarrativeTimeline();
      const view = g.get("narrativeView");
      view.textContent = "No narrative yet — ✨ Generate one from the Attack Path.";
      if (raw !== undefined) view.dataset.raw = raw;
      else view.textContent = "—"; // the markup's own placeholder carries no data-raw
      g.get("editNarrativeBtn").click();
      expect(g.get("narrativeText").value).toBe("");
    }
  });
});
