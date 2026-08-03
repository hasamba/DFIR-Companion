import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-values.js — labels, keys, lookups and predicates (#415).
//
// Several of these take an ELEMENT as an argument. Receiving a node is not the same as reaching
// for one: they never touch `document`, so a stub with the two properties they read is enough, and
// that is exactly what makes them testable at all.

const v = loadDashboardModule("dashboard-values.js");

describe("_workflowInitials", () => {
  it.each([
    ["Ada Lovelace", "AL"],
    ["ada  lovelace", "AL"],
    ["Ada Byron King Lovelace", "AL"], // first and LAST, not first two
    ["Ada", "AD"],
    ["a", "A"],
    ["   ", "?"],
    ["", "?"],
  ])("%j -> %s", (name, expected) => expect(v._workflowInitials(name)).toBe(expected));
});

describe("pbLocalStats", () => {
  it("counts done tasks and rounds the percentage", () => {
    expect(v.pbLocalStats([{ status: "done" }, { status: "todo" }, { status: "done" }])).toEqual({
      total: 3,
      done: 2,
      completionPct: 67,
    });
  });

  it("reports 0% rather than NaN for an empty playbook", () => {
    expect(v.pbLocalStats([])).toEqual({ total: 0, done: 0, completionPct: 0 });
  });
});

describe("ticketLabel", () => {
  it("names Jira, and treats everything else as ServiceNow", () => {
    expect(v.ticketLabel("jira")).toBe("Jira");
    expect(v.ticketLabel("servicenow")).toBe("ServiceNow");
    expect(v.ticketLabel(undefined)).toBe("ServiceNow");
  });
});

// Three lookups over the same tool list with three different jobs: what IS configured for this
// extension, what COULD be, and all of them.
describe("toolForExt / suggestToolForExt / toolsForExt", () => {
  const status = {
    tools: [
      { id: "unconfigured", configured: false, extensions: [".evtx"] },
      { id: "configured", configured: true, extensions: [".evtx"] },
      { id: "other", configured: true, extensions: [".evtx", ".pf"] },
    ],
  };

  it("toolForExt returns the first CONFIGURED tool", () => {
    expect(v.toolForExt(".evtx", status)).toBe("configured");
    expect(v.toolForExt(".unknown", status)).toBeNull();
  });

  it("suggestToolForExt returns the first tool whether configured or not", () => {
    expect(v.suggestToolForExt(".evtx", status)).toBe("unconfigured");
    expect(v.suggestToolForExt(".unknown", status)).toBeNull();
  });

  it("toolsForExt returns every configured tool", () => {
    expect(v.toolsForExt(".evtx", status).map((t: { id: string }) => t.id)).toEqual(["configured", "other"]);
    expect(v.toolsForExt(".pf", status).map((t: { id: string }) => t.id)).toEqual(["other"]);
  });

  it("survives a status object that has not loaded yet", () => {
    for (const empty of [null, undefined, {}]) {
      expect(v.toolForExt(".evtx", empty)).toBeNull();
      expect(v.suggestToolForExt(".evtx", empty)).toBeNull();
      expect(v.toolsForExt(".evtx", empty)).toEqual([]);
    }
  });
});

describe("jobMenuView", () => {
  it("offers cancel only for a running or queued cancellable job", () => {
    expect(v.jobMenuView({ status: "running", cancellable: true }).cancel).toBe(true);
    expect(v.jobMenuView({ status: "queued", cancellable: true }).cancel).toBe(true);
    expect(v.jobMenuView({ status: "running", cancellable: false }).cancel).toBe(false);
    expect(v.jobMenuView({ status: "done", cancellable: true }).cancel).toBe(false);
  });

  // A failed job is resumable only when the failure says so. "Retry" on a job that failed for a
  // non-retryable reason is an invitation to burn another hour on the same error.
  it("offers resume for an interrupted job, or a failure marked retryable", () => {
    expect(v.jobMenuView({ resumable: true, status: "interrupted" }).resume).toBe(true);
    expect(v.jobMenuView({ resumable: true, status: "failed", failure: { retryable: true } }).resume).toBe(
      true,
    );
    expect(v.jobMenuView({ resumable: true, status: "failed", failure: { retryable: false } }).resume).toBe(
      false,
    );
    expect(v.jobMenuView({ resumable: false, status: "interrupted" }).resume).toBe(false);
  });

  it("assembles progress, throughput, ETA, checkpoint and warnings into one detail line", () => {
    const view = v.jobMenuView({
      status: "running",
      detail: "importing",
      progress: { done: 3, total: 10 },
      throughputPerSecond: 2.5,
      lastCheckpoint: { progress: { done: 2, total: 10 } },
      warnings: ["a", "b"],
    });
    expect(view.detail).toContain("importing");
    expect(view.detail).toContain(" 3/10");
    expect(view.detail).toContain("2.5/s");
    expect(view.detail).toContain("durable checkpoint 2/10");
    expect(view.detail).toContain("2 warning(s)");
  });

  it("leaves the detail empty when there is nothing to say", () => {
    expect(v.jobMenuView({ status: "done" }).detail).toBe("");
  });
});

describe("updateJobRow", () => {
  /** The five children updateJobRow reaches for, and nothing else. */
  const fakeRow = () => {
    const cells: Record<string, Record<string, unknown>> = {
      ".job-st": { className: "", textContent: "" },
      ".job-detail": { textContent: "", style: {} },
      ".job-kind": { textContent: "" },
      ".job-label": { textContent: "" },
    };
    return { cells, querySelector: (sel: string) => cells[sel] };
  };

  it("writes the job's fields into the row and classes the status", () => {
    const row = fakeRow();
    v.updateJobRow(row, { job: { kind: "import", label: "evtx", status: "running" }, detail: "3/10" });
    expect(row.cells[".job-kind"].textContent).toBe("import");
    expect(row.cells[".job-label"].textContent).toBe("evtx");
    expect(row.cells[".job-st"].className).toBe("job-st job-running");
    expect(row.cells[".job-detail"].textContent).toBe("3/10");
  });

  it("hides the detail cell when there is no detail, rather than leaving an empty gap", () => {
    const row = fakeRow();
    v.updateJobRow(row, { job: { kind: "k", status: "done" }, detail: "" });
    expect((row.cells[".job-detail"].style as Record<string, string>).display).toBe("none");
    expect(row.cells[".job-label"].textContent).toBe("");
  });

  // textContent, never innerHTML — the label is evidence-derived and the status comes off the wire.
  it("assigns through textContent so a job label cannot inject markup", () => {
    const row = fakeRow();
    v.updateJobRow(row, { job: { kind: "k", label: "<img src=x>", status: "done" }, detail: "" });
    expect(row.cells[".job-label"].textContent).toBe("<img src=x>");
  });
});

describe("deepPassResultKey / eventDeepLink", () => {
  it("namespaces the storage key by case", () => {
    expect(v.deepPassResultKey("c1")).toBe("dfir.deepPassResult:c1");
  });

  it("encodes both halves of a deep link", () => {
    expect(v.eventDeepLink("case 1", "ev&2")).toBe("?caseId=case%201#event=ev%262");
  });
});

describe("rvStatusLabel / analysisRunLabel", () => {
  it("title-cases a workflow status, spelling out peer-review", () => {
    expect(v.rvStatusLabel({ status: "peer-review" })).toBe("Peer review");
    expect(v.rvStatusLabel({ status: "final" })).toBe("Final");
    expect(v.rvStatusLabel(undefined)).toBe("Draft");
    expect(v.rvStatusLabel({})).toBe("Draft");
  });

  it("names an analysis run by kind, provider/model and start time", () => {
    const at = "2026-03-01T12:00:00Z";
    expect(
      v.analysisRunLabel({
        kind: "synthesis",
        configuration: { provider: "anthropic", model: "opus" },
        startedAt: at,
      }),
    ).toBe(`synthesis · anthropic/opus · ${new Date(at).toLocaleString()}`);
    expect(
      v.analysisRunLabel({ kind: "vision", configuration: { provider: "anthropic" }, startedAt: at }),
    ).toContain("vision · anthropic ·");
    expect(v.analysisRunLabel({ kind: "vision", startedAt: at })).toBe(
      `vision · ${new Date(at).toLocaleString()}`,
    );
  });
});

describe("fileToBase64", () => {
  it("resolves with the payload after the data: prefix", async () => {
    const sandbox = loadDashboardModule("dashboard-values.js", [], {
      FileReader: class {
        onload: (() => void) | null = null;
        onerror: (() => void) | null = null;
        result = "";
        readAsDataURL() {
          this.result = "data:application/octet-stream;base64,aGVsbG8=";
          this.onload?.();
        }
      },
    });
    await expect(sandbox.fileToBase64({})).resolves.toBe("aGVsbG8=");
  });

  it("rejects when the read fails", async () => {
    const sandbox = loadDashboardModule("dashboard-values.js", [], {
      FileReader: class {
        onerror: (() => void) | null = null;
        readAsDataURL() {
          this.onerror?.();
        }
      },
    });
    await expect(sandbox.fileToBase64({})).rejects.toThrow("read failed");
  });
});

// getClientRects() rather than an offsetParent or a class check, because it is the one test that
// covers every way an element can be invisible — display:none, a collapsed ancestor, `hidden`.
describe("paletteVisible / isSectionDataOpen / stabHidden", () => {
  it("treats an element with no client rects as not visible", () => {
    expect(v.paletteVisible({ getClientRects: () => [{}] })).toBe(true);
    expect(v.paletteVisible({ getClientRects: () => [] })).toBe(false);
    expect(v.paletteVisible(null)).toBe(false);
  });

  // Absent means open. A section is closed only when something has explicitly said so, so a
  // section rendered before the gate state loads is searchable rather than silently missing.
  it("treats a section with no gate attribute as open", () => {
    expect(v.isSectionDataOpen({ dataset: {} })).toBe(true);
    expect(v.isSectionDataOpen({ dataset: { gateOpen: "1" } })).toBe(true);
    expect(v.isSectionDataOpen({ dataset: { gateOpen: "0" } })).toBe(false);
  });

  it("hides a non-essential button only in essential mode", () => {
    const plain = { hasAttribute: () => false };
    const essential = { hasAttribute: () => true };
    expect(v.stabHidden(plain, "essential")).toBe(true);
    expect(v.stabHidden(essential, "essential")).toBe(false);
    expect(v.stabHidden(plain, "advanced")).toBe(false);
  });
});

describe("swCanvasXY", () => {
  // The canvas backing store is not the CSS box. Scaling the pointer by width/rect.width is what
  // keeps hit-testing correct on a HiDPI display or a resized swimlane.
  it("scales pointer coordinates from CSS pixels into canvas pixels", () => {
    const canvas = {
      width: 800,
      height: 400,
      getBoundingClientRect: () => ({ left: 10, top: 20, width: 400, height: 200 }),
    };
    expect(v.swCanvasXY({ clientX: 110, clientY: 70 }, canvas)).toEqual({ x: 200, y: 100 });
  });

  it("is the identity when the backing store matches the CSS box", () => {
    const canvas = {
      width: 400,
      height: 200,
      getBoundingClientRect: () => ({ left: 0, top: 0, width: 400, height: 200 }),
    };
    expect(v.swCanvasXY({ clientX: 5, clientY: 7 }, canvas)).toEqual({ x: 5, y: 7 });
  });
});

describe("wizFieldId", () => {
  it("prefixes an env key", () => {
    expect(v.wizFieldId("ANTHROPIC_API_KEY")).toBe("wizf-ANTHROPIC_API_KEY");
  });
});

describe("veloTimeScopeBody / veloTimeScopeIncomplete", () => {
  const form = (timescope: string, start = "", end = "") => ({
    querySelector: (sel: string) =>
      ({
        ".velo-timescope": { value: timescope },
        ".velo-ts-start": { value: start },
        ".velo-ts-end": { value: end },
      })[sel],
  });

  it("sends a preset when one is picked", () => {
    expect(v.veloTimeScopeBody(form("last24h"))).toEqual({ preset: "last24h" });
  });

  it("sends nothing when no scope is picked", () => {
    expect(v.veloTimeScopeBody(form(""))).toBeUndefined();
  });

  // The custom range appends ":00Z" — the picker's wall clock is UTC, matching isoToUtcInput's
  // contract on the other side of the dashboard.
  it("sends a custom range as UTC, with the end optional", () => {
    expect(v.veloTimeScopeBody(form("custom", "2026-03-01T00:00", "2026-03-02T00:00"))).toEqual({
      start: "2026-03-01T00:00:00Z",
      end: "2026-03-02T00:00:00Z",
    });
    expect(v.veloTimeScopeBody(form("custom", "2026-03-01T00:00"))).toEqual({
      start: "2026-03-01T00:00:00Z",
    });
  });

  it("reports a custom range with no start as incomplete, and nothing else", () => {
    expect(v.veloTimeScopeIncomplete(form("custom"))).toBe(true);
    expect(v.veloTimeScopeIncomplete(form("custom", "2026-03-01T00:00"))).toBe(false);
    expect(v.veloTimeScopeIncomplete(form("last24h"))).toBe(false);
  });

  it("sends nothing for a custom range with no start, matching the incomplete check", () => {
    expect(v.veloTimeScopeBody(form("custom"))).toBeUndefined();
  });
});

// The secret-blanking contract. A blank credential means "keep what is saved", so the dashboard
// never round-trips a redacted value back to the server as if it were the real one.
describe("ntfChannelToBody", () => {
  it("blanks the telegram bot token so the server keeps the saved one", () => {
    const body = v.ntfChannelToBody({
      type: "telegram",
      name: "n",
      telegram: { botToken: "•••", chatId: "5" },
    });
    expect(body.telegram).toEqual({ botToken: "", chatId: "5" });
  });

  it("blanks the SMTP password but carries the rest of the transport", () => {
    const body = v.ntfChannelToBody({
      type: "email",
      smtp: { host: "h", port: 587, secure: true, from: "a", to: "b", username: "u", password: "•••" },
    });
    expect(body.smtp.password).toBe("");
    expect(body.smtp).toMatchObject({ host: "h", port: 587, secure: true, username: "u" });
    expect(body.smtp.rejectUnauthorized).toBeUndefined();
  });

  it("carries rejectUnauthorized only when it was set, so the server default is not overwritten", () => {
    const body = v.ntfChannelToBody({ type: "email", smtp: { rejectUnauthorized: false } });
    expect(body.smtp.rejectUnauthorized).toBe(false);
  });

  it("blanks the webhook URL for every other channel type", () => {
    expect(v.ntfChannelToBody({ type: "slack", webhookUrl: "https://real" }).webhookUrl).toBe("");
    // A channel whose type says email/telegram but whose transport is missing falls through here
    // too, which is the safe direction: it sends no credential rather than a partial one.
    expect(v.ntfChannelToBody({ type: "telegram" }).webhookUrl).toBe("");
  });
});

describe("ntfEventsSummary", () => {
  it("lists the enabled event kinds in a fixed order", () => {
    expect(v.ntfEventsSummary({ mention: true, critical_finding: true, milestone: true })).toBe(
      "findings, milestones, mentions",
    );
    expect(v.ntfEventsSummary({ playbook_update: true })).toBe("playbook");
  });

  it("says nothing rather than rendering an empty list", () => {
    expect(v.ntfEventsSummary({})).toBe("nothing");
  });
});
