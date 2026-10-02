import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// The per-finding containment check (#1925), driven the way the browser drives it: delegated
// click/change listeners on document, fetch answered by the test, the card re-rendered from state.
//
// What it pins: the chip appears only when Jev is configured; every suggested step starts unticked
// and Add stays off until the analyst ticks one; only ticked step ids travel, with the checkId; a
// step already in the Playbook cannot be ticked; flagged answers and the in-progress caveat are on
// screen; server strings are escaped; the busy flag comes off on failure; a stale check asks for a
// re-run; a case switch forgets every result.

interface Api {
  loadContainmentCheck(caseId: string): Promise<void>;
  containmentCheckChip(fid: string): string;
  containmentCheckPanel(fid: string): string;
  containmentAttributionHtml(task: unknown): string;
  containmentSyncPlaybook(tasks: unknown[]): void;
}

interface Deferred {
  url: string;
  method: string;
  body: string;
  resolve(body: unknown, init?: { ok?: boolean; status?: number }): void;
  reject(err: Error): void;
}

type Handler = (e: unknown) => void;

function harness() {
  const pending: Deferred[] = [];
  const handlers: Record<string, Handler[]> = {};
  const renders: unknown[] = [];
  const playbookLoads: string[] = [];
  const state = { caseId: "case-1" };
  const globals = {
    document: {
      getElementById: () => null,
      addEventListener: (type: string, fn: Handler) => {
        (handlers[type] ||= []).push(fn);
      },
    },
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
    render: (s: unknown) => renders.push(s),
    DfirState: { lastState: () => state },
    loadPlaybook: (caseId: string) => playbookLoads.push(caseId),
  };
  const api = loadDashboardModule<Api>("dashboard-containment-check.js", ["dashboard-escape.js"], globals);

  /** A fake element that matches exactly one selector. */
  const target = (selector: string, attrs: Record<string, string>, extra: Record<string, unknown> = {}) => {
    const self: Record<string, unknown> = {
      ...extra,
      getAttribute: (n: string) => attrs[n] ?? null,
    };
    self.closest = (sel: string) => (sel === selector ? self : null);
    return self;
  };
  const click = (selector: string, attrs: Record<string, string>) =>
    (handlers.click || []).forEach((f) => f({ target: target(selector, attrs) }));
  const change = (fid: string, step: string, checked: boolean) =>
    (handlers.change || []).forEach((f) =>
      f({
        target: target(".ccheck-step-cb", { "data-ccheck-fid": fid, "data-ccheck-step": step }, { checked }),
      }),
    );
  return { api, pending, renders, playbookLoads, click, change };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

const RESULT = {
  checkId: "chk-1",
  model: "typesafe/jev-1.13",
  checkedAt: "2026-10-02T10:20:30.000Z",
  answers: [
    {
      id: "credentials_exposed",
      label: "Credentials exposed",
      kind: "yesno",
      value: 0.82,
      verdict: "yes",
      checkManually: false,
    },
    {
      id: "persistence",
      label: "Persistence",
      kind: "yesno",
      value: 0.4,
      verdict: "unsure",
      checkManually: true,
    },
    {
      id: "in_progress",
      label: "Attack in progress",
      kind: "yesno",
      value: 0.7,
      verdict: "yes",
      checkManually: false,
    },
    { id: "reach", label: "Reach", kind: "choice", value: 0.55, verdict: "one_entity", checkManually: true },
  ],
  steps: [
    {
      id: "revoke-keys",
      title: "Reset the exposed credentials <b>now</b>",
      priority: "critical",
      basis: ["credentials_exposed"],
      basisLabels: ["Credentials exposed"],
      checkManually: false,
      inPlaybook: false,
    },
    {
      id: "isolate-host",
      title: "Isolate the host",
      priority: "critical",
      basis: ["persistence"],
      basisLabels: ["Persistence"],
      checkManually: true,
      inPlaybook: false,
    },
    {
      id: "require-reauth",
      title: "Require re-authentication",
      priority: "critical",
      basis: ["credentials_exposed"],
      basisLabels: ["Credentials exposed"],
      checkManually: false,
      inPlaybook: true,
      taskShortId: "PB-3",
    },
  ],
  coverage: { cited: 12, sent: 10, notInTimeline: 2, truncated: true },
  snapshotCaveat: "x",
  usage: {},
};

async function configured() {
  const h = harness();
  const load = h.api.loadContainmentCheck("case-1");
  const status = h.pending.shift()!;
  expect(status.url).toBe("/cases/case-1/jev/status");
  status.resolve({ configured: true, model: "typesafe/jev-1.13" });
  await load;
  return h;
}

async function withResult(result: unknown = RESULT, fid = "f1") {
  const h = await configured();
  h.click("[data-ccheck-run]", { "data-ccheck-run": fid });
  h.pending.shift()!.resolve(result);
  await settle();
  return h;
}

describe("the chip", () => {
  it("is hidden when Jev is not configured", async () => {
    const h = harness();
    const load = h.api.loadContainmentCheck("case-1");
    h.pending.shift()!.resolve({ configured: false, reason: "no key" });
    await load;
    expect(h.api.containmentCheckChip("f1")).toBe("");
  });

  it("is shown when Jev is configured, and carries the escaped finding id", async () => {
    const h = await configured();
    const chip = h.api.containmentCheckChip('f"1');
    expect(chip).toContain("Containment check");
    expect(chip).toContain('data-ccheck-run="f&quot;1"');
  });

  it("posts to the finding's route with encoded ids", async () => {
    const h = await configured();
    h.click("[data-ccheck-run]", { "data-ccheck-run": "f/1 x" });
    const req = h.pending.shift()!;
    expect(req.method).toBe("POST");
    expect(req.url).toBe("/cases/case-1/findings/f%2F1%20x/containment-check");
  });
});

describe("the panel", () => {
  it("shows every answer, flagged answers, and the in-progress caveat", async () => {
    const html = (await withResult()).api.containmentCheckPanel("f1");
    expect(html).toContain("Credentials exposed");
    expect(html).toContain("yes · 82% likely");
    expect(html).toContain("one entity (confidence 55%)");
    expect(html).toContain("check manually");
    expect(html).toContain("still in progress at the end of the collected evidence — not a live status");
    expect(html).toContain("10 of 12 cited events sent, 2 not in the forensic timeline + truncated");
    expect(html).toContain("because: Credentials exposed");
    expect(html).toContain("Advice only — nothing is run.");
  });

  it("starts every box unticked, and Add is off until one is ticked", async () => {
    const h = await withResult();
    const html = h.api.containmentCheckPanel("f1");
    expect(html).not.toMatch(/ccheck-step-cb[^>]*checked/);
    expect(html).toMatch(/data-ccheck-add="f1" disabled/);
    h.change("f1", "revoke-keys", true);
    expect(h.api.containmentCheckPanel("f1")).not.toMatch(/data-ccheck-add="f1" disabled/);
    h.change("f1", "revoke-keys", false);
    expect(h.api.containmentCheckPanel("f1")).toMatch(/data-ccheck-add="f1" disabled/);
  });

  it("shows a step already in the Playbook as such, with its box disabled", async () => {
    const html = (await withResult()).api.containmentCheckPanel("f1");
    expect(html).toMatch(/data-ccheck-step="require-reauth" disabled/);
    expect(html).toContain("in Playbook (PB-3)");
    expect(html).toMatch(/data-ccheck-step="revoke-keys" \/>/);
  });

  it("escapes server strings", async () => {
    const h = await withResult({
      ...RESULT,
      model: "<img src=x>",
      answers: [{ id: "a", label: "<script-ish>", kind: "yesno", value: 0.9, verdict: "yes" }],
    });
    const html = h.api.containmentCheckPanel("f1");
    expect(html).toContain("&lt;b&gt;now&lt;/b&gt;");
    expect(html).toContain("&lt;img src=x&gt;");
    expect(html).toContain("&lt;script-ish&gt;");
    expect(html).not.toContain("<b>now");
    expect(html).not.toContain("<img");
  });

  it("is busy while running, and the busy flag comes off on an error", async () => {
    const h = await configured();
    h.click("[data-ccheck-run]", { "data-ccheck-run": "f1" });
    expect(h.api.containmentCheckPanel("f1")).toContain("Running the containment check");
    expect(h.api.containmentCheckChip("f1")).toContain("disabled");
    h.pending.shift()!.resolve({ error: "Jev containment check failed: 401" }, { ok: false, status: 502 });
    await settle();
    const html = h.api.containmentCheckPanel("f1");
    expect(html).not.toContain("Running the containment check");
    expect(html).toContain("Jev containment check failed: 401");
    expect(h.api.containmentCheckChip("f1")).not.toContain("disabled");
  });

  it("clears the busy flag when the request itself fails", async () => {
    const h = await configured();
    h.click("[data-ccheck-run]", { "data-ccheck-run": "f1" });
    h.pending.shift()!.reject(new Error("network down"));
    await settle();
    expect(h.api.containmentCheckPanel("f1")).toContain("network down");
    expect(h.api.containmentCheckChip("f1")).not.toContain("disabled");
  });

  it("turns a 501 into the Settings pointer", async () => {
    const h = await configured();
    h.click("[data-ccheck-run]", { "data-ccheck-run": "f1" });
    h.pending.shift()!.resolve({ error: "no key" }, { ok: false, status: 501 });
    await settle();
    expect(h.api.containmentCheckPanel("f1")).toContain("Settings → AI");
  });
});

describe("adding to the Playbook", () => {
  it("posts only the ticked step ids, with the checkId", async () => {
    const h = await withResult();
    h.change("f1", "isolate-host", true);
    h.click("[data-ccheck-add]", { "data-ccheck-add": "f1" });
    const req = h.pending.shift()!;
    expect(req.method).toBe("POST");
    expect(req.url).toBe("/cases/case-1/findings/f1/containment-check/playbook");
    expect(JSON.parse(req.body)).toEqual({ checkId: "chk-1", steps: ["isolate-host"] });
  });

  it("marks added steps as in the Playbook and refreshes the Playbook", async () => {
    const h = await withResult();
    h.change("f1", "revoke-keys", true);
    h.change("f1", "isolate-host", true);
    h.click("[data-ccheck-add]", { "data-ccheck-add": "f1" });
    h.pending.shift()!.resolve({
      added: [{ id: "t1", containmentCheck: { stepId: "revoke-keys" } }],
      alreadyInPlaybook: ["isolate-host"],
    });
    await settle();
    const html = h.api.containmentCheckPanel("f1");
    expect(html).toMatch(/data-ccheck-step="revoke-keys" disabled/);
    expect(html).toMatch(/data-ccheck-step="isolate-host" disabled/);
    expect(html).toMatch(/data-ccheck-add="f1" disabled/);
    expect(h.playbookLoads).toEqual(["case-1"]);
  });

  it("asks for a re-run on a 409 rerun answer", async () => {
    const h = await withResult();
    h.change("f1", "revoke-keys", true);
    h.click("[data-ccheck-add]", { "data-ccheck-add": "f1" });
    h.pending.shift()!.resolve({ error: "stale", rerun: true }, { ok: false, status: 409 });
    await settle();
    expect(h.api.containmentCheckPanel("f1")).toContain(
      "The check result expired or the finding changed — run the check again.",
    );
  });

  it("follows the Playbook: a deleted task frees its step", async () => {
    const h = await withResult();
    h.api.containmentSyncPlaybook([]);
    expect(h.api.containmentCheckPanel("f1")).not.toMatch(/data-ccheck-step="require-reauth" disabled/);
    h.api.containmentSyncPlaybook([{ relatedFindingId: "f1", containmentCheck: { stepId: "isolate-host" } }]);
    expect(h.api.containmentCheckPanel("f1")).toMatch(/data-ccheck-step="isolate-host" disabled/);
  });
});

describe("a case switch", () => {
  it("clears every check result", async () => {
    const h = await withResult();
    expect(h.api.containmentCheckPanel("f1")).not.toBe("");
    void h.api.loadContainmentCheck("case-2");
    expect(h.api.containmentCheckPanel("f1")).toBe("");
    expect(h.api.containmentCheckChip("f1")).toBe("");
  });

  it("drops a check answer that arrives after the switch", async () => {
    const h = await configured();
    h.click("[data-ccheck-run]", { "data-ccheck-run": "f1" });
    const req = h.pending.shift()!;
    const load = h.api.loadContainmentCheck("case-2");
    h.pending.shift()!.resolve({ configured: true });
    await load;
    req.resolve(RESULT);
    await settle();
    expect(h.api.containmentCheckPanel("f1")).toBe("");
  });
});

describe("the Playbook attribution line", () => {
  it("names the model, the date and the basis answers, with check-manually marked", () => {
    const h = harness();
    const html = h.api.containmentAttributionHtml({
      title: "Isolate the host",
      containmentCheck: {
        kind: "jev-containment",
        model: "typesafe/jev-1.13",
        checkedAt: "2026-10-02T10:20:30.000Z",
        findingId: "f1",
        stepId: "isolate-host",
        basis: ["persistence"],
        answers: [
          {
            id: "persistence",
            label: "Persistence <x>",
            kind: "yesno",
            value: 0.4,
            verdict: "unsure",
            checkManually: true,
          },
          {
            id: "reach",
            label: "Reach",
            kind: "choice",
            value: 0.8,
            verdict: "workgroup",
            checkManually: false,
          },
        ],
        inProgressCaveat: true,
      },
    });
    expect(html).toContain("typesafe/jev-1.13");
    expect(html).toContain("2026-10-02 10:20");
    expect(html).toContain("Persistence &lt;x&gt;: unsure · 40% likely");
    expect(html).toContain("check manually");
    expect(html).not.toContain("Reach");
    expect(html).toContain("not a live status");
  });

  it("is empty for a task without a containment check", () => {
    expect(harness().api.containmentAttributionHtml({ title: "x" })).toBe("");
  });
});
