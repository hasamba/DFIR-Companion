// Task 7: Watson Velociraptor launch cards, the connected chip, Auto attribution and the Auto listing.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";
import { listingTurns } from "../../src/analysis/ai/watson/autoApply.js";

interface Velo {
  watsonVeloCardHtml(p: unknown): string;
  watsonVeloAutoListHtml(text: string): string;
  watsonVeloChipSync(chat: unknown): void;
  watsonVeloResolve(el: unknown): Promise<void>;
  watsonVeloRiskArm(el: unknown): void;
  watsonVeloRiskCancel(el: unknown): void;
  watsonVeloApplyRisk(el: unknown): Promise<void>;
}
interface Cards {
  watsonCardHtml(p: unknown): string;
}
interface Marks {
  watsonMarksSet(p: unknown[]): void;
  watsonMarkHtml(kind: string, id: string, item?: unknown): string;
}

const HOSTILE = "<img src=x onerror=1>";
const globals = {
  document: { getElementById: () => null, querySelector: () => null, querySelectorAll: () => [] },
};
const velo = () => loadDashboardModule<Velo>("dashboard-watson-velo.js", ["dashboard-escape.js"], globals);

const base = (over: Record<string, unknown> = {}) => ({
  id: "wp-velo-1",
  turnId: "t1",
  kind: "velo_launch",
  status: "pending",
  targetId: "t",
  mode: "collection",
  hostname: "host-a.example.com",
  title: "Collect autoruns",
  vql: "SELECT * FROM Artifact.Windows.Sys.Autoruns()",
  fingerprint: "f",
  fingerprints: ["f"],
  ...over,
});

describe("watsonVeloCardHtml", () => {
  it("draws a collection card with Launch and Reject", () => {
    const h = velo().watsonVeloCardHtml(base());
    expect(h).toContain("Collection on host-a.example.com");
    expect(h).toContain("Collect autoruns");
    expect(h).toContain('<pre class="watson-pre">SELECT * FROM Artifact.Windows.Sys.Autoruns()</pre>');
    expect(h).toContain('data-w-verb="copy"');
    expect(h).toContain(">Launch</button>");
    expect(h).toContain(">Reject</button>");
  });

  it("names a fleet hunt", () => {
    expect(velo().watsonVeloCardHtml(base({ mode: "hunt", hostname: undefined }))).toContain(
      "Fleet-wide hunt — all enrolled clients",
    );
  });

  it("escapes hostile title, VQL, host and error text", () => {
    const h = velo().watsonVeloCardHtml(
      base({ title: HOSTILE, vql: HOSTILE, hostname: HOSTILE, uiError: HOSTILE, id: '"><x' }),
    );
    expect(h).not.toContain("<img");
    expect(h).not.toContain('"><x');
    expect(h).toContain("&lt;img");
  });

  it("shows launching without buttons", () => {
    const h = velo().watsonVeloCardHtml(base({ status: "launching" }));
    expect(h).toContain("Launching…");
    expect(h).not.toContain(
      '<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="apply"',
    );
    expect(h).not.toContain('data-w-verb="reject"');
  });

  it("shows who launched, the live status and no Undo", () => {
    const launched = { by: "Dana", at: "2026-11-14T10:00:00Z", flowId: "F.SAMPLE", clientId: "C.webserver1" };
    const card = (watch: unknown) => velo().watsonVeloCardHtml(base({ status: "applied", launched, watch }));
    const running = card({ deadline: "x", state: "watching" });
    expect(running).toContain("Launched by Dana at ");
    expect(running).toContain('title="2026-11-14T10:00:00Z"');
    expect(running).toContain("Running");
    expect(running).toContain("cannot be undone");
    expect(running).not.toContain('data-w-verb="undo"');
    expect(card({ deadline: "x", state: "finished", rows: 12 })).toContain("Collected 12 rows");
    expect(card({ deadline: "x", state: "finished", rows: 0 })).toContain("Found nothing");
    expect(card({ deadline: "x", state: "finished", rows: 500, truncated: true, total: 900 })).toContain(
      "row cap",
    );
    expect(card({ deadline: "x", state: "failed", error: HOSTILE })).toContain("&lt;img");
    expect(card({ deadline: "x", state: "timeout" })).toContain("Timed out");
  });

  it("a launch marked as launched (no ids) never claims to be running (G8)", () => {
    const launched = { by: "Dana", at: "2026-11-14T10:00:00Z" };
    const h = velo().watsonVeloCardHtml(base({ status: "applied", launched }));
    expect(h).toContain(
      "Marked as launched. Watson does not know this run&#39;s id and will not read its result; import it from Velociraptor.",
    );
    expect(h).not.toContain("Running");
  });

  it("a launching card no live request owns offers the uncertain answers (G11)", () => {
    const h = velo().watsonVeloCardHtml(base({ status: "launching", stalled: true }));
    expect(h).toContain("interrupted");
    expect(h).toContain('data-outcome="launched"');
    expect(h).toContain('data-outcome="retry"');
    expect(h).not.toContain("Launching…");
  });

  it("an uncertain launch explains itself and offers both answers", () => {
    const h = velo().watsonVeloCardHtml(base({ status: "uncertain" }));
    expect(h).toContain(
      "Watson cannot tell whether this ran. Check Velociraptor, then mark it launched or try again.",
    );
    expect(h).toContain('data-outcome="launched"');
    expect(h).toContain('data-outcome="retry"');
    expect(h).toContain("Mark as launched");
    expect(h).toContain("Try again");
  });

  it("greys a rejected card with no buttons", () => {
    const h = velo().watsonVeloCardHtml(base({ status: "rejected" }));
    expect(h).toContain("watson-rejected");
    expect(h).not.toContain(
      '<button type="button" class="watson-mini" data-act="watsonAct" data-w-verb="reject"',
    );
  });

  it("uses no inline handlers or style attributes", () => {
    for (const s of ["pending", "uncertain", "applied", "rejected"]) {
      const h = velo().watsonVeloCardHtml(base({ status: s }));
      expect(h).not.toMatch(/\son[a-z]+=|style=/i);
    }
  });
});

describe("card dispatch and Auto", () => {
  it("watsonCardHtml hands velo_launch to the velo card", () => {
    const api = loadDashboardModule<Cards>(
      "dashboard-watson-cards.js",
      ["dashboard-escape.js", "dashboard-watson-velo.js"],
      globals,
    );
    expect(api.watsonCardHtml(base())).toContain("Velociraptor launch");
  });

  it("a held-events card says it is waiting for approval while pending", () => {
    const api = loadDashboardModule<Cards>("dashboard-watson-cards.js", ["dashboard-escape.js"], globals);
    const held = (status: string) =>
      api.watsonCardHtml({
        id: "h",
        kind: "event_promote",
        status,
        events: [{ severity: "High", description: "d" }],
      });
    expect(held("pending")).toContain("Waiting for your approval");
    expect(held("applied")).not.toContain("Waiting for your approval");
  });

  it("the badge title names Watson (Auto)", () => {
    const api = loadDashboardModule<Marks>("dashboard-watson-marks.js", ["dashboard-escape.js"], globals);
    api.watsonMarksSet([
      { id: "p", kind: "next_step_new", status: "applied", targetId: "s1", appliedBy: "Watson (Auto)" },
    ]);
    const h = api.watsonMarkHtml("next_step", "s1");
    expect(h).toContain("Added by Watson (Auto)");
    expect(h).toContain('data-w-verb="undo"');
  });

  it("draws the Auto listing as a list with the VQL in a pre, escaped", () => {
    const text = [
      "Watson acted on its own (Auto mode, switched on by Dana):",
      "- Launched collection on host-a.example.com: Collect autoruns",
      "  VQL:",
      `SELECT '${HOSTILE}' FROM x`,
      "- Added next step: check backups",
    ].join("\n");
    const h = velo().watsonVeloAutoListHtml(text);
    expect(h).toContain("<ul");
    expect(h.match(/<li>/g)).toHaveLength(2);
    expect(h).toContain('<pre class="watson-pre">SELECT');
    expect(h).not.toContain("<img");
  });

  it("leaves ordinary system turns alone", () => {
    expect(velo().watsonVeloAutoListHtml("Watson reacted to a new import")).toBe("");
  });
});

describe("chip, launch time, listing and resolve", () => {
  const chipEnv = () => {
    const slot = { innerHTML: "" };
    const document = {
      getElementById: () => ({ value: "case-1" }),
      querySelectorAll: () => [slot],
      createElement: () => ({ setAttribute() {}, className: "", textContent: "" }),
    };
    return { slot, document };
  };

  it("keeps the chip when a proposal reply carries no veloConnected", () => {
    const { slot, document } = chipEnv();
    const api = loadDashboardModule<Velo>("dashboard-watson-velo.js", ["dashboard-escape.js"], { document });
    api.watsonVeloChipSync({ veloConnected: true });
    expect(slot.innerHTML).toContain("Velociraptor connected");
    api.watsonVeloChipSync({ proposals: [] });
    expect(slot.innerHTML).toContain("Velociraptor connected");
    api.watsonVeloChipSync({ veloConnected: false });
    expect(slot.innerHTML).toBe("");
  });

  it("a case switch clears the chip until the new case's GET (G19)", () => {
    const { slot, document } = chipEnv();
    const api = loadDashboardModule<Velo & { watsonCaseReset(): void }>(
      "dashboard-watson-velo.js",
      ["dashboard-escape.js"],
      { document },
    );
    api.watsonVeloChipSync({ veloConnected: true });
    expect(slot.innerHTML).toContain("Velociraptor connected");
    api.watsonCaseReset();
    expect(slot.innerHTML).toBe("");
  });

  it("shows the launch time friendly with the ISO value in an escaped title", () => {
    const iso = "2026-11-14T10:00:00Z";
    const h = velo().watsonVeloCardHtml(base({ status: "applied", launched: { by: "Dana", at: iso } }));
    expect(h).toContain(`title="${iso}"`);
    expect(h).toContain(new Date(iso).toLocaleString());
    const bad = velo().watsonVeloCardHtml(base({ status: "applied", launched: { by: "Dana", at: HOSTILE } }));
    expect(bad).not.toContain("<img");
  });

  it("parses the text the real listingTurns writes", () => {
    const vql = "SELECT 1 FROM info()";
    const [turn] = listingTurns("Dana", [
      { line: "- Launched collection on host-a.example.com: Collect autoruns", vql },
      { line: "- Added next step: check backups" },
    ]);
    const h = velo().watsonVeloAutoListHtml(turn);
    expect(h).toContain("<ul");
    expect(h.match(/<li>/g)).toHaveLength(2);
    expect(h).toContain(`<pre class="watson-pre">${vql}</pre>`);
    expect(h).toContain("Added next step: check backups");
    const [more] = listingTurns("Dana", [{ line: "x".repeat(10) }]);
    expect(velo().watsonVeloAutoListHtml(more)).toContain("<ul");
  });

  const resolveEnv = (fetch: unknown) => {
    const msg = { className: "", textContent: "", setAttribute() {} };
    const host = { querySelector: () => null, appendChild: () => {} };
    const document = {
      getElementById: () => ({ value: "case-1" }),
      querySelectorAll: () => [],
      createElement: () => msg,
    };
    const api = loadDashboardModule<Velo>("dashboard-watson-velo.js", ["dashboard-escape.js"], {
      document,
      fetch,
      renderWatson: () => {},
    });
    const el = { dataset: { pid: "wp 1", outcome: "retry" }, parentElement: host };
    return { api, el, msg };
  };

  it("posts the outcome to the resolve route", async () => {
    const calls: unknown[][] = [];
    const fetch = async (...a: unknown[]) => {
      calls.push(a);
      return { ok: true, json: async () => ({ chat: {} }) };
    };
    const { api, el } = resolveEnv(fetch);
    await api.watsonVeloResolve(el);
    expect(calls[0][0]).toBe("/cases/case-1/watson/proposals/wp%201/resolve");
    const init = calls[0][1] as { method: string; body: string };
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({ outcome: "retry" });
  });

  it("shows a refusal through textContent", async () => {
    const fetch = async () => ({ ok: false, status: 409, json: async () => ({ error: HOSTILE }) });
    const { api, el, msg } = resolveEnv(fetch);
    await api.watsonVeloResolve(el);
    expect(msg.textContent).toContain(HOSTILE);
  });

  it("posts acceptRisk:true to the apply route for a confirmed risky launch (Task 9)", async () => {
    const calls: unknown[][] = [];
    const fetch = async (...a: unknown[]) => {
      calls.push(a);
      return { ok: true, json: async () => ({ chat: {} }) };
    };
    const { api, el } = resolveEnv(fetch);
    await api.watsonVeloApplyRisk(el);
    expect(calls[0][0]).toBe("/cases/case-1/watson/proposals/wp%201/apply");
    const init = calls[0][1] as { method: string; body: string };
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({ acceptRisk: true });
  });

  it("a refused risky launch shows the server message through textContent", async () => {
    const fetch = async () => ({ ok: false, status: 409, json: async () => ({ error: HOSTILE }) });
    const { api, el, msg } = resolveEnv(fetch);
    await api.watsonVeloApplyRisk(el);
    expect(msg.textContent).toContain(HOSTILE);
  });
});

describe("risky launch cards (Task 9)", () => {
  const RISK = { reasons: ["runs a program on the endpoint (execve)", HOSTILE], checks: ["x"] };

  it("a risky pending card shows the red warning and asks for review instead of Launch", () => {
    const h = velo().watsonVeloCardHtml(base({ risk: RISK }));
    expect(h).toContain("Risky query — runs a program on the endpoint (execve)");
    expect(h).toContain("safety check would normally block this. Read the query before approving.");
    expect(h).toContain("watson-risk");
    expect(h).not.toContain("<img");
    expect(h).toContain('data-w-verb="riskArm"');
    expect(h).not.toContain(">Launch</button>");
    expect(h).toContain(">Reject</button>");
  });

  it("arming shows an inline second confirmation; cancel takes it away", () => {
    const api = velo();
    const el = { dataset: { pid: "wp-velo-1" } };
    api.watsonVeloRiskArm(el);
    const armed = api.watsonVeloCardHtml(base({ risk: RISK }));
    expect(armed).toContain('data-w-verb="applyRisk"');
    expect(armed).toContain('data-w-verb="riskCancel"');
    expect(armed).toContain('role="group"');
    api.watsonVeloRiskCancel(el);
    expect(api.watsonVeloCardHtml(base({ risk: RISK }))).not.toContain('data-w-verb="applyRisk"');
  });

  it("a launched risky card says who approved it despite the warning", () => {
    const h = velo().watsonVeloCardHtml(
      base({
        status: "applied",
        risk: RISK,
        launched: {
          huntId: "H.1",
          at: "2026-11-14T00:00:00Z",
          by: "Dana",
          riskAccepted: { by: HOSTILE, at: "2026-11-14T00:00:00Z", reasons: RISK.reasons },
        },
      }),
    );
    expect(h).toContain("despite the warning");
    expect(h).not.toContain("<img");
    expect(h).not.toContain('data-w-verb="riskArm"');
  });

  it("a safe card still shows Launch and no warning", () => {
    const h = velo().watsonVeloCardHtml(base());
    expect(h).toContain(">Launch</button>");
    expect(h).not.toContain("Risky query");
  });
});

describe("refusal and risk notes in a Watson turn (Task 9, M-2, M-3)", () => {
  const view = () =>
    loadDashboardModule<{ watsonTurnHtml(t: unknown, p: unknown[], ro?: boolean): string }>(
      "dashboard-watson-view.js",
      ["dashboard-escape.js"],
      { ...globals, watsonWroteHtml: () => "" },
    );
  const NOTE = "(Nothing to approve: this collection already ran on the case, so Watson proposed nothing.)";
  const turn = (text: string, veloNote?: string) => ({
    id: "t1",
    at: "2026-11-14T00:00:00Z",
    role: "watson",
    text,
    ...(veloNote ? { veloNote } : {}),
  });

  it("draws the server's veloNote as its own warning block, apart from Watson's promise", () => {
    const h = view().watsonTurnHtml(turn(`Approve it in the request panel. ${HOSTILE}\n\n${NOTE}`, NOTE), []);
    expect(h).toContain('class="watson-why watson-warn watson-note"');
    expect(h).toContain("(Nothing to approve: this collection already ran on the case");
    expect(h.split("Nothing to approve").length).toBe(2); // shown once, not twice
    expect(h).not.toContain("<img");
  });

  it("Watson's own text cannot forge a note block", () => {
    const h = view().watsonTurnHtml(turn(`ok\n\n${NOTE}`), []);
    expect(h).not.toContain("watson-note");
  });

  it("shows the note when Watson's reply text is empty", () => {
    const h = view().watsonTurnHtml(turn(NOTE, NOTE), []);
    expect(h).toContain("watson-note");
    expect(h.split("Nothing to approve").length).toBe(2);
  });

  it("a plain turn has no note block", () => {
    expect(view().watsonTurnHtml(turn("Just text."), [])).not.toContain("watson-note");
  });
});

describe("risky card fixes (M-4, M-5, M-7)", () => {
  const RISK = { reasons: ["runs a program on the endpoint (execve)"], checks: ["x"] };

  it("a risk with no reasons is still a risky card (decided by the risk field)", () => {
    const h = velo().watsonVeloCardHtml(base({ risk: { reasons: [], checks: [] } }));
    expect(h).toContain("Risky query");
    expect(h).toContain('data-w-verb="riskArm"');
    expect(h).not.toContain(">Launch</button>");
  });

  const armedEnv = (fetch: unknown) => {
    const msg = { className: "", textContent: "", setAttribute() {} };
    const host = { querySelector: () => null, appendChild: () => {} };
    const document = {
      getElementById: () => ({ value: "case-1" }),
      querySelectorAll: () => [],
      createElement: () => msg,
    };
    const api = loadDashboardModule<Velo>("dashboard-watson-velo.js", ["dashboard-escape.js"], {
      document,
      fetch,
      renderWatson: () => {},
    });
    const el = { dataset: { pid: "wp-velo-1" }, parentElement: host, disabled: false };
    return { api, el };
  };

  it("Yes, launch it is disabled while the request runs; a second click sends nothing", async () => {
    let release: (v: unknown) => void = () => {};
    const calls: unknown[] = [];
    const fetch = (...a: unknown[]) => {
      calls.push(a);
      return new Promise((r) => (release = r));
    };
    const { api, el } = armedEnv(fetch);
    api.watsonVeloRiskArm(el);
    const first = api.watsonVeloApplyRisk(el);
    expect(el.disabled).toBe(true);
    expect(api.watsonVeloCardHtml(base({ risk: RISK }))).toMatch(/data-w-verb="applyRisk"[^>]*disabled/);
    await api.watsonVeloApplyRisk(el);
    expect(calls).toHaveLength(1);
    release({ ok: true, json: async () => ({ chat: {} }) });
    await first;
    expect(el.disabled).toBe(false);
  });

  it("after a refused or uncertain launch the card asks for the second confirmation again", async () => {
    const fetch = async () => ({ ok: false, status: 409, json: async () => ({ error: "uncertain" }) });
    const { api, el } = armedEnv(fetch);
    api.watsonVeloRiskArm(el);
    await api.watsonVeloApplyRisk(el);
    expect(el.disabled).toBe(true); // the stale "Yes" cannot be clicked again before the re-render
    const h = api.watsonVeloCardHtml(base({ risk: RISK }));
    expect(h).not.toContain('data-w-verb="applyRisk"');
    expect(h).toContain('data-w-verb="riskArm"');
  });

  it("a card that is no longer pending forgets its armed state", () => {
    const { api, el } = armedEnv(async () => ({}));
    api.watsonVeloRiskArm(el);
    api.watsonVeloCardHtml(base({ risk: RISK, status: "uncertain" }));
    expect(api.watsonVeloCardHtml(base({ risk: RISK }))).not.toContain('data-w-verb="applyRisk"');
  });
});
