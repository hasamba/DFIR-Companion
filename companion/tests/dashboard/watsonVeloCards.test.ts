// Task 7: Watson Velociraptor launch cards, the connected chip, Auto attribution and the Auto listing.
import { describe, expect, it } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface Velo {
  watsonVeloCardHtml(p: unknown): string;
  watsonVeloAutoListHtml(text: string): string;
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
    const launched = { by: "Dana", at: "2026-11-14T10:00:00Z" };
    const card = (watch: unknown) => velo().watsonVeloCardHtml(base({ status: "applied", launched, watch }));
    const running = card({ deadline: "x", state: "watching" });
    expect(running).toContain("Launched by Dana at 2026-11-14T10:00:00Z");
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
