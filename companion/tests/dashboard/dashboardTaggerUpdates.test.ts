import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { STATIC_ASSETS } from "../../src/http/staticAssets.js";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// public/js/dashboard-tagger-updates.js — Content tagger → "your detection rules are older than the
// built-in set" (#2344): the notice, the review list, the conflict choice and the apply call.

const DASHBOARD = new URL("../../../public/dashboard.html", import.meta.url);

/** Just enough DOM for the module: elements with children, text, style and handlers. */
class FakeEl {
  children: FakeEl[] = [];
  hidden = false;
  type = "";
  name = "";
  checked = false;
  className = "";
  title = "";
  id = "";
  style = { color: "", cssText: "" };
  onclick: (() => unknown) | null = null;
  onchange: (() => unknown) | null = null;
  private text = "";
  constructor(readonly tag: string) {}
  get textContent(): string {
    return this.text + this.children.map((c) => c.textContent).join("");
  }
  set textContent(v: string) {
    this.text = v;
    this.children = [];
  }
  appendChild(c: FakeEl): FakeEl {
    this.children.push(c);
    return c;
  }
  all(): FakeEl[] {
    return [this, ...this.children.flatMap((c) => c.all())];
  }
}

interface Api {
  loadTaggerUpdates: () => Promise<void>;
  openTaggerUpdates: () => void;
  applyTaggerUpdates: () => Promise<void>;
  exportTaggerUpdates: () => Promise<void>;
  dismissTaggerUpdates: () => Promise<void>;
}

const side = (description: string, severity: string) => ({
  description,
  severity,
  yaml: `${description}: ${severity}\n`,
});

const VIEW = {
  source: "user",
  revision: "rev1",
  readOnly: false,
  dismissed: false,
  notice: true,
  tracked: true,
  upstreamId: "builtin",
  upstreamRevision: "0123456789abcdef",
  counts: { added: 2, changed: 1, conflicts: 1, removedByYou: 1 },
  added: [
    { key: "new_rule", uncertain: false, upstream: side("New rule", "High") },
    { key: "maybe_new", uncertain: true, upstream: side("Maybe new", "Medium") },
  ],
  changed: [
    { key: "chg", uncertain: false, upstream: side("Changed", "High"), mine: side("Changed", "Low") },
  ],
  conflicts: [
    { key: "both", uncertain: false, upstream: side("Both up", "High"), mine: side("Both mine", "Medium") },
  ],
  removedByYou: [{ key: "gone", uncertain: false, upstream: side("Gone", "Low") }],
};

function harness(view: Record<string, unknown>, applyStatus = 200, conflictReason = "copy") {
  const els: Record<string, FakeEl> = {
    taggerUpdatesNotice: new FakeEl("div"),
    taggerUpdatesPane: new FakeEl("div"),
  };
  els.taggerUpdatesNotice.hidden = true;
  els.taggerUpdatesPane.hidden = true;
  const calls: Array<{ url: string; body?: Record<string, unknown> }> = [];
  let ranTagger = 0;
  const api = loadDashboardModule<Api>("dashboard-tagger-updates.js", [], {
    document: {
      getElementById: (id: string) =>
        els[id] ??
        Object.values(els)
          .flatMap((e) => e.all())
          .find((e) => e.id === id) ??
        null,
      createElement: (tag: string) => new FakeEl(tag),
    },
    runTagger: () => {
      ranTagger += 1;
    },
    fetch: async (url: string, init?: { body?: string }) => {
      const body = init?.body ? JSON.parse(init.body) : undefined;
      calls.push({ url, body });
      if (url.endsWith("/apply")) {
        return applyStatus === 409
          ? {
              ok: false,
              status: 409,
              json: async () => ({ error: "stale", reason: conflictReason, revision: "rev2" }),
            }
          : { ok: true, status: 200, json: async () => ({ applied: ["new_rule"], kept: [], ruleCount: 9 }) };
      }
      if (url.endsWith("/export")) {
        return applyStatus === 409
          ? { ok: false, status: 409, json: async () => ({ error: "stale", reason: "upstream" }) }
          : { ok: true, status: 200, blob: async () => new Blob(["x: 1\n"]) };
      }
      if (url.endsWith("/dismiss")) return { ok: true, status: 200, json: async () => ({ dismissed: true }) };
      return { ok: true, status: 200, json: async () => view };
    },
  });
  const pane = () => els.taggerUpdatesPane;
  const button = (root: FakeEl, label: string) =>
    root.all().find((e) => e.tag === "button" && e.textContent === label);
  return { api, els, calls, pane, button, ranTagger: () => ranTagger };
}

describe("the rule-updates notice", () => {
  it("shows the added and changed counts for an outdated copy", async () => {
    const h = harness(VIEW);
    await h.api.loadTaggerUpdates();
    expect(h.els.taggerUpdatesNotice.hidden).toBe(false);
    expect(h.els.taggerUpdatesNotice.textContent).toContain(
      "Your detection rules are older than the built-in set: 2 added, 2 changed since your copy.",
    );
  });

  it("names an installed rule pack as what the copy is older than (#2349)", async () => {
    const h = harness({ ...VIEW, upstreamLabel: "rule pack rules-2026.11.05 (downloaded from GitHub)" });
    await h.api.loadTaggerUpdates();
    expect(h.els.taggerUpdatesNotice.textContent).toContain(
      "Your detection rules are older than the installed rule pack rules-2026.11.05 (downloaded from GitHub): 2 added",
    );
  });

  it("stays hidden when there is nothing new, and on a refused request", async () => {
    const h = harness({ source: "default", revision: "r", readOnly: false, dismissed: false, notice: false });
    await h.api.loadTaggerUpdates();
    expect(h.els.taggerUpdatesNotice.hidden).toBe(true);
  });

  it("dismisses at the built-in revision it was shown for", async () => {
    const h = harness(VIEW);
    await h.api.loadTaggerUpdates();
    await h.api.dismissTaggerUpdates();
    expect(h.calls.at(-1)).toEqual({
      url: "/tagger/rules/updates/dismiss",
      body: { upstreamRevision: "0123456789abcdef" },
    });
    expect(h.els.taggerUpdatesNotice.hidden).toBe(true);
  });
});

describe("the review list", () => {
  it("lists every group with description and grade, old and new for a changed rule", async () => {
    const h = harness(VIEW);
    await h.api.loadTaggerUpdates();
    h.api.openTaggerUpdates();
    const text = h.pane().textContent;
    expect(text).toContain("new_rule · High — New rule");
    expect(text).toContain("new, or removed by you");
    expect(text).toContain("chg: Low → High — Changed");
    expect(text).toContain("both: you and the built-in set both changed this rule");
    expect(text).toContain("Restore gone · Low — Gone — removed by you");
    expect(h.button(h.pane(), "Add new rules")).toBeDefined();
  });

  it("offers only the download for a read-only operator file", async () => {
    const h = harness({ ...VIEW, readOnly: true, source: "env" });
    await h.api.loadTaggerUpdates();
    h.api.openTaggerUpdates();
    expect(h.button(h.pane(), "Add new rules")).toBeUndefined();
    expect(h.button(h.pane(), "Download merged rules")).toBeDefined();
  });

  it("applies the default selection plus the analyst's conflict choice and restore, with the revision", async () => {
    const h = harness(VIEW);
    await h.api.loadTaggerUpdates();
    h.api.openTaggerUpdates();
    const radios = h
      .pane()
      .all()
      .filter((e) => e.type === "radio" && e.name === "tu-both");
    expect(radios).toHaveLength(2);
    expect(radios.some((r) => r.checked)).toBe(false); // a conflict is never pre-picked
    radios[0].onchange?.(); // Keep mine
    const restore = h
      .pane()
      .all()
      .find((e) => e.tag === "label" && e.textContent.startsWith("Restore gone"))!
      .children.find((e) => e.type === "checkbox")!;
    expect(restore.checked).toBe(false); // a deletion is never undone unasked
    restore.checked = true;
    restore.onchange?.();
    await h.api.applyTaggerUpdates();
    const apply = h.calls.find((c) => c.url === "/tagger/rules/updates/apply")!;
    expect(apply.body).toEqual({
      revision: "rev1",
      upstreamId: "builtin",
      upstreamRevision: "0123456789abcdef",
      choices: { new_rule: "upstream", chg: "upstream", both: "mine", gone: "upstream" },
    });
  });

  it("after applying, says open cases keep their grades and offers Run tagger, never running it itself", async () => {
    const h = harness(VIEW);
    await h.api.loadTaggerUpdates();
    h.api.openTaggerUpdates();
    await h.api.applyTaggerUpdates();
    const notice = h.els.taggerUpdatesNotice;
    expect(notice.textContent).toContain("Open cases keep their current grades until you press");
    expect(notice.textContent).toContain("Super-Timeline → Content tagger → Run tagger");
    expect(h.ranTagger()).toBe(0);
    h.button(notice, "Run tagger on this case")!.onclick!();
    expect(h.ranTagger()).toBe(1);
  });

  it("explains a stale review instead of applying", async () => {
    const h = harness(VIEW, 409);
    await h.api.loadTaggerUpdates();
    h.api.openTaggerUpdates();
    await h.api.applyTaggerUpdates();
    expect(h.pane().textContent).toContain("the rules changed since this review was loaded");
  });

  it("reloads the review and says so when the compared-with rules changed (pack installed or rolled back)", async () => {
    const h = harness(VIEW, 409, "upstream");
    await h.api.loadTaggerUpdates();
    h.api.openTaggerUpdates();
    const before = h.calls.filter((c) => c.url === "/tagger/rules/updates").length;
    await h.api.applyTaggerUpdates();
    expect(h.calls.filter((c) => c.url === "/tagger/rules/updates").length).toBe(before + 1);
    expect(h.pane().textContent).toContain("the rules your copy is compared with changed");
  });

  it("sends the reviewed revisions with a download, and reloads on a stale review", async () => {
    const h = harness({ ...VIEW, readOnly: true, source: "env" }, 409);
    await h.api.loadTaggerUpdates();
    h.api.openTaggerUpdates();
    const before = h.calls.filter((c) => c.url === "/tagger/rules/updates").length;
    await h.api.exportTaggerUpdates();
    const exp = h.calls.find((c) => c.url === "/tagger/rules/updates/export")!;
    expect(exp.body).toMatchObject({
      revision: "rev1",
      upstreamId: "builtin",
      upstreamRevision: "0123456789abcdef",
    });
    expect(h.calls.filter((c) => c.url === "/tagger/rules/updates").length).toBe(before + 1);
    expect(h.pane().textContent).toContain("Not downloaded");
  });

  it("lets a copy saved before tracking select every added rule in one click", async () => {
    const h = harness(VIEW);
    await h.api.loadTaggerUpdates();
    h.api.openTaggerUpdates();
    h.button(h.pane(), "Select all added rules")!.onclick!();
    await h.api.applyTaggerUpdates();
    const apply = h.calls.find((c) => c.url === "/tagger/rules/updates/apply")!;
    expect(apply.body?.choices).toMatchObject({ new_rule: "upstream", maybe_new: "upstream" });
    expect(apply.body?.choices).not.toHaveProperty("gone"); // removed-by-you is not part of "added"
  });
});

describe("wiring", () => {
  it("is loaded before the inline script, served, and has its panel in the Content tagger", async () => {
    const html = await readFile(DASHBOARD, "utf8");
    expect(html).toContain('<script src="/js/dashboard-tagger-updates.js"></script>');
    expect(html.indexOf('src="/js/dashboard-tagger-updates.js"')).toBeLessThan(
      html.lastIndexOf("<script nonce="),
    );
    expect(STATIC_ASSETS["/js/dashboard-tagger-updates.js"]).toMatch(/javascript/);
    expect(html).toContain('id="taggerUpdatesNotice"');
    expect(html).toContain('id="taggerUpdatesPane"');
  });
});
