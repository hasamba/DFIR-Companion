import { readFileSync } from "node:fs";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

// The Case Details form sends the version it opened (baseUpdatedAt), so a save cannot overwrite
// report text Watson wrote (or another analyst saved) after the form loaded; on 409 it says so.

const source = readFileSync(join(__dirname, "../../../public/js/dashboard-report-meta.js"), "utf8");

type El = { value: string; checked: boolean; textContent: string; style: Record<string, string> };

function load(status: number, body: unknown = {}) {
  const els = new Map<string, El>();
  const sent: { url: string; init?: { body?: string } }[] = [];
  const el = (id: string): El => {
    if (!els.has(id)) {
      els.set(id, { value: id === "caseId" ? "c1" : "", checked: true, textContent: "", style: {} });
    }
    return els.get(id) as El;
  };
  const win: Record<string, unknown> = {};
  runInNewContext(source, {
    window: win,
    document: { getElementById: (id: string) => withRemove(el(id)) },
    fetch: async (url: string, init?: { body?: string }) => {
      sent.push({ url, init });
      return { ok: status < 400, status, json: async () => body };
    },
    rowsToText: () => "",
    linesToArray: () => [],
    parseRows: () => [],
    setTimeout: () => 0,
  });
  return { win, sent, el };
}

function withRemove(target: El): El & { removeAttribute(): void } {
  return Object.assign(target, { removeAttribute: () => undefined });
}

const flush = () => new Promise((r) => setTimeout(r, 0));

describe("Case Details form version check", () => {
  it("sends the updatedAt it was filled with as baseUpdatedAt", async () => {
    const { win, sent } = load(200, { updatedAt: "2026-03-01T10:00:00.001Z" });
    (win.fillReportMeta as (m: unknown) => void)({ updatedAt: "2026-03-01T10:00:00.000Z" });
    (win.saveReportMeta as () => void)();
    await flush();
    expect(JSON.parse(sent[0].init?.body ?? "{}").baseUpdatedAt).toBe("2026-03-01T10:00:00.000Z");
  });

  it("a never-saved case sends an empty base", async () => {
    const { win, sent } = load(200);
    (win.fillReportMeta as (m: unknown) => void)({});
    (win.saveReportMeta as () => void)();
    await flush();
    expect(JSON.parse(sent[0].init?.body ?? "{}").baseUpdatedAt).toBe("");
  });

  it("on 409 tells the analyst to reload", async () => {
    const { win, el } = load(409, { error: "stale" });
    (win.fillReportMeta as (m: unknown) => void)({ updatedAt: "2026-03-01T10:00:00.000Z" });
    (win.saveReportMeta as () => void)();
    await flush();
    await flush();
    expect(el("rmStatus").textContent).toBe("Report details changed since you opened them — reload");
  });
});
