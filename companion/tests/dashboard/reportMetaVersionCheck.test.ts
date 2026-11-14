import { readFileSync } from "node:fs";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

// The Case Details form sends the version it opened (baseUpdatedAt), so a save cannot overwrite
// report text Watson wrote (or another analyst saved) after the form loaded; on 409 it says so.
// A save from a form never loaded for this case (the Executive Summary "Save") loads it first.

const source = readFileSync(join(__dirname, "../../../public/js/dashboard-report-meta.js"), "utf8");

type El = { value: string; checked: boolean; textContent: string; style: Record<string, string> };
type Sent = { url: string; method: string; body: Record<string, unknown> };
type Api = {
  loadReportMeta(caseId: string): Promise<void>;
  saveReportMeta(edits?: Record<string, string>): Promise<void>;
};

const STORED = {
  organization: "ExampleCorp",
  conclusions: "Analyst words",
  updatedAt: "2026-03-01T10:00:00.000Z",
};

function load(opts: { getBody?: unknown; putStatus?: number } = {}) {
  const els = new Map<string, El>();
  const sent: Sent[] = [];
  const el = (id: string): El => {
    if (!els.has(id)) {
      els.set(id, { value: id === "caseId" ? "c1" : "", checked: true, textContent: "", style: {} });
    }
    return els.get(id) as El;
  };
  const win: Record<string, unknown> = {};
  runInNewContext(source, {
    window: win,
    // querySelectorAll feeds the form's unsaved-edits key (formKey); no form fields in this harness.
    document: { getElementById: (id: string) => withRemove(el(id)), querySelectorAll: () => [] },
    fetch: async (url: string, init?: { method?: string; body?: string }) => {
      const method = init?.method ?? "GET";
      const body = init?.body ? (JSON.parse(init.body) as Record<string, unknown>) : {};
      sent.push({ url, method, body });
      const status = method === "PUT" ? (opts.putStatus ?? 200) : 200;
      const reply =
        method === "PUT" ? { ...body, updatedAt: "2026-03-01T10:00:00.001Z" } : (opts.getBody ?? STORED);
      return { ok: status < 400, status, json: async () => reply };
    },
    rowsToText: () => "",
    linesToArray: () => [],
    parseRows: () => [],
    setTimeout: () => 0,
  });
  return { api: win as unknown as Api, sent, el };
}

function withRemove(target: El): El & { removeAttribute(): void } {
  return Object.assign(target, { removeAttribute: () => undefined });
}

describe("Case Details form version check", () => {
  it("sends the updatedAt it was loaded with as baseUpdatedAt", async () => {
    const { api, sent } = load();
    await api.loadReportMeta("c1");
    await api.saveReportMeta();
    const put = sent.filter((s) => s.method === "PUT");
    expect(put).toHaveLength(1);
    expect(put[0].body.baseUpdatedAt).toBe(STORED.updatedAt);
  });

  it("a never-saved case sends an empty base", async () => {
    const { api, sent } = load({ getBody: {} });
    await api.loadReportMeta("c1");
    await api.saveReportMeta();
    expect(sent.find((s) => s.method === "PUT")?.body.baseUpdatedAt).toBe("");
  });

  it("on 409 tells the analyst to reload", async () => {
    const { api, el } = load({ putStatus: 409 });
    await api.loadReportMeta("c1");
    await api.saveReportMeta();
    expect(el("rmStatus").textContent).toBe("Report details changed since you opened them — reload");
  });

  it("a save from a never-loaded form loads the stored details first, then applies the edit", async () => {
    const { api, sent } = load();
    await api.saveReportMeta({ "rm-executiveSummary": "Watson-free summary" });
    expect(sent.map((s) => s.method)).toEqual(["GET", "PUT"]);
    const put = sent[1].body;
    expect(put.baseUpdatedAt).toBe(STORED.updatedAt);
    expect(put.organization).toBe("ExampleCorp");
    expect(put.conclusions).toBe("Analyst words");
    expect(put.executiveSummary).toBe("Watson-free summary");
  });

  it("a form loaded for another case is loaded again before saving", async () => {
    const { api, sent, el } = load();
    await api.loadReportMeta("c0");
    el("caseId").value = "c1";
    await api.saveReportMeta();
    expect(sent.map((s) => `${s.method} ${s.url}`)).toEqual([
      "GET /cases/c0/report-meta",
      "GET /cases/c1/report-meta",
      "PUT /cases/c1/report-meta",
    ]);
  });
});
