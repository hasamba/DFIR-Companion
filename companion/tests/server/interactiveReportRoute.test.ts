import { describe, it, expect, beforeEach } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";
import { emptyState } from "../../src/analysis/stateTypes.js";
import { createApp } from "../../src/server.js";

// Route-level coverage for the interactive report. The renderer has its own unit tests; what is
// exercised here is everything those cannot see — that the URL actually reaches this handler at
// all, and that the served document satisfies the CSP the app stamps on every response.
//
// Both were real defects. `GET /cases/:id/report/:file` in reportsExport.ts matches
// `/report/interactive` and answers unknown names with 400 instead of calling next(), so the
// endpoint returned `{"error":"unknown report file"}` until it was registered ahead of that
// handler. Separately the inline <script> blocks carried no nonce, so script-src blocked both and
// the page rendered as a header above two empty sections.

let app: ReturnType<typeof createApp>;
let cases: CaseStore;

beforeEach(async () => {
  const root = await mkdtemp(join(tmpdir(), "dfir-interactive-"));
  cases = new CaseStore(root);
  await cases.createCase({ caseId: "c1", name: "Phishing Case", investigator: "Alice", aiProvider: null });

  const stateStore = new StateStore(cases);
  await stateStore.save({
    ...emptyState("c1"),
    forensicTimeline: [
      {
        id: "e1",
        timestamp: "2026-01-01T00:00:00Z",
        description: "powershell -enc from VICTIM-PC",
        severity: "High",
        mitreTechniques: ["T1059"],
        relatedFindingIds: [],
        sourceScreenshots: [],
        asset: "VICTIM-PC",
      },
    ],
  });

  app = createApp(cases, { stateStore, reportWriter: new ReportWriter(cases, stateStore) });
});

describe("GET /cases/:id/report/interactive", () => {
  it("is reachable and serves HTML, not the reportsExport :file handler", async () => {
    const res = await request(app).get("/cases/c1/report/interactive");

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("text/html");
    expect(res.headers["cache-control"]).toBe("private, no-cache");
    expect(res.text.startsWith("<!doctype html>")).toBe(true);
    // The exact body the shadowing route returns. Asserting on it pins the regression directly.
    expect(res.text).not.toContain("unknown report file");
  });

  it("embeds the case data and renders the case metadata", async () => {
    const res = await request(app).get("/cases/c1/report/interactive");

    expect(res.text).toContain("window.__DFIR_CASE__");
    expect(res.text).toContain("Phishing Case");
    expect(res.text).toContain("T1059");
  });

  it("stamps this response's CSP nonce into every inline script", async () => {
    const res = await request(app).get("/cases/c1/report/interactive");

    const csp = res.headers["content-security-policy"];
    const nonce = /'nonce-([^']+)'/.exec(csp ?? "")?.[1];
    expect(nonce).toBeTruthy();

    // Every script tag in the document must carry this response's nonce, or the browser drops it.
    const scriptTags = res.text.match(/<script\b[^>]*>/gi) ?? [];
    expect(scriptTags).toHaveLength(2);
    for (const tag of scriptTags) expect(tag).toContain(`nonce="${nonce}"`);

    // The placeholder must not survive into the served document.
    expect(res.text).not.toContain("__CSP_NONCE__");
  });

  it("mints a fresh nonce per response rather than reusing one", async () => {
    const a = await request(app).get("/cases/c1/report/interactive");
    const b = await request(app).get("/cases/c1/report/interactive");

    const nonceOf = (text: string) => /<script nonce="([^"]+)"/.exec(text)?.[1];
    expect(nonceOf(a.text)).toBeTruthy();
    expect(nonceOf(a.text)).not.toBe(nonceOf(b.text));
  });

  it("501s when the report writer is not configured", async () => {
    const bare = createApp(cases, {});
    const res = await request(bare).get("/cases/c1/report/interactive");
    expect(res.status).toBe(501);
  });
});
