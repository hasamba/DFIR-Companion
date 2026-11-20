// #2721: the "AI Agent Forensics" case report section — template wiring, which runs it shows (launched
// in the case, sweeps filed into it), escaping, and the AI boundary (report-time only, never saved).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Marked } from "marked";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { renderHtmlReport } from "../../src/reports/html.js";
import { emptyState, type InvestigationState } from "../../src/analysis/stateTypes.js";
import { emptyReportMeta } from "../../src/reports/reportMeta.js";
import {
  BUILT_IN_REPORT_TEMPLATES,
  HUNT_REPORT_TEMPLATE,
  normalizeReportTemplate,
  normalizeSections,
  REPORT_SECTION_DEFS,
  type ReportTemplate,
} from "../../src/reports/reportTemplate.js";
import { AI_AGENT_HASH_CAVEAT } from "../../src/analysis/aiAgentHashCheck.js";
import type { AiAgentCaseRuns, AiAgentReport } from "../../src/analysis/aiAgentReportTypes.js";
import { AiAgentRunStore, type AiAgentRun } from "../../src/analysis/aiAgentRunStore.js";
import { loadAiAgentCaseRuns, projectAiAgentRun } from "../../src/reports/aiAgentCaseRuns.js";
import { AI_AGENT_SECTION_MAX_HITS } from "../../src/reports/aiAgentSection.js";
import { aiAgentReportMarkdown } from "../../src/reports/aiAgentReportExport.js";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { ReportWriter } from "../../src/reports/reportWriter.js";

const MARK = "SNIPPET-MARK-7731";
const HOSTILE =
  "![t](https://evil.example/t.png) [go](https://evil.example/x) [js](javascript:alert(1)) " +
  "<script>alert(1)</script> a|b `tick`\n## Forged";

function report(over: Partial<AiAgentReport> = {}): AiAgentReport {
  return {
    builtAt: "2026-11-19T11:00:00Z",
    ruleSetVersion: "rules-1",
    endpoints: [
      {
        host: `WS-1 ${HOSTILE}`,
        clientId: "C.1",
        tools: ["Claude Code", HOSTILE],
        mcpServers: [{ name: `mcp ${HOSTILE}`, command: HOSTILE, argCount: 0, config: "", tool: "Cursor" }],
        credentialStores: 1,
        hits: 1,
        coverage: [{ source: "yara", status: "ran", detail: HOSTILE }],
        sigma: [{ rule: "Rule S", status: `ran ${HOSTILE}`, hits: 1 }],
      },
    ],
    hits: [
      {
        host: `WS-1 ${HOSTILE}`,
        clientId: "C.1",
        rule: `Rule ${HOSTILE}`,
        family: "yara",
        ruleFile: "r.yar",
        author: HOSTILE,
        link: "https://example.invalid/rule",
        atlas: "",
        scope: "agent-home",
        severity: "High",
        selfScan: false,
        path: `C:\\Users\\dev\\.claude\\${HOSTILE}`,
        sha256: "a".repeat(64),
        preservedSha256: "b".repeat(64),
        hashCheck: "differs",
        time: "2026-11-19T09:00:00Z",
        timeBasis: "mtime",
        timeLabel: "",
        scanTime: "2026-11-19T10:00:00Z",
        snippet: `${MARK} ${HOSTILE}`,
        preserved: "uploaded",
      },
    ],
    sigmaRules: [{ rule: "Rule S", mode: "compiled", basis: `live ${HOSTILE}` }],
    notRun: [{ reason: "needs LLM application logs", rules: ["Rule N"] }],
    unreadableRows: 0,
    provisionalGrades: true,
    ...over,
  };
}

function run(over: Partial<AiAgentRun> = {}): AiAgentRun {
  return {
    runId: "aar-00000000-0000-0000-0000-000000000001",
    huntId: "H.CASE",
    launchedAt: "2026-11-19T10:00:00Z",
    endpoints: [{ clientId: "C.1", hostname: "WS-1" }],
    failedEndpoints: [],
    skippedEndpoints: [],
    scopes: ["agent-home"],
    uploadMaxBytes: 1,
    ruleSetVersion: "rules-1",
    artifacts: [],
    preserved: true,
    warnings: [],
    sensitive: true,
    report: report(),
    ...over,
  };
}

const only = normalizeReportTemplate({
  id: "t",
  name: "ai agent only",
  sections: REPORT_SECTION_DEFS.map((s) => ({ key: s.key, enabled: s.key === "aiAgentForensics" })),
});
const md = (state: InvestigationState, template: ReportTemplate = only): string =>
  renderMarkdownReport(state, emptyReportMeta(), undefined, undefined, undefined, undefined, template);
const html = (state: InvestigationState): string =>
  renderHtmlReport(state, emptyReportMeta(), undefined, undefined, undefined, undefined, only);
const withRuns = (runs: AiAgentCaseRuns): InvestigationState => ({
  ...emptyState("INC-1"),
  aiAgentRuns: runs,
});
const one = (r: AiAgentRun = run()): InvestigationState =>
  withRuns({ runs: [{ run: projectAiAgentRun(r)! }], unreadable: [] });

describe("aiAgentForensics report section wiring (#2721)", () => {
  it("is on in Standard and Technical Detail, off in the Executive Brief, the hunt template and old saved templates", () => {
    const enabled = (t: ReportTemplate) => t.sections.find((s) => s.key === "aiAgentForensics")?.enabled;
    const byId = (id: string) => BUILT_IN_REPORT_TEMPLATES.find((t) => t.id === id)!;
    expect(enabled(byId("standard"))).toBe(true);
    expect(enabled(byId("technical-detailed"))).toBe(true);
    expect(enabled(byId("executive-brief"))).toBe(false);
    expect(enabled(HUNT_REPORT_TEMPLATE)).toBe(false);
    expect(
      normalizeSections([{ key: "titlePage", enabled: true }]).find((s) => s.key === "aiAgentForensics")
        ?.enabled,
    ).toBe(false);
  });

  it("is mirrored in the dashboard's template editor with the same label and position", () => {
    const js = readFileSync(
      new URL("../../../public/js/dashboard-report-templates.js", import.meta.url),
      "utf8",
    );
    const def = REPORT_SECTION_DEFS.find((d) => d.key === "aiAgentForensics")!;
    expect(js).toContain(`["aiAgentForensics", ${JSON.stringify(def.label)}]`);
    expect(js.indexOf('["cloudWeaknesses"')).toBeLessThan(js.indexOf('["aiAgentForensics"'));
    expect(js.indexOf('["aiAgentForensics"')).toBeLessThan(js.indexOf('["handoffBrief"'));
  });
});

describe("aiAgentForensics section rendering (#2721)", () => {
  it("renders nothing for a case with no run, so other reports are unchanged", () => {
    expect(md(emptyState("INC-1"))).not.toMatch(/AI Agent Forensics/);
    expect(md(withRuns({ runs: [], unreadable: [] }))).not.toMatch(/AI Agent Forensics/);
  });

  it("shows the run report: inventory, hits with the matched text, both hashes with the caveat, Sigma coverage, rules not run", () => {
    const out = md(one());
    expect(out).toMatch(/^## AI Agent Forensics$/m);
    expect(out).toMatch(/^### Run ` H\.CASE ` — launched 2026-11-19T10:00:00Z$/m);
    expect(out).toContain("Launched in this case.");
    expect(out).toMatch(/^#### Endpoints$/m);
    expect(out).toMatch(/^#### Hits$/m);
    expect(out).toContain(MARK);
    expect(out).toContain(AI_AGENT_HASH_CAVEAT);
    expect(out).toContain("differs: changed between hashing and preservation");
    expect(out).toContain("a".repeat(64));
    expect(out).toContain("b".repeat(64));
    expect(out).toMatch(/^#### Sigma coverage per rule and endpoint$/m);
    expect(out).toMatch(/^#### Rules not run, and why$/m);
    expect(out).toContain("Grades are provisional");
    expect(out).toContain("Sensitive run");
    expect(out).toContain("the AI never reads it");
    expect(out).toContain("not to this record");
  });

  it("keeps every attacker-reachable value literal: no live link, image, HTML or heading, and no extra cell", () => {
    const out = md(one());
    expect(out).not.toMatch(/^#+ Forged/m);
    // Each table keeps its header's cell count on every row.
    const tables = new Marked({ gfm: true }).lexer(out).filter((t) => t.type === "table") as unknown as {
      header: unknown[];
      rows: unknown[][];
    }[];
    expect(tables.length).toBe(3); // endpoints, hits, Sigma coverage
    for (const t of tables) for (const r of t.rows) expect(r.length).toBe(t.header.length);
    const page = html(one());
    expect(page).not.toMatch(/<img[^>]*evil\.example/);
    expect(page).not.toMatch(/<a [^>]*evil\.example/);
    expect(page).not.toMatch(/href="javascript/);
    expect(page).not.toContain("<script>alert(1)</script>");
    expect(page).not.toMatch(/<h\d[^>]*>\s*Forged/);
  });

  it("says when the results are incomplete instead of reading as a clean result, and lists failed or skipped endpoints", () => {
    const out = md(
      one(
        run({
          report: report({ hits: [] }),
          readIncomplete: [{ artifact: "Custom.DFIRCompanion.AIAgentForensics.X", rowsRead: 5 }],
          reportError: "upload manifest: timed out",
          failedEndpoints: [{ clientId: "C.9", error: "offline" }],
          skippedEndpoints: [{ clientId: "C.8", hostname: "WS-8", reason: "no Windows" }],
        }),
      ),
    );
    expect(out).toContain("only the first 5 row(s) were read");
    expect(out).toContain("upload manifest: timed out");
    expect(out).toContain("Hunt not started on ` C.9 `");
    expect(out).toContain("Skipped ` WS-8 `");
    expect(out).toContain("not a clean result");
    expect(out).not.toContain("No rule matched on the endpoints and scopes above.");
  });

  it("does not read as a clean result when result rows could not be read", () => {
    const out = md(one(run({ report: report({ hits: [], unreadableRows: 2 }) })));
    expect(out).toContain("not a clean result");
    expect(out).toContain("2 result row(s) could not be read.");
    expect(out).not.toContain("No rule matched on the endpoints and scopes above.");
  });

  it("caps the hits table in the case report and points to the run's own download for the rest", () => {
    const h = report().hits[0];
    const many = report({ hits: Array.from({ length: AI_AGENT_SECTION_MAX_HITS + 3 }, () => h) });
    const out = md(one(run({ report: many })));
    expect(out).toContain("3 more hit(s) are not shown here");
    expect(aiAgentReportMarkdown(run({ report: many }))).not.toContain("more hit(s) are not shown");
  });

  it("states a sweep's origin and a re-read after filing, lists unreadable records, and survives a malformed run", () => {
    const sweep = projectAiAgentRun(run({ huntId: "H.SWEEP" }))!;
    const out = md(
      withRuns({
        runs: [
          {
            run: sweep,
            filedFrom: { sweepCaseId: "aiagent-sweep-20261119-100000-abcdef", at: "2026-11-19T10:30:00Z" },
          },
          { run: { ...sweep, runId: "x", huntId: "H.BAD", report: { endpoints: null } as never } },
        ],
        unreadable: ["the run record of sweep aiagent-sweep-x"],
      }),
    );
    expect(out).toContain("Filed into this case from sweep ` aiagent-sweep-20261119-100000-abcdef `");
    expect(out).toContain("Its results were read again after that");
    expect(out).toContain("- Could not be read: the run record of sweep aiagent-sweep-x");
    expect(out).toContain("This run's record could not be rendered.");
  });
});

describe("which runs a case report reads, and the AI boundary (#2721)", () => {
  let root: string;
  let cases: CaseStore;
  let stateStore: StateStore;
  let writer: ReportWriter;
  const SWEEP = "aiagent-sweep-20261119-100000-abcdef";
  const OTHER_SWEEP = "aiagent-sweep-20261119-110000-fedcba";

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "dfir-aiagent-section-"));
    cases = new CaseStore(root);
    for (const caseId of ["c1", "c2"])
      await cases.createCase({ caseId, name: caseId, investigator: "i", aiProvider: null });
    for (const caseId of [SWEEP, OTHER_SWEEP])
      await cases.createCase({ caseId, name: caseId, investigator: "i", aiProvider: null, kind: "sweep" });
    stateStore = new StateStore(cases);
    await stateStore.save(emptyState("c1"));
    writer = new ReportWriter(cases, stateStore, {});
    const store = new AiAgentRunStore(cases);
    // A legacy run that still carries its raw rows inline, with an unredacted secret.
    await store.upsert("c1", run({ rows: [{ Snippet: "RAW-UNREDACTED-SECRET" }] }));
    await store.upsert(
      SWEEP,
      run({
        runId: "aar-00000000-0000-0000-0000-000000000002",
        huntId: "H.SWEEP",
        addedTo: [{ caseId: "c1", at: "2026-11-19T12:00:00Z", events: 1 }],
      }),
    );
    await store.upsert(
      OTHER_SWEEP,
      run({
        runId: "aar-00000000-0000-0000-0000-000000000003",
        huntId: "H.ELSEWHERE",
        addedTo: [{ caseId: "c2", at: "2026-11-19T12:00:00Z", events: 1 }],
      }),
    );
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("reads the case's own runs and the sweeps filed into it, never one filed elsewhere, never the raw rows", async () => {
    const got = await loadAiAgentCaseRuns(cases, "c1");
    expect(got.runs.map((r) => r.run.huntId)).toEqual(["H.CASE", "H.SWEEP"]);
    expect(got.runs[1].filedFrom).toEqual({ sweepCaseId: SWEEP, at: "2026-11-19T12:00:00Z" });
    expect(JSON.stringify(got)).not.toContain("RAW-UNREDACTED-SECRET");
    expect(Object.keys(got.runs[0].run)).not.toContain("rows");
  });

  it("writes the section into report.md, report.html and state-export.json, and the .docx builds", async () => {
    const paths = await writer.writeAll("c1");
    const mdOut = await readFile(paths.markdown, "utf8");
    expect(mdOut).toContain("## AI Agent Forensics");
    expect(mdOut).toContain("` H.SWEEP `");
    expect(mdOut).not.toContain("H.ELSEWHERE");
    expect(await readFile(paths.html, "utf8")).toContain(MARK);
    const exported = await readFile(paths.stateJson, "utf8");
    expect(exported).toContain(MARK);
    expect(exported).not.toContain("RAW-UNREDACTED-SECRET");
    await expect(writer.docx("c1")).resolves.toBeDefined();
  });

  it("never saves the runs with the case, and no other surface of the filtered state carries them", async () => {
    await writer.writeAll("c1");
    expect(JSON.stringify(await stateStore.load("c1"))).not.toContain(MARK);
    expect((await writer.filteredState("c1")).aiAgentRuns).toBeUndefined();
    expect((await writer.filteredState("c1", true)).aiAgentRuns).toBeUndefined();
    const redacted = await writer.redactedReportContents("c1", (t) => t);
    expect(JSON.stringify(redacted)).not.toContain(MARK);
  });

  it("still writes the report when the case's run record is corrupt, and says so", async () => {
    await writeFile(join(cases.stateDir("c1"), "ai-agent-runs.json"), "{not json");
    const mdOut = await readFile((await writer.writeAll("c1")).markdown, "utf8");
    expect(mdOut).toContain("Could not be read: this case's AI Agent Forensics run record");
    expect(mdOut).toContain("` H.SWEEP `");
  });
});

describe("the run data reaches report renderers only (#2721)", () => {
  it("is read by the report section, the loader and the run report renderer, and imported only by the report writer", async () => {
    const { readdirSync, statSync } = await import("node:fs");
    const SRC = fileURLToPath(new URL("../../src/", import.meta.url));
    const walk = (d: string): string[] =>
      readdirSync(d).flatMap((n) => {
        const f = join(d, n);
        return statSync(f).isDirectory() ? walk(f) : f.endsWith(".ts") ? [f] : [];
      });
    const rel = (f: string) => f.slice(SRC.length).split("\\").join("/");
    const files = walk(SRC);
    const readers = files.filter((f) => /\.aiAgentRuns\b|aiAgentRuns\s*[,}]/.test(readFileSync(f, "utf8")));
    expect(readers.map(rel).sort()).toEqual(["reports/aiAgentCaseRuns.ts", "reports/aiAgentSection.ts"]);
    const importers = files.filter((f) => readFileSync(f, "utf8").includes("/aiAgentCaseRuns.js"));
    expect(importers.map(rel)).toEqual(["reports/reportWriter.ts"]);
  });
});
