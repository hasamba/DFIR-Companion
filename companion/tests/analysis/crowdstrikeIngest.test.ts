import { describe, it, expect } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CaseStore } from "../../src/storage/caseStore.js";
import { StateStore } from "../../src/analysis/stateStore.js";
import { AnalysisPipeline } from "../../src/analysis/pipeline.js";
import { computeMainSource } from "../../src/analysis/caseMainSource.js";
import { huntLanguageFor } from "../../src/analysis/huntLanguage.js";
import { forensicTimelineCsv } from "../../src/reports/csv.js";
import { renderMarkdownReport } from "../../src/reports/markdown.js";
import { renderHtmlReport } from "../../src/reports/html.js";

// #2592 — a Falcon sensor export end to end through the real pipeline (synthetic rows).
async function makePipeline(caseId: string) {
  const root = await mkdtemp(join(tmpdir(), "dfir-crowdstrike-"));
  const cases = new CaseStore(root);
  await cases.createCase({ caseId, name: "n", investigator: "i", aiProvider: null });
  return new AnalysisPipeline({
    stateStore: new StateStore(cases),
    imageLoader: async () => ({ base64: "AAAA", mimeType: "image/webp" }),
  });
}

const base = { aid: "abc", ComputerName: "WS-01", ContextTimeStamp: "1731399999.456" };
const ADVERSARY =
  "=cmd|' /C calc'!A0 & powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AA== <script>alert(1)</script>";
const rows = [
  { ...base, "#event_simpleName": "ProcessRollup2", RawProcessId: "77", CommandLine: ADVERSARY },
  { ...base, "#event_simpleName": "NetworkConnectIP4", RemoteAddressIP4: "203.0.113.10", RemotePort: "443" },
  { ...base, "#event_simpleName": "NetworkConnectIP4", RemoteAddressIP4: "203.0.113.11", RemotePort: "443" },
  { ...base, "#event_simpleName": "DnsRequest", DomainName: "c2.example.com" },
];
const text = rows.map((r) => JSON.stringify(r)).join("\n");

describe("importCrowdstrike through the pipeline", () => {
  it("lands Falcon rows with source, IOCs, main-source family and escaped report output", async () => {
    const pipeline = await makePipeline("cs1");
    const state = await pipeline.importCrowdstrike("cs1", text, {
      label: "falcon.ndjson",
      idPrefix: "cs-",
      importedAt: "2024-11-12T09:00:00.000Z",
    });
    const falcon = state.forensicTimeline.filter((e) => e.sources?.includes("CrowdStrike Falcon"));
    expect(falcon.length).toBe(4);
    const values = state.iocs.map((i) => i.value);
    expect(values).toEqual(expect.arrayContaining(["203.0.113.10", "203.0.113.11", "c2.example.com"]));

    // AC12 — a case with only Falcon evidence picks the crowdstrike family and CQL hunts.
    const main = computeMainSource(
      [...falcon, ...falcon.map((e) => ({ ...e, sourceScreenshots: ["falcon2.ndjson"] }))],
      null,
    );
    expect(main.counts.map((c) => c.family)).toEqual(["crowdstrike"]);
    expect(huntLanguageFor("crowdstrike", ["crowdstrike"]).language).toBe("cql");

    // AC13 — adversary command line: no CSV cell opens with a formula, table intact in MD, no live markup in HTML.
    const csv = forensicTimelineCsv(state);
    expect(csv.split("\n").some((l) => /(^|,)"?=/.test(l))).toBe(false);
    // Markdown keeps the table intact (the pipe is escaped); the HTML export is what stops live markup.
    expect(renderMarkdownReport(state)).toContain("=cmd\\|' /C calc'!A0");
    expect(renderHtmlReport(state)).not.toContain("<script>alert(1)</script>");
  });
});

describe("a mixed Falcon + wrapped Okta export through the real importers (AC21)", () => {
  it("lands 2 CrowdStrike Falcon rows and 2 Okta rows, none of the Okta rows labelled Falcon", async () => {
    const { dispatchCrowdstrike } = await import("../../src/composition/crowdstrikeDispatch.js");
    const pipeline = await makePipeline("cs2");
    const okta = (n: number) => ({
      uuid: `u${n}`,
      published: `2024-11-12T08:0${n}:00.000Z`,
      eventType: "user.session.start",
      actor: { alternateId: `user${n}@example.com`, type: "User" },
      outcome: { result: "SUCCESS" },
      client: { ipAddress: "198.51.100.20" },
    });
    const wrapped = (n: number) => ({
      "@timestamp": 1731398400000,
      "@rawstring": JSON.stringify(okta(n)),
      "#repo": "3pi_okta",
    });
    const sensorRow = (d: string) => ({
      ...base,
      "#event_simpleName": "DnsRequest",
      DomainName: d,
      "#repo": "base_sensor",
    });
    const file = [sensorRow("a.example.com"), wrapped(1), sensorRow("b.example.com"), wrapped(2)]
      .map((r) => JSON.stringify(r))
      .join("\n");
    const opts = { label: "mixed.ndjson", idPrefix: "m", importedAt: "2024-11-12T09:00:00.000Z" };
    const kinds: string[] = [];
    const state = (await dispatchCrowdstrike(file, opts, {
      importFalcon: (t, b, src) =>
        pipeline.importCrowdstrike("cs2", t, { ...b, ...(src ? { crowdstrike: { sourceText: src } } : {}) }),
      dispatch: (k, t, b) => {
        kinds.push(k);
        return pipeline.importOkta("cs2", t, b);
      },
    })) as Awaited<ReturnType<typeof pipeline.importOkta>>;
    expect(kinds).toEqual(["okta"]);
    const falcon = state.forensicTimeline.filter((e) => e.sources?.includes("CrowdStrike Falcon"));
    const rest = state.forensicTimeline.filter((e) => !e.sources?.includes("CrowdStrike Falcon"));
    expect(falcon).toHaveLength(2);
    const oktaRows = rest.filter((e) => e.sources?.includes("Okta"));
    expect(oktaRows).toHaveLength(2);
    expect(oktaRows.every((e) => e.sourceScreenshots.includes("mixed.ndjson"))).toBe(true);
  });
});
