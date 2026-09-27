// #1713: a live `state` push armed ~21 debounced panel reloads that all fired together ~800 ms
// later, outside the four-lane request cap the case load and the #1709 catch-up run under. Every
// debounced reload now fires through the page's shared cap — and so does every other caller of the
// same helpers (scope apply, the #1447 provenance flush after an import).
import { readFileSync, readdirSync } from "node:fs";
import { describe, it, expect, vi, afterEach } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

const JS = new URL("../../../public/js/", import.meta.url);
const read = (f: string) => readFileSync(new URL(f, JS), "utf8").replace(/\r\n/g, "\n");

// The debounced reloads a `state` push arms, plus the second-opinion one it arms beside them.
const HELPERS = [
  "scheduleAssetGraphReload",
  "scheduleEvidenceGraphReload",
  "schedulePhasesReload",
  "scheduleTimelineGapsReload",
  "scheduleEvidenceGapsReload",
  "scheduleCloudCoverageReload",
  "scheduleBeaconsReload",
  "scheduleAnomaliesReload",
  "scheduleSessionsReload",
  "scheduleAdversaryHintsReload",
  "schedulePlaybookMatchReload",
  "scheduleHostRankingReload",
  "scheduleD3fendReload",
  "scheduleAttackMitigationsReload",
  "scheduleComplianceReload",
  "scheduleGeoMapReload",
  "scheduleSwimlaneReload",
  "scheduleIocSourcesReload",
  "scheduleIocProvenanceReload",
  "scheduleIocRiskReload",
  "scheduleIocProvenanceChainReload",
  "scheduleSecondOpinionReload",
];

/** The source of `function <name>(` up to its closing brace at the same indent. */
function bodyOf(name: string): { file: string; body: string } {
  for (const file of readdirSync(JS).filter((f) => f.endsWith(".js"))) {
    const src = read(file);
    const m = src.match(new RegExp(`\\n( *)function ${name}\\(`));
    if (!m || m.index === undefined) continue;
    const start = m.index + 1;
    const end = src.indexOf(`\n${m[1]}}`, start);
    return { file, body: src.slice(start, end + m[1].length + 2) };
  }
  throw new Error(`no function ${name} in public/js`);
}

describe("every debounced panel reload fires through the shared request cap (#1713)", () => {
  it.each(HELPERS)("%s hands its loader to panelReload", (name) => {
    const { body } = bodyOf(name);
    expect(body).toMatch(/setTimeout\(\s*\(\) =>\s*panelReload\(\s*"[a-zA-Z0-9]+",/);
  });

  it("each module's panelReload falls back to running the loader when the cap is missing", () => {
    const files = [...new Set(HELPERS.map((n) => bodyOf(n).file))];
    for (const file of files) {
      const src = read(file);
      expect(src, file).toMatch(/const panelReload = \(key, run\) => \{/);
      expect(src, file).toMatch(
        /clp && typeof clp\.runPanelReload === "function"\s*\?\s*clp\.runPanelReload\(key, run\)\s*:\s*run\(\)/,
      );
    }
  });
});

describe("the provenance reloads parked during an import still go through the cap (#1713)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function harness(opts: { withCap: boolean }) {
    const fetched: string[] = [];
    const capped: string[] = [];
    let running = true;
    const api = loadDashboardModule<{
      scheduleIocProvenanceReload: () => void;
      scheduleIocProvenanceChainReload: () => void;
      flushDeferredIocProvenanceReloads: () => void;
    }>("dashboard-ioc-provenance.js", ["dashboard-escape.js"], {
      activeCaseId: "CASE-1",
      fetch: async (url: string) => {
        fetched.push(url);
        return { ok: true, json: async () => ({}) };
      },
      document: {
        getElementById: (id: string) => (id === "caseId" ? { value: "CASE-1" } : null),
        querySelectorAll: () => [],
      },
      DfirState: { lastState: () => null, lastFt: () => [] },
      DfirScope: { project: (s: unknown) => s },
      ICON_CHAIN: "<svg></svg>",
      localStorage: { getItem: () => null, setItem() {} },
      setTimeout: (fn: () => void, ms: number) => globalThis.setTimeout(fn, ms),
      clearTimeout: (id: unknown) => globalThis.clearTimeout(id as number),
      runningJob: (kind: string) => (kind === "import" && running ? { id: "imp-1" } : undefined),
      ...(opts.withCap
        ? {
            DfirCaseLoadProgress: {
              runPanelReload: (key: string, run: () => void) => {
                capped.push(key);
                run();
              },
            },
          }
        : {}),
    });
    return {
      api,
      fetched,
      capped,
      finishImport: () => {
        running = false;
      },
    };
  }

  it("park, then flush after the import: each reload goes through the cap once", () => {
    vi.useFakeTimers();
    const h = harness({ withCap: true });
    h.api.scheduleIocProvenanceReload();
    h.api.scheduleIocProvenanceChainReload();
    vi.advanceTimersByTime(800);
    expect(h.capped).toEqual([]);
    h.finishImport();
    h.api.flushDeferredIocProvenanceReloads();
    vi.advanceTimersByTime(800);
    expect(h.capped).toEqual(["iocProvenance", "iocProvenanceChain"]);
    expect(h.fetched).toEqual(["/cases/CASE-1/ioc-provenance", "/cases/CASE-1/ioc-provenance-chain"]);
  });

  it("without the cap module the reload still runs — a reload is never dropped", () => {
    vi.useFakeTimers();
    const h = harness({ withCap: false });
    h.finishImport();
    h.api.scheduleIocProvenanceReload();
    vi.advanceTimersByTime(800);
    expect(h.fetched).toEqual(["/cases/CASE-1/ioc-provenance"]);
  });
});

describe("the case paths share the page's lanes and retire the reloads (#1713)", () => {
  const CONNECT = read("dashboard-case-connect.js");
  const LIVE = read("dashboard-live-socket.js");
  const fnBody = (src: string, name: string) => {
    const start = src.indexOf(`function ${name}(`);
    return src.slice(start, src.indexOf("\n  }\n", start));
  };

  it("the case load and the catch-up both run on the shared lane pool", () => {
    expect(CONNECT).toMatch(/lanes: panelApi\.panelLanes/);
    expect(LIVE).toMatch(/lanes: window\.DfirCaseLoadProgress\.panelLanes/);
  });

  it("switching case and cancelling a load both retire the pending reloads", () => {
    for (const name of ["proceedConnect", "dismissCaseLoading"]) {
      expect(fnBody(CONNECT, name), name).toMatch(/retirePanelReloads\(\)/);
    }
  });
});
