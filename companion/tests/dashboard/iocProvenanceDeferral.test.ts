// #1447: every `state` push during an import used to reload the two IOC-provenance panels, and
// each reload is a full super-timeline scan on the server (~75 s on a capped case). While an
// import job is running for the case on screen, the reloads are deferred; they fire once, when
// the jobs module reports the import gone. This pins that hand-off from the panel's side.
import { describe, it, expect, vi } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

interface ProvenanceApi {
  scheduleIocProvenanceReload: () => void;
  scheduleIocProvenanceChainReload: () => void;
  flushDeferredIocProvenanceReloads: () => void;
  loadIocProvenance: (caseId: string) => void;
}

function harness(opts: { importRunning: () => boolean; withJobs?: boolean }) {
  const fetched: string[] = [];
  const el = (id: string) => (id === "caseId" ? { value: "CASE-1" } : null);
  const api = loadDashboardModule<ProvenanceApi>("dashboard-ioc-provenance.js", ["dashboard-escape.js"], {
    fetch: async (url: string) => {
      fetched.push(url);
      return { ok: true, json: async () => ({}) };
    },
    document: { getElementById: el, querySelectorAll: () => [] },
    DfirState: { lastState: () => null, lastFt: () => [] },
    DfirScope: { project: (s: unknown) => s },
    ICON_CHAIN: "<svg></svg>",
    localStorage: { getItem: () => null, setItem() {} },
    // Resolved per call so vi.useFakeTimers() installed after load still reaches the module.
    setTimeout: (fn: () => void, ms: number) => globalThis.setTimeout(fn, ms),
    clearTimeout: (id: unknown) => globalThis.clearTimeout(id as number),
    ...(opts.withJobs === false
      ? {}
      : {
          runningJob: (kind: string) =>
            kind === "import" && opts.importRunning() ? { id: "imp-1" } : undefined,
        }),
  });
  return { api, fetched };
}

describe("IOC-provenance reloads while an import runs (#1447)", () => {
  it("with no import running, a scheduled reload fetches after the debounce as before", () => {
    vi.useFakeTimers();
    const { api, fetched } = harness({ importRunning: () => false });
    api.scheduleIocProvenanceReload();
    api.scheduleIocProvenanceChainReload();
    vi.advanceTimersByTime(800);
    expect(fetched).toEqual(["/cases/CASE-1/ioc-provenance", "/cases/CASE-1/ioc-provenance-chain"]);
    vi.useRealTimers();
  });

  it("while an import runs, scheduled reloads do not fetch; the flush after the import fetches each once", () => {
    vi.useFakeTimers();
    let running = true;
    const { api, fetched } = harness({ importRunning: () => running });
    for (let artifact = 0; artifact < 5; artifact++) {
      api.scheduleIocProvenanceReload();
      api.scheduleIocProvenanceChainReload();
      vi.advanceTimersByTime(800);
    }
    expect(fetched).toEqual([]);

    api.flushDeferredIocProvenanceReloads(); // the jobs refresh still sees the import
    vi.advanceTimersByTime(800);
    expect(fetched).toEqual([]);

    running = false;
    api.flushDeferredIocProvenanceReloads(); // the import finished
    vi.advanceTimersByTime(800);
    expect(fetched).toEqual(["/cases/CASE-1/ioc-provenance", "/cases/CASE-1/ioc-provenance-chain"]);

    api.flushDeferredIocProvenanceReloads(); // nothing left to flush
    vi.advanceTimersByTime(800);
    expect(fetched).toHaveLength(2);
    vi.useRealTimers();
  });

  it("an import starting after the timer was armed cancels the pending fetch and defers it", () => {
    vi.useFakeTimers();
    let running = false;
    const { api, fetched } = harness({ importRunning: () => running });
    api.scheduleIocProvenanceReload();
    running = true;
    api.scheduleIocProvenanceReload(); // the next state push, now under an import
    vi.advanceTimersByTime(800);
    expect(fetched).toEqual([]);
    running = false;
    api.flushDeferredIocProvenanceReloads();
    vi.advanceTimersByTime(800);
    expect(fetched).toEqual(["/cases/CASE-1/ioc-provenance"]);
    vi.useRealTimers();
  });

  it("a direct load (case connect) clears the deferral so the flush does not fetch twice", () => {
    vi.useFakeTimers();
    let running = true;
    const { api, fetched } = harness({ importRunning: () => running });
    api.scheduleIocProvenanceReload();
    api.loadIocProvenance("CASE-1"); // the connect fan-out loads the panel outright
    running = false;
    api.flushDeferredIocProvenanceReloads();
    vi.advanceTimersByTime(800);
    expect(fetched).toEqual(["/cases/CASE-1/ioc-provenance"]);
    vi.useRealTimers();
  });

  it("without the jobs module loaded, reloads behave as before (nothing is ever deferred)", () => {
    vi.useFakeTimers();
    const { api, fetched } = harness({ importRunning: () => true, withJobs: false });
    api.scheduleIocProvenanceReload();
    vi.advanceTimersByTime(800);
    expect(fetched).toEqual(["/cases/CASE-1/ioc-provenance"]);
    expect(() => api.flushDeferredIocProvenanceReloads()).not.toThrow();
    vi.useRealTimers();
  });
});
