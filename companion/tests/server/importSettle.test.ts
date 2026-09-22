import { describe, it, expect, vi, afterEach } from "vitest";
import { settleForensicImport } from "../../src/routes/importSettle.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import { LoggerImpl, type LogWriter } from "../../src/logging/logger.js";
import { getServerLogger, setServerLogger } from "../../src/logging/serverLogger.js";

// The one seam every import crosses: dual-write the ADDED rows → tag them → demote → diff against
// the post-demote state. Pinned here so a route can neither skip a step nor run them out of order.

function ev(id: string, severity: ForensicEvent["severity"], description = id): ForensicEvent {
  return {
    id,
    timestamp: "2026-05-02T10:00:00Z",
    description,
    severity,
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function state(events: ForensicEvent[], iocs: InvestigationState["iocs"] = []): InvestigationState {
  return { forensicTimeline: events, iocs } as unknown as InvestigationState;
}

describe("settleForensicImport", () => {
  it("dual-writes only the rows the import added, tags them, demotes, and diffs post-demote", async () => {
    const calls: string[] = [];
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High"), ev("info", "Info"), ev("high", "High")]);
    const afterDemote = state([ev("old", "High"), ev("high", "High")]);
    const deps = {
      stateStore: { load: vi.fn(async () => merged), save: vi.fn(async () => {}) },
      superTimelineStore: {
        append: vi.fn(async (_c: string, events: ForensicEvent[]) => {
          calls.push(`append:${events.map((e) => e.id).join(",")}`);
          return events.length;
        }),
      },
      onSuperTimeline: vi.fn(() => calls.push("notify")),
      autoTagImported: vi.fn(async (_c: string, events: ForensicEvent[]) => {
        calls.push(`tag:${events.map((e) => e.id).join(",")}`);
      }),
      demoteForensicForCase: vi.fn(async () => {
        calls.push("demote");
        return afterDemote;
      }),
    };
    const r = await settleForensicImport(deps, "c1", before);
    expect(calls).toEqual(["append:info,high", "notify", "tag:info,high", "demote"]);
    expect(r.superTimelineAddedCount).toBe(2);
    // The diff is against the POST-demote state: the Info row is not "+1 event".
    expect(r.timelineDiff.added.map((e) => e.description)).toEqual(["high"]);
    expect(r.state).toBe(afterDemote);
  });

  it("returns the retained count the store reports, not the number handed to it", async () => {
    const before = state([]);
    const merged = state([ev("a", "Info"), ev("b", "Info")]);
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: { append: async () => 1 }, // the cap kept one
      autoTagImported: async () => {},
      demoteForensicForCase: async () => state([]),
    };
    expect((await settleForensicImport(deps, "c1", before)).superTimelineAddedCount).toBe(1);
  });

  it("still tags and demotes when the super-timeline append fails", async () => {
    const before = state([]);
    const merged = state([ev("a", "Info")]);
    const tagged: string[] = [];
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: {
        append: async () => {
          throw new Error("disk");
        },
      },
      autoTagImported: async (_c: string, events: ForensicEvent[]) => {
        tagged.push(...events.map((e) => e.id));
      },
      demoteForensicForCase: async () => state([]),
    };
    const r = await settleForensicImport(deps, "c1", before);
    expect(tagged).toEqual(["a"]);
    expect(r.superTimelineAddedCount).toBe(0);
    expect(r.state.forensicTimeline).toEqual([]);
  });

  it("skips the dual-write when no store is wired, and demotes anyway", async () => {
    const demote = vi.fn(async () => state([]));
    const r = await settleForensicImport(
      {
        stateStore: { load: async () => state([ev("a", "Info")]), save: async () => {} },
        autoTagImported: async () => {},
        demoteForensicForCase: demote,
      },
      "c1",
      state([]),
    );
    expect(demote).toHaveBeenCalledOnce();
    expect(r.superTimelineAddedCount).toBe(0);
  });
});

// ── #1157: per-event importedAt / importBatchId ─────────────────────────────────────────────────
describe("settleForensicImport — importedAt / importBatchId (#1157)", () => {
  it("stamps importedAt and importBatchId on rows genuinely new to this case, and saves them", async () => {
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High"), ev("new1", "High"), ev("new2", "High")]);
    let saved: InvestigationState | undefined;
    const deps = {
      stateStore: {
        load: async () => merged,
        save: vi.fn(async (s: InvestigationState) => {
          saved = s;
        }),
      },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => saved ?? merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(deps.stateStore.save).toHaveBeenCalledOnce();
    const byId = new Map(saved!.forensicTimeline.map((e) => [e.id, e]));
    expect(byId.get("old")!.importedAt).toBeUndefined();
    expect(byId.get("old")!.importBatchId).toBeUndefined();
    expect(byId.get("new1")!.importedAt).toEqual(expect.any(String));
    expect(byId.get("new2")!.importedAt).toBe(byId.get("new1")!.importedAt);
    expect(byId.get("new1")!.importBatchId).toEqual(expect.any(String));
    expect(byId.get("new2")!.importBatchId).toBe(byId.get("new1")!.importBatchId);
  });

  // #1174: dashboard/WS subscribers were not notified at the instant the importedAt/importBatchId
  // stamps were saved — only whenever a LATER broadcast happened to fire.
  it("notifies onState with the stamped state right after the save, not just on a later broadcast", async () => {
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High"), ev("new1", "High")]);
    let saved: InvestigationState | undefined;
    const onState = vi.fn();
    const deps = {
      stateStore: {
        load: async () => merged,
        save: async (s: InvestigationState) => {
          saved = s;
        },
      },
      onState,
      autoTagImported: async () => {},
      demoteForensicForCase: async () => saved ?? merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(onState).toHaveBeenCalledOnce();
    expect(onState).toHaveBeenCalledWith(saved);
  });

  it("does not fire onState when nothing new was imported (save never ran)", async () => {
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High")]);
    const onState = vi.fn();
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      onState,
      autoTagImported: async () => {},
      demoteForensicForCase: async () => merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(onState).not.toHaveBeenCalled();
  });

  it("does not re-stamp a row that already existed before this import", async () => {
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High")]); // nothing new — a no-op import
    const save = vi.fn(async () => {});
    const deps = {
      stateStore: { load: async () => merged, save },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(save).not.toHaveBeenCalled();
  });

  it("stamps new rows even when no super-timeline store is configured", async () => {
    const before = state([]);
    const merged = state([ev("new1", "Info")]);
    let saved: InvestigationState | undefined;
    const deps = {
      stateStore: {
        load: async () => merged,
        save: async (s: InvestigationState) => {
          saved = s;
        },
      },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => saved ?? merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(saved!.forensicTimeline[0].importedAt).toEqual(expect.any(String));
  });

  it("persists the stamp through demoteForensicForCase's own independent reload", async () => {
    // demoteForensicForCase in production reloads from the store itself — this fixture models
    // that by returning exactly what was saved, proving the stamp survived a save/reload round
    // trip rather than only existing on an in-memory object this function happens to return.
    const before = state([]);
    const merged = state([ev("new1", "High")]);
    let saved: InvestigationState = merged;
    const deps = {
      stateStore: {
        load: async () => merged,
        save: async (s: InvestigationState) => {
          saved = s;
        },
      },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => saved,
    };
    const r = await settleForensicImport(deps, "c1", before);
    expect(r.state.forensicTimeline[0].importedAt).toEqual(expect.any(String));
  });

  it("gives two separate imports different importedAt and importBatchId values", async () => {
    const before = state([]);
    let saved: InvestigationState | undefined;
    const deps = (mergedState: InvestigationState) => ({
      stateStore: {
        load: async () => mergedState,
        save: async (s: InvestigationState) => {
          saved = s;
        },
      },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => saved ?? mergedState,
    });
    await settleForensicImport(deps(state([ev("a", "High")])), "c1", before);
    const first = saved!.forensicTimeline[0];
    saved = undefined;
    await new Promise((r) => setTimeout(r, 2));
    await settleForensicImport(deps(state([ev("b", "High")])), "c1", before);
    const second = saved!.forensicTimeline[0];
    expect(second.importBatchId).not.toBe(first.importBatchId);
    expect(second.importedAt).not.toBe(first.importedAt);
  });

  it("stamps the rows dual-written to the super-timeline and offered to the tagger too", async () => {
    const before = state([]);
    const merged = state([ev("new1", "Info")]);
    let taggedEvents: ForensicEvent[] = [];
    let appendedEvents: ForensicEvent[] = [];
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: {
        append: async (_c: string, events: ForensicEvent[]) => {
          appendedEvents = events;
          return events.length;
        },
      },
      autoTagImported: async (_c: string, events: ForensicEvent[]) => {
        taggedEvents = events;
      },
      demoteForensicForCase: async () => state([]),
    };
    await settleForensicImport(deps, "c1", before);
    expect(appendedEvents[0].importedAt).toEqual(expect.any(String));
    expect(taggedEvents[0].importedAt).toEqual(expect.any(String));
  });
});

// ── #1438: the "done" log line ──────────────────────────────────────────────────────────────────
describe("settleForensicImport — the [import] done line (#1438)", () => {
  const previous = getServerLogger();
  afterEach(() => setServerLogger(previous));

  // A LogWriter that records every (path, line) pair: the session log and the case log both show up.
  function captureLogger(level: "info" | "debug") {
    const lines: { path: string; line: string }[] = [];
    const writer: LogWriter = {
      write: (path, line) => lines.push({ path, line }),
      close: async () => {},
    };
    setServerLogger(
      new LoggerImpl({
        level,
        sessionLogPath: "/session.log",
        caseLogPath: (caseId) => `/cases/${caseId}.log`,
        console: false,
        writer,
        now: () => "T",
      }),
    );
    return lines;
  }

  it("logs what landed at INFO, with the label, in the session log and the case log", async () => {
    const lines = captureLogger("info");
    const ioc = (value: string) =>
      ({ id: value, type: "ip", value }) as unknown as InvestigationState["iocs"][number];
    const before = state([ev("old", "High")], [ioc("10.0.0.1")]);
    const merged = state([ev("old", "High"), ev("info", "Info"), ev("high", "High")]);
    const afterDemote = state([ev("old", "High"), ev("high", "High")], [ioc("10.0.0.1"), ioc("10.0.0.2")]);
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: { append: async (_c: string, events: ForensicEvent[]) => events.length },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => afterDemote,
    };
    await settleForensicImport(deps, "c1", before, "0007_x.json");
    const expected = "T INFO  [c1] [import] c1 0007_x.json: done — forensic +1, super +2, IOCs +1";
    expect(lines).toEqual([
      { path: "/session.log", line: expected },
      { path: "/cases/c1.log", line: expected },
    ]);
  });

  it("logs an all-zero settle at DEBUG only, so an empty monitor poll does not fill the log", async () => {
    const lines = captureLogger("info");
    const unchanged = state([ev("old", "High")]);
    const deps = {
      stateStore: { load: async () => unchanged, save: async () => {} },
      superTimelineStore: { append: async () => 0 },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => unchanged,
    };
    await settleForensicImport(deps, "c1", unchanged);
    expect(lines).toEqual([]);

    const debugLines = captureLogger("debug");
    await settleForensicImport(deps, "c1", unchanged);
    expect(debugLines.map((l) => l.line)).toEqual([
      "T DEBUG [c1] [import] c1: done — forensic +0, super +0, IOCs +0",
      "T DEBUG [c1] [import] c1: done — forensic +0, super +0, IOCs +0",
    ]);
  });
});

// Older rows under a name this import taught the case was a former one are re-homed at this seam,
// before they are stamped/dual-written/tagged, and the carry-only change is still saved (#1495).
describe("settleForensicImport — carries learned renames onto rows already in the case (#1495)", () => {
  const OLD = "WIN-UK1GV882OK6";
  const NEW = "DESKTOP-16OJFO6";
  const ledger = (events: ForensicEvent[]): InvestigationState =>
    ({
      forensicTimeline: events,
      iocs: [],
      hostRenames: [
        { formerName: OLD, currentName: NEW, until: "2026-08-26T13:49:52.000Z", basis: "machine-account" },
      ],
    }) as unknown as InvestigationState;

  it("re-homes an older bare row, saves and broadcasts even when this import added no row", async () => {
    const older: ForensicEvent = {
      ...ev("older", "High", `x @ ${OLD}`),
      asset: OLD,
      assetRecord: OLD,
      timestamp: "2025-12-05T03:02:24Z",
    };
    const before = state([older]);
    const merged = ledger([older]);
    const save = vi.fn(async (_s: InvestigationState) => {});
    const onState = vi.fn();
    let demoted: InvestigationState | null = null;
    const deps = {
      stateStore: { load: async () => merged, save },
      onState,
      autoTagImported: async () => {},
      demoteForensicForCase: async () => demoted ?? merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(save).toHaveBeenCalledOnce();
    const saved = save.mock.calls[0][0];
    expect(saved.forensicTimeline[0].asset).toBe(NEW);
    expect(saved.forensicTimeline[0].description).toContain(`[logged under former hostname ${OLD}]`);
    expect(onState).toHaveBeenCalledWith(saved);
    demoted = saved;
  });

  it("the re-homed older row is not counted as added (not dual-written twice)", async () => {
    const older: ForensicEvent = {
      ...ev("older", "High", `x @ ${OLD}`),
      asset: OLD,
      assetRecord: OLD,
      timestamp: "2025-12-05T03:02:24Z",
    };
    const fresh = ev("new", "High");
    const before = state([older]);
    const merged = ledger([older, fresh]);
    const append = vi.fn(async (_c: string, rows: ForensicEvent[]) => rows.length);
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: { append },
      autoTagImported: async () => {},
      demoteForensicForCase: async () => merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(append.mock.calls[0][1].map((e) => e.id)).toEqual(["new"]);
  });
});

// The super-timeline holds its own copies of every row — dual-written, or Info rows demote captured
// that live only there — and the carry above never sees them (#1508). When the settle learns a
// rename, the seam re-homes the super-timeline from its own rows, so both records show one host.
describe("settleForensicImport — re-homes the super-timeline copies too (#1508)", () => {
  const OLD = "WIN-UK1GV882OK6";
  const NEW = "DESKTOP-16OJFO6";
  const renames: InvestigationState["hostRenames"] = [
    { formerName: OLD, currentName: NEW, until: "2026-08-26T13:49:52.000Z", basis: "machine-account" },
  ];
  const under = (id: string, severity: ForensicEvent["severity"]): ForensicEvent => ({
    ...ev(id, severity, `x @ ${OLD}`),
    asset: OLD,
    assetRecord: OLD,
    timestamp: "2025-12-05T03:02:24Z",
  });
  function fakeSuper(rows: ForensicEvent[]) {
    const rehome = vi.fn(async (_c: string, events: ForensicEvent[]) => events.length);
    return {
      store: {
        append: vi.fn(async (_c: string, events: ForensicEvent[]) => events.length),
        rehome,
        eventBatches: async function* () {
          yield rows.slice(0, 1);
          yield rows.slice(1);
        },
      },
      rehome,
    };
  }

  it("re-homes the super-only Info row AND the carried row's copy when the ledger is learned", async () => {
    const carried = under("carried", "High");
    const before = state([carried]); // no ledger yet
    const merged = { ...state([carried]), hostRenames: renames } as InvestigationState;
    const superOnly = under("info-only", "Info");
    const { store, rehome } = fakeSuper([superOnly, carried]);
    const onSuperTimeline = vi.fn();
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: store,
      onSuperTimeline,
      autoTagImported: async () => {},
      demoteForensicForCase: async () => merged,
    };
    await settleForensicImport(deps, "c1", before);
    const written = rehome.mock.calls.flatMap((c) => c[1]);
    expect(written.map((e) => e.id).sort()).toEqual(["carried", "info-only"]);
    for (const e of written) {
      expect(e.asset).toBe(NEW);
      expect(e.description).toContain(`[logged under former hostname ${OLD}]`);
    }
    expect(written.find((e) => e.id === "info-only")?.severity).toBe("Info");
    expect(onSuperTimeline).toHaveBeenCalledWith("c1");
  });

  it("runs when the ledger changed even though no forensic row moved (every old-name row was Info)", async () => {
    const before = state([ev("unrelated", "High")]);
    const merged = { ...state([ev("unrelated", "High")]), hostRenames: renames } as InvestigationState;
    const { store, rehome } = fakeSuper([under("info-only", "Info")]);
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: store,
      autoTagImported: async () => {},
      demoteForensicForCase: async () => merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(rehome.mock.calls.flatMap((c) => c[1]).map((e) => e.id)).toEqual(["info-only"]);
  });

  it("touches nothing when the ledger did not change", async () => {
    const before = { ...state([ev("a", "High")]), hostRenames: renames } as InvestigationState;
    const merged = {
      ...state([ev("a", "High"), ev("b", "High")]),
      hostRenames: renames,
    } as InvestigationState;
    const { store, rehome } = fakeSuper([under("info-only", "Info")]);
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: store,
      autoTagImported: async () => {},
      demoteForensicForCase: async () => merged,
    };
    await settleForensicImport(deps, "c1", before);
    expect(rehome).not.toHaveBeenCalled();
  });

  it("a failing super re-home does not fail the import", async () => {
    const before = state([]);
    const merged = { ...state([]), hostRenames: renames } as InvestigationState;
    const { store } = fakeSuper([under("info-only", "Info")]);
    store.rehome.mockRejectedValue(new Error("disk"));
    const deps = {
      stateStore: { load: async () => merged, save: async () => {} },
      superTimelineStore: store,
      autoTagImported: async () => {},
      demoteForensicForCase: async () => merged,
    };
    await expect(settleForensicImport(deps, "c1", before)).resolves.toBeTruthy();
  });
});
