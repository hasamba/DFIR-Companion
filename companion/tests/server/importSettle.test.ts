import { describe, it, expect, vi, afterEach } from "vitest";
import { settleForensicImport } from "../../src/routes/importSettle.js";
import type { ForensicEvent, InvestigationState } from "../../src/analysis/stateTypes.js";
import { LoggerImpl, type LogWriter } from "../../src/logging/logger.js";
import { getServerLogger, setServerLogger } from "../../src/logging/serverLogger.js";
import { memoryRowStore } from "../helpers/memoryRowStore.js";

// The one seam every import crosses: dual-write the ADDED rows → tag them → demote → diff against
// the post-demote state. Pinned here so a route can neither skip a step nor run them out of order.
//
// #1874: the seam reads and writes rows, not the whole case, so these tests run it over an
// in-memory row store (tests/helpers/memoryRowStore.ts) instead of a { load, save } fake; `before`
// is still a full state, which the seam accepts from a legacy caller.

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
  return { caseId: "c1", forensicTimeline: events, iocs } as unknown as InvestigationState;
}

describe("settleForensicImport", () => {
  it("dual-writes only the rows the import added, tags them, demotes, and diffs post-demote", async () => {
    const calls: string[] = [];
    const before = state([ev("old", "High")]);
    const merged = state([ev("old", "High"), ev("info", "Info"), ev("high", "High")]);
    const store = memoryRowStore(merged);
    const deps = {
      stateStore: store,
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
      demoteForensic: vi.fn(async () => {
        calls.push("demote");
        return store.demoteInfo();
      }),
    };
    const r = await settleForensicImport(deps, "c1", before);
    expect(calls).toEqual(["append:info,high", "notify", "tag:info,high", "demote"]);
    expect(r.superTimelineAddedCount).toBe(2);
    // The diff is against the POST-demote state: the Info row is not "+1 event".
    expect(r.timelineDiff.added.map((e) => e.description)).toEqual(["high"]);
    expect((await store.load()).forensicTimeline.map((e) => e.id)).toEqual(["old", "high"]);
    expect((await r.addedEvents()).map((e) => e.id)).toEqual(["high"]);
  });

  it("returns the retained count the store reports, not the number handed to it", async () => {
    const before = state([]);
    const store = memoryRowStore(state([ev("a", "Info"), ev("b", "Info")]));
    const deps = {
      stateStore: store,
      superTimelineStore: { append: async () => 1 }, // the cap kept one
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
    };
    expect((await settleForensicImport(deps, "c1", before)).superTimelineAddedCount).toBe(1);
  });

  it("still tags and demotes when the super-timeline append fails", async () => {
    const before = state([]);
    const store = memoryRowStore(state([ev("a", "Info")]));
    const tagged: string[] = [];
    const deps = {
      stateStore: store,
      superTimelineStore: {
        append: async () => {
          throw new Error("disk");
        },
      },
      autoTagImported: async (_c: string, events: ForensicEvent[]) => {
        tagged.push(...events.map((e) => e.id));
      },
      demoteForensic: () => store.demoteInfo(),
    };
    const r = await settleForensicImport(deps, "c1", before);
    expect(tagged).toEqual(["a"]);
    expect(r.superTimelineAddedCount).toBe(0);
    expect(r.forensicCount).toBe(0);
  });

  it("skips the dual-write when no store is wired, and demotes anyway", async () => {
    const store = memoryRowStore(state([ev("a", "Info")]));
    const demote = vi.fn(() => store.demoteInfo());
    const r = await settleForensicImport(
      {
        stateStore: store,
        autoTagImported: async () => {},
        demoteForensic: demote,
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
  it("stamps importedAt and importBatchId on rows genuinely new to this case, and writes only them", async () => {
    const before = state([ev("old", "High")]);
    const store = memoryRowStore(state([ev("old", "High"), ev("new1", "High"), ev("new2", "High")]));
    const deps = {
      stateStore: store,
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
    };
    await settleForensicImport(deps, "c1", before);
    expect(store.writes).toEqual([["new1", "new2"]]);
    const byId = new Map((await store.load()).forensicTimeline.map((e) => [e.id, e]));
    expect(byId.get("old")!.importedAt).toBeUndefined();
    expect(byId.get("old")!.importBatchId).toBeUndefined();
    expect(byId.get("new1")!.importedAt).toEqual(expect.any(String));
    expect(byId.get("new2")!.importedAt).toBe(byId.get("new1")!.importedAt);
    expect(byId.get("new1")!.importBatchId).toEqual(expect.any(String));
    expect(byId.get("new2")!.importBatchId).toBe(byId.get("new1")!.importBatchId);
  });

  // #1174: dashboard/WS subscribers were not notified when the importedAt/importBatchId stamps were
  // saved — only whenever a LATER broadcast happened to fire. The settle announces its own change.
  it("announces the changed case once, from the settle itself", async () => {
    const before = state([ev("old", "High")]);
    const store = memoryRowStore(state([ev("old", "High"), ev("new1", "High")]));
    const onStateChanged = vi.fn();
    const deps = {
      stateStore: store,
      onStateChanged,
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
    };
    await settleForensicImport(deps, "c1", before);
    expect(onStateChanged).toHaveBeenCalledOnce();
    expect(onStateChanged).toHaveBeenCalledWith("c1");
  });

  it("a caller with only a state broadcaster gets the stamped state, loaded once", async () => {
    const before = state([ev("old", "High")]);
    const store = memoryRowStore(state([ev("old", "High"), ev("new1", "High")]));
    const onState = vi.fn();
    const deps = {
      stateStore: store,
      onState,
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
    };
    await settleForensicImport(deps, "c1", before);
    expect(onState).toHaveBeenCalledOnce();
    const pushed = onState.mock.calls[0][0] as InvestigationState;
    expect(pushed.forensicTimeline.find((e) => e.id === "new1")?.importedAt).toEqual(expect.any(String));
  });

  it("does not announce anything when nothing new was imported", async () => {
    const before = state([ev("old", "High")]);
    const store = memoryRowStore(state([ev("old", "High")]));
    const onStateChanged = vi.fn();
    const deps = {
      stateStore: store,
      onStateChanged,
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
    };
    await settleForensicImport(deps, "c1", before);
    expect(onStateChanged).not.toHaveBeenCalled();
  });

  it("does not re-stamp a row that already existed before this import", async () => {
    const before = state([ev("old", "High")]);
    const store = memoryRowStore(state([ev("old", "High")])); // nothing new — a no-op import
    const deps = {
      stateStore: store,
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
    };
    await settleForensicImport(deps, "c1", before);
    expect(store.writes.flat()).toEqual([]);
  });

  it("stamps new rows even when no super-timeline store is configured", async () => {
    const store = memoryRowStore(state([ev("new1", "Low")]));
    const deps = {
      stateStore: store,
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
    };
    await settleForensicImport(deps, "c1", state([]));
    expect((await store.load()).forensicTimeline[0].importedAt).toEqual(expect.any(String));
  });

  it("persists the stamp in the store, not only on the rows it hands on", async () => {
    const store = memoryRowStore(state([ev("new1", "High")]));
    const deps = {
      stateStore: store,
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
    };
    const r = await settleForensicImport(deps, "c1", state([]));
    expect((await store.load()).forensicTimeline[0].importedAt).toEqual(expect.any(String));
    expect((await r.addedEvents())[0].importedAt).toEqual(expect.any(String));
  });

  it("gives two separate imports different importedAt and importBatchId values", async () => {
    const run = async (id: string): Promise<ForensicEvent> => {
      const store = memoryRowStore(state([ev(id, "High")]));
      await settleForensicImport(
        { stateStore: store, autoTagImported: async () => {}, demoteForensic: () => store.demoteInfo() },
        "c1",
        state([]),
      );
      return (await store.load()).forensicTimeline[0];
    };
    const first = await run("a");
    await new Promise((r) => setTimeout(r, 2));
    const second = await run("b");
    expect(second.importBatchId).not.toBe(first.importBatchId);
    expect(second.importedAt).not.toBe(first.importedAt);
  });

  it("stamps the rows dual-written to the super-timeline and offered to the tagger too", async () => {
    const store = memoryRowStore(state([ev("new1", "Info")]));
    let taggedEvents: ForensicEvent[] = [];
    let appendedEvents: ForensicEvent[] = [];
    const deps = {
      stateStore: store,
      superTimelineStore: {
        append: async (_c: string, events: ForensicEvent[]) => {
          appendedEvents = events;
          return events.length;
        },
      },
      autoTagImported: async (_c: string, events: ForensicEvent[]) => {
        taggedEvents = events;
      },
      demoteForensic: () => store.demoteInfo(),
    };
    await settleForensicImport(deps, "c1", state([]));
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
    const store = memoryRowStore(
      state([ev("old", "High"), ev("info", "Info"), ev("high", "High")], [ioc("10.0.0.1"), ioc("10.0.0.2")]),
    );
    const deps = {
      stateStore: store,
      superTimelineStore: { append: async (_c: string, events: ForensicEvent[]) => events.length },
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
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
    const store = memoryRowStore(unchanged);
    const deps = {
      stateStore: store,
      superTimelineStore: { append: async () => 0 },
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
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
      caseId: "c1",
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
    const store = memoryRowStore(ledger([older]));
    const onStateChanged = vi.fn();
    const deps = {
      stateStore: store,
      onStateChanged,
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
    };
    await settleForensicImport(deps, "c1", before);
    expect(store.writes).toEqual([["older"]]);
    const saved = await store.load();
    expect(saved.forensicTimeline[0].asset).toBe(NEW);
    expect(saved.forensicTimeline[0].description).toContain(`[logged under former hostname ${OLD}]`);
    expect(onStateChanged).toHaveBeenCalledWith("c1");
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
    const store = memoryRowStore(ledger([older, fresh]));
    const append = vi.fn(async (_c: string, rows: ForensicEvent[]) => rows.length);
    const deps = {
      stateStore: store,
      superTimelineStore: { append },
      autoTagImported: async () => {},
      demoteForensic: () => store.demoteInfo(),
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
      stateStore: memoryRowStore(merged),
      superTimelineStore: store,
      onSuperTimeline,
      autoTagImported: async () => {},
      demoteForensic: async () => [],
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
      stateStore: memoryRowStore(merged),
      superTimelineStore: store,
      autoTagImported: async () => {},
      demoteForensic: async () => [],
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
      stateStore: memoryRowStore(merged),
      superTimelineStore: store,
      autoTagImported: async () => {},
      demoteForensic: async () => [],
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
      stateStore: memoryRowStore(merged),
      superTimelineStore: store,
      autoTagImported: async () => {},
      demoteForensic: async () => [],
    };
    await expect(settleForensicImport(deps, "c1", before)).resolves.toBeTruthy();
  });
});

// #1530 — the first-party-egress downgrade runs inside this seam, and WHERE it runs is the point:
// before the dual-write, so the super-timeline keeps the Info copy, and before the tagger, so a
// tagger rule can raise the row straight back.
describe("settleForensicImport — first-party update traffic", () => {
  function oneDriveRow(id: string): ForensicEvent {
    return {
      ...ev(id, "Medium", "Sigma: Net Conn (Sysmon Alert) - Sysmon Network connection (EID 3)"),
      canonical: {
        schemaVersion: "1.1.0",
        event: { category: "network", type: "connection" },
        network: { source: { address: "192.0.2.10" }, destination: { address: "150.171.109.82", port: 443 } },
        file: {
          path: "C:\\Users\\a\\AppData\\Local\\Microsoft\\OneDrive\\StandaloneUpdater\\OneDriveSetup.exe",
          name: "OneDriveSetup.exe",
        },
        time: { observed: "2026-08-30 15:02:40", normalized: "2026-08-30T15:02:40Z" },
      },
    } as ForensicEvent;
  }

  it("lowers the row before the dual-write and the tagger see it", async () => {
    const seen: Record<string, ForensicEvent[]> = {};
    const rows = memoryRowStore(state([ev("old", "High"), oneDriveRow("new")]));
    const deps = {
      stateStore: rows,
      superTimelineStore: {
        append: async (_c: string, events: ForensicEvent[]) => {
          seen.super = events;
          return events.length;
        },
      },
      autoTagImported: async (_c: string, events: ForensicEvent[]) => {
        seen.tagged = events;
      },
      demoteForensic: async () => [],
    };
    await settleForensicImport(deps, "c1", state([ev("old", "High")]));
    const saved = await rows.load();
    expect(seen.super.map((e) => e.severity)).toEqual(["Info"]);
    expect(seen.super[0].description).toContain("first-party update traffic");
    expect(seen.tagged.map((e) => e.severity)).toEqual(["Info"]);
    expect(saved?.forensicTimeline.find((e) => e.id === "new")?.severity).toBe("Info");
  });

  it("leaves the grade alone when no super-timeline store is wired — demote would delete the row", async () => {
    const rows = memoryRowStore(state([oneDriveRow("new")]));
    const deps = { stateStore: rows, autoTagImported: async () => {}, demoteForensic: async () => [] };
    await settleForensicImport(deps, "c1", state([]));
    const saved = await rows.load();
    expect(saved?.forensicTimeline[0].severity).toBe("Medium");
  });
});

// #1958 — generic Sysmon registry alerts are lowered in the #1530 position: before the dual-write
// and the tagger. A key on the pass's own keep-list keeps its grade with the tagger doing nothing,
// so the persistence rows never depend on auto-tagging.
describe("settleForensicImport — generic Sysmon registry alerts", () => {
  function regRow(id: string, key: string): ForensicEvent {
    return ev(
      id,
      "Medium",
      `Hayabusa: Reg Key Value Set (Sysmon Alert) (EID 13 Sysmon) — EventType=SetValue TgtObj=${key} Details=DWORD (0x00000001) @ HOST-01`,
    );
  }
  const ORDINARY = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Foo";
  const RUN = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater";

  it("lowers an ordinary key before the dual-write; demote then takes it out of the forensic timeline", async () => {
    const seen: Record<string, ForensicEvent[]> = {};
    const rows = memoryRowStore(state([regRow("ord", ORDINARY), regRow("run", RUN)]));
    const deps = {
      stateStore: rows,
      superTimelineStore: {
        append: async (_c: string, events: ForensicEvent[]) => {
          seen.super = events;
          return events.length;
        },
      },
      autoTagImported: async (_c: string, events: ForensicEvent[]) => {
        seen.tagged = events;
      },
      demoteForensic: () => rows.demoteInfo(),
    };
    await settleForensicImport(deps, "c1", state([]));
    const bySuper = new Map(seen.super.map((e) => [e.id, e]));
    expect(bySuper.get("ord")?.severity).toBe("Info");
    expect(bySuper.get("ord")?.description).toContain("generic Sysmon alert");
    expect(seen.tagged.find((e) => e.id === "ord")?.severity).toBe("Info");
    // The Run-key row keeps Medium with a no-op tagger: the keep-list, not the tagger, holds it.
    expect(bySuper.get("run")?.severity).toBe("Medium");
    const saved = await rows.load();
    expect(saved?.forensicTimeline.map((e) => e.id)).toEqual(["run"]);
  });

  it("leaves the grade alone when no super-timeline store is wired — demote would delete the row", async () => {
    const rows = memoryRowStore(state([regRow("ord", ORDINARY)]));
    const deps = { stateStore: rows, autoTagImported: async () => {}, demoteForensic: async () => [] };
    await settleForensicImport(deps, "c1", state([]));
    expect((await rows.load())?.forensicTimeline[0].severity).toBe("Medium");
  });
});
