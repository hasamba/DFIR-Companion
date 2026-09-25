import { describe, it, expect } from "vitest";
import {
  buildCollectionInventory,
  coveredOnAll,
  emptySettledClasses,
  inventorySignature,
  renderCollectionInventory,
  sanitizeHuntJobs,
} from "../../src/analysis/collectionInventory.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { VeloHuntJob } from "../../src/analysis/veloHuntStore.js";
import { buildHostAliasIndex, type HostAliasIndex } from "../../src/analysis/hostAlias.js";

// #1588 — the collection inventory is what the model judges every "not observed" answer against, so
// it must be deterministic and must never call a detection feed "collection". Built on the
// INC-2026-005 shape: Sigma/Chainsaw hits on Sysmon, no raw Sysmon, a cleared Security log.

function ev(id: string, over: Partial<ForensicEvent> = {}): ForensicEvent {
  return {
    id,
    timestamp: "2026-08-28T09:00:00Z",
    description: `event ${id}`,
    severity: "Medium",
    mitreTechniques: [],
    relatedFindingIds: [],
    sourceScreenshots: [],
    asset: "WS01",
    ...over,
  };
}

const CHAINSAW = (id: string): ForensicEvent =>
  ev(id, { sources: ["Chainsaw"], description: "Sigma: Suspicious file write" });
const PREFETCH = ev("p1", { sources: ["Velociraptor"], artifactName: "Windows.Forensics.Prefetch" });
const CLEAR = (id: string, at: string, host = "WS01"): ForensicEvent =>
  ev(id, {
    timestamp: at,
    asset: host,
    description: "Security audit log cleared (EID 1102)",
    sources: ["Velociraptor"],
  });

function job(over: Partial<VeloHuntJob>): VeloHuntJob {
  return {
    bundleId: "b",
    bundleName: "B",
    artifacts: [],
    huntId: "H.1",
    launchedAt: "2026-08-28T10:00:00Z",
    waitMinutes: 5,
    collectAt: "2026-08-28T10:05:00Z",
    status: "imported",
    // Every scheduled client finished (#1612) and the one client, WS01, finished cleanly (#1625), so a
    // test about another bound isolates that bound.
    clientCounts: { scheduled: 1, completed: 1, errors: 0 },
    reachedClients: [{ clientId: "C.1", hostname: "WS01", fqdn: "", os: "windows" }],
    ...over,
  };
}

describe("collection inventory (#1588)", () => {
  it("a detection feed built on Sysmon is not file-activity collection", () => {
    const inv = buildCollectionInventory({ events: [CHAINSAW("c1"), CHAINSAW("c2"), PREFETCH] });
    expect(coveredOnAll(inv, ["WS01"])).toEqual(new Set(["execution"]));
    const text = renderCollectionInventory(inv);
    expect(text).toContain(
      "- WS01: collected raw: execution; no raw collection found: file-activity, network, persistence",
    );
    expect(text).toContain(
      "file-activity → Windows.EventLogs.Evtx (Microsoft-Windows-Sysmon/Operational EID 11/23",
    );
    expect(text).toContain("Chainsaw (detections) 2");
    expect(text).toContain("Windows.Forensics.Prefetch (raw) 1");
  });

  it("raw Sysmon collected through Windows.EventLogs.Evtx covers the class its record type names", () => {
    const sysmonFile = ev("s1", {
      sources: ["Velociraptor"],
      artifactName: "Windows.EventLogs.Evtx",
      sourceRecordId: "evtx:microsoft-windows-sysmon/operational:42",
      canonical: { event: { category: "file", type: "creation" } } as ForensicEvent["canonical"],
    });
    expect(
      coveredOnAll(buildCollectionInventory({ events: [sysmonFile] }), ["WS01"]).has("file-activity"),
    ).toBe(true);
    // A rule hit on the SAME record is still a detection feed.
    const hit = { ...sysmonFile, id: "s2", sources: ["Hayabusa"], artifactName: undefined };
    expect(coveredOnAll(buildCollectionInventory({ events: [hit] }), ["WS01"]).has("file-activity")).toBe(
      false,
    );
  });

  it("coverage is per host: WS01's collection says nothing about WS02", () => {
    const inv = buildCollectionInventory({
      events: [PREFETCH, ev("w2", { asset: "WS02", sources: ["Chainsaw"] })],
    });
    expect(coveredOnAll(inv, ["WS01"]).has("execution")).toBe(true);
    expect(coveredOnAll(inv, ["WS02"]).has("execution")).toBe(false);
    expect(coveredOnAll(inv, ["WS01", "WS02"]).has("execution")).toBe(false);
  });

  it("a log clear is recorded per host and channel with its LATEST time; wevtutil running is not a clear", () => {
    const wevtutil = ev("x", {
      description: "Prefetch: WEVTUTIL.EXE executed",
      mitreTechniques: ["T1070.001"],
      artifactName: "Windows.Forensics.Prefetch",
    });
    const inv = buildCollectionInventory({
      events: [CLEAR("k1", "2026-08-28T09:10:00Z"), CLEAR("k2", "2026-08-28T09:12:03Z"), wevtutil],
    });
    expect(inv.cleared).toEqual([
      { host: "WS01", channel: "Security", at: "2026-08-28T09:12:03Z", count: 2 },
    ]);
    expect(renderCollectionInventory(inv)).toContain(
      "- Cleared: Security log on WS01 at 2026-08-28T09:12:03Z (cleared 2×; latest shown)",
    );
  });

  it("names the channel a System 104 row says was cleared, and admits when it does not say", () => {
    const named = ev("n", { description: "Event log cleared: The Windows PowerShell log file was cleared." });
    const bare = ev("b", { description: "Event log cleared", asset: "WS02" });
    const inv = buildCollectionInventory({ events: [named, bare] });
    expect(inv.cleared.map((c) => `${c.host}:${c.channel}`)).toEqual(["WS01:Windows PowerShell", "WS02:"]);
    expect(renderCollectionInventory(inv)).toContain("An event log (channel not recorded) on WS02");
  });

  it("reads imported hunt metadata only: empty, failed, truncated, archive-only, still running", () => {
    const inv = buildCollectionInventory({
      events: [PREFETCH],
      hunts: [
        job({
          huntId: "H.1",
          artifacts: [
            "Windows.Forensics.Prefetch",
            "Windows.EventLogs.Evtx",
            "Windows.NTFS.MFT",
            "Windows.Search.FileFinder",
            "Custom.X",
          ],
          emptyArtifacts: ["Windows.Search.FileFinder"],
          skippedArtifacts: [{ name: "Windows.NTFS.MFT", error: "timeout" }],
          truncatedArtifacts: [{ name: "Custom.X", kept: 500, total: 501 }],
        }),
        job({ huntId: "H.2", status: "running", artifacts: ["Windows.System.TaskScheduler"] }),
        job({ huntId: "H.3", status: "error", artifacts: ["Windows.Sysinternals.Autoruns"] }),
      ],
    });
    expect(inv.hunts.map((h) => `${h.artifact}=${h.state}`)).toEqual([
      "Custom.X=truncated",
      "Windows.EventLogs.Evtx=archive-only",
      "Windows.NTFS.MFT=failed",
      "Windows.Search.FileFinder=empty",
      "Windows.System.TaskScheduler=running",
    ]);
  });

  it("is deterministic: input order does not change the text", () => {
    const events = [
      CHAINSAW("c1"),
      PREFETCH,
      CLEAR("k1", "2026-08-28T09:12:03Z"),
      ev("w2", { asset: "WS02" }),
    ];
    const a = renderCollectionInventory(buildCollectionInventory({ events }));
    const b = renderCollectionInventory(buildCollectionInventory({ events: [...events].reverse() }));
    expect(a).toBe(b);
    expect(a).toContain("Rules for negative answers:");
  });

  it("the hunt signature changes when a hunt's outcome changes, and not with list order", () => {
    const one = job({ huntId: "H.1", artifacts: ["A"] });
    const two = job({ huntId: "H.2", artifacts: ["B"] });
    expect(inventorySignature([one, two])).toBe(inventorySignature([two, one]));
    expect(inventorySignature([one])).not.toBe(inventorySignature([{ ...one, emptyArtifacts: ["A"] }]));
  });

  // #1604 — a hunt's silence can be BOUNDED: by the analyst's time window or by a result filter.
  // "Nothing in the window" or "nothing matched" is not "the artifact holds nothing", so a bounded
  // empty may qualify an answer but never settle an evidence class.
  describe("bounded empty hunts (#1604)", () => {
    const PF = "Windows.Forensics.Prefetch";
    const MFT = "Windows.NTFS.MFT";
    const window = (names: string[] | undefined, over: Record<string, unknown> = {}) => ({
      start: "2026-06-01T00:00:00.000Z",
      end: "2026-06-30T00:00:00.000Z",
      scopedArtifacts: names ? names.length : 1,
      totalArtifacts: 2,
      degraded: false,
      ...(names ? { scopedArtifactNames: names } : {}),
      ...over,
    });
    const settled = (hunts: VeloHuntJob[]) =>
      [...emptySettledClasses(buildCollectionInventory({ events: [], hunts }), "WS01")].sort();

    it("a clean unbounded fleet-wide empty still settles its class", () => {
      expect(settled([job({ artifacts: [PF], emptyArtifacts: [PF] })])).toEqual(["execution"]);
    });

    it("an empty artifact that took the time window does not settle, and says it was time-bounded", () => {
      const hunts = [job({ artifacts: [PF], emptyArtifacts: [PF], timeScope: window([PF]) })];
      expect(settled(hunts)).toEqual([]);
      const text = renderCollectionInventory(buildCollectionInventory({ events: [], hunts }));
      expect(text).toContain("time-bounded");
      expect(text).toContain("2026-06-01T00:00:00.000Z → 2026-06-30T00:00:00.000Z");
    });

    it("in a mixed hunt only the artifact that took the window is bounded", () => {
      const hunts = [job({ artifacts: [PF, MFT], emptyArtifacts: [PF, MFT], timeScope: window([MFT]) })];
      expect(settled(hunts)).toEqual(["execution"]);
    });

    it("a legacy scoped job that does not name its scoped artifacts bounds every artifact", () => {
      const hunts = [job({ artifacts: [PF], emptyArtifacts: [PF], timeScope: window(undefined) })];
      expect(settled(hunts)).toEqual([]);
      expect(renderCollectionInventory(buildCollectionInventory({ events: [], hunts }))).toContain(
        "not recorded",
      );
    });

    it("a window that reached no artifact bounds nothing, degraded or not", () => {
      for (const degraded of [false, true]) {
        const hunts = [job({ artifacts: [PF], emptyArtifacts: [PF], timeScope: window([], { degraded }) })];
        expect(settled(hunts)).toEqual(["execution"]);
      }
    });

    it("a result filter on the artifact bounds it; a filter on another artifact does not", () => {
      const filtered = [job({ artifacts: [PF], emptyArtifacts: [PF], filters: { [PF]: "Name =~ 'x'" } })];
      expect(settled(filtered)).toEqual([]);
      expect(renderCollectionInventory(buildCollectionInventory({ events: [], hunts: filtered }))).toContain(
        "filter",
      );
      const other = [job({ artifacts: [PF], emptyArtifacts: [PF], filters: { [MFT]: "x", [PF]: "  " } })];
      expect(settled(other)).toEqual(["execution"]);
    });

    it("names both bounds when a filter and a time window apply", () => {
      const hunts = [
        job({ artifacts: [PF], emptyArtifacts: [PF], filters: { [PF]: "x" }, timeScope: window([PF]) }),
      ];
      const text = renderCollectionInventory(buildCollectionInventory({ events: [], hunts }));
      expect(text).toContain("time-bounded");
      expect(text).toContain("filter");
    });

    it("an unbounded empty beside a bounded one for the same artifact still settles, in either order", () => {
      const bounded = job({ huntId: "H.1", artifacts: [PF], emptyArtifacts: [PF], timeScope: window([PF]) });
      const clean = job({ huntId: "H.2", artifacts: [PF], emptyArtifacts: [PF] });
      expect(settled([bounded, clean])).toEqual(["execution"]);
      expect(settled([clean, bounded])).toEqual(["execution"]);
    });

    it("an exclude-label or OS-targeted hunt is not fleet-wide and settles nothing", () => {
      for (const target of [{ excludeLabels: ["dc"] }, { os: "windows" }] as VeloHuntJob["target"][])
        expect(settled([job({ artifacts: [PF], emptyArtifacts: [PF], target })])).toEqual([]);
    });

    it("malformed time scope or filters from an old velo-hunt.json never throw", () => {
      const raw = [
        { ...job({ artifacts: [PF], emptyArtifacts: [PF] }), timeScope: "junk", filters: 7 },
        {
          ...job({ huntId: "H.2", artifacts: [MFT], emptyArtifacts: [MFT] }),
          timeScope: { scopedArtifactNames: "x" },
        },
      ] as unknown as VeloHuntJob[];
      expect(() => settled(raw)).not.toThrow();
    });

    it("the signature changes with the bounds and the target", () => {
      const base = job({ artifacts: [PF], emptyArtifacts: [PF] });
      const sig = inventorySignature([base]);
      for (const changed of [
        { ...base, timeScope: window([PF]) },
        { ...base, filters: { [PF]: "x" } },
        { ...base, target: { excludeLabels: ["dc"] } },
        { ...base, target: { includeLabels: ["finance"] } },
      ])
        expect(inventorySignature([changed])).not.toBe(sig);
      expect(inventorySignature([{ ...base, timeScope: window([PF]) }])).not.toBe(
        inventorySignature([{ ...base, timeScope: window([]) }]),
      );
    });
  });

  // #1625 — Velociraptor schedules a hunt on a client only when it checks in, so the hunt counts
  // cannot see a client that stayed offline. An empty result settles a class only for the hosts whose
  // flow finished without error.
  describe("per-host settlement of empty hunts (#1625)", () => {
    const PF = "Windows.Forensics.Prefetch";
    type Reached = { clientId: string; hostname: string; fqdn: string; os: string };
    const win = (id: string, hostname: string, fqdn = ""): Reached => ({
      clientId: id,
      hostname,
      fqdn,
      os: "windows",
    });
    const inv = (hunts: VeloHuntJob[], aliasIndex?: HostAliasIndex) =>
      buildCollectionInventory({ events: [], hunts, aliasIndex });
    const settledOn = (host: string, hunts: VeloHuntJob[], aliasIndex?: HostAliasIndex) =>
      [...emptySettledClasses(inv(hunts, aliasIndex), host)].sort();
    const empty = (reachedClients?: unknown, over: Partial<VeloHuntJob> = {}) =>
      job({ artifacts: [PF], emptyArtifacts: [PF], reachedClients, ...over } as Partial<VeloHuntJob>);

    it("1 of 100 clients online: the empty settles for that host only, not for the 99 it never reached", () => {
      const hunts = [
        empty([win("C.1", "WS01")], { clientCounts: { scheduled: 1, completed: 1, errors: 0 } }),
      ];
      expect(settledOn("WS01", hunts)).toEqual(["execution"]);
      expect(settledOn("WS02", hunts)).toEqual([]);
      const text = renderCollectionInventory(inv(hunts));
      expect(text).toContain("returned no rows on ws01");
      expect(text).toContain("silence on any other host is not absence");
    });

    it("a hunt collected before the per-host list was recorded settles nothing, and says why", () => {
      const hunts = [empty(undefined)];
      expect(settledOn("WS01", hunts)).toEqual([]);
      expect(renderCollectionInventory(inv(hunts))).toContain(
        "which hosts the hunt finished on is not recorded",
      );
    });

    it("a hunt that finished on no client settles nothing, and says so", () => {
      const hunts = [empty([])];
      expect(settledOn("WS01", hunts)).toEqual([]);
      expect(renderCollectionInventory(inv(hunts))).toContain("finished cleanly on no client");
    });

    it("a clean flow on a Linux client does not settle a Windows artifact there", () => {
      const hunts = [
        empty([{ clientId: "C.2", hostname: "web01", fqdn: "", os: "linux" }, win("C.1", "WS01")]),
      ];
      expect(settledOn("web01", hunts)).toEqual([]);
      expect(settledOn("WS01", hunts)).toEqual(["execution"]);
      expect(settledOn("WS01", [empty([{ clientId: "C.1", hostname: "WS01", fqdn: "", os: "" }])])).toEqual(
        [],
      );
    });

    it("unfinished or failed clients no longer block the hosts that did finish, and the counts are shown", () => {
      const hunts = [
        empty([win("C.1", "WS01")], { clientCounts: { scheduled: 4, completed: 2, errors: 1 } }),
      ];
      expect(settledOn("WS01", hunts)).toEqual(["execution"]);
      expect(renderCollectionInventory(inv(hunts))).toContain(
        "only 2 of 4 scheduled client(s) finished, 1 with errors",
      );
    });

    it("matches the host by FQDN, and by client id through the alias index", () => {
      expect(settledOn("ws01.example.com", [empty([win("C.1", "WS01", "ws01.example.com")])])).toEqual([
        "execution",
      ]);
      // The short name alone is never proof: ws01 does not match ws01.example.com.
      expect(settledOn("ws01.example.com", [empty([win("C.1", "WS01")])])).toEqual([]);
      const idx = buildHostAliasIndex([{ clientId: "C.9", hostname: "ws09", fqdn: "ws09.example.com" }], {});
      // The client id decides when the index knows it, even if the recorded name went stale.
      expect(settledOn("ws09.example.com", [empty([win("C.9", "old-name")])], idx)).toEqual(["execution"]);
      expect(settledOn("old-name", [empty([win("C.9", "old-name")])], idx)).toEqual([]);
    });

    it("two empty hunts that reached different hosts settle for both", () => {
      const hunts = [
        empty([win("C.1", "WS01")], { huntId: "H.1" }),
        empty([win("C.2", "WS02")], { huntId: "H.2" }),
      ];
      expect(settledOn("WS01", hunts)).toEqual(["execution"]);
      expect(settledOn("WS02", hunts)).toEqual(["execution"]);
      expect(renderCollectionInventory(inv(hunts))).toContain("across 2 hunts");
    });

    it("malformed per-host lists from an old velo-hunt.json never throw and never settle", () => {
      for (const bad of ["junk", 7, { clientId: "C.1" }, [{ hostname: "WS01", os: "windows" }], [null, 3]])
        expect(settledOn("WS01", [empty(bad)])).toEqual([]);
    });

    it("the signature changes with the per-host list, and unknown differs from empty", () => {
      const sig = inventorySignature([empty([win("C.1", "WS01")])]);
      expect(inventorySignature([empty([win("C.1", "WS01"), win("C.2", "WS02")])])).not.toBe(sig);
      expect(inventorySignature([empty(undefined)])).not.toBe(inventorySignature([empty([])]));
      expect(inventorySignature([empty([win("C.2", "WS02"), win("C.1", "WS01")])])).toBe(
        inventorySignature([empty([win("C.1", "WS01"), win("C.2", "WS02")])]),
      );
    });
  });

  // #1635 — when the artifact catalog lookup fails, the collect cannot know whether the artifact keeps
  // rows under named sources. TaskScheduler keeps them all under /Analysis, so its bare read is empty
  // whether or not the host has scheduled tasks. That silence must never settle persistence.
  describe("artifacts whose named sources were not read (#1635)", () => {
    const TS = "Windows.System.TaskScheduler";
    const inv = (hunts: VeloHuntJob[]) => buildCollectionInventory({ events: [], hunts });

    it("a zero-row artifact whose source list could not be looked up settles nothing, and says so", () => {
      const hunts = [job({ artifacts: [TS], unreadArtifacts: [{ name: TS, rows: 0 }] })];
      expect([...emptySettledClasses(inv(hunts), "WS01")]).toEqual([]);
      const lines = inv(hunts).hunts;
      expect(lines.map((l) => l.state)).toEqual(["unread"]);
      const text = renderCollectionInventory(inv(hunts));
      expect(text).toContain("not read");
      expect(text).toContain("not evidence of absence");
    });

    it("an unread artifact listed as empty by a stale record still does not settle", () => {
      const hunts = [
        job({ artifacts: [TS], emptyArtifacts: [TS], unreadArtifacts: [{ name: TS, rows: 0 }] }),
      ];
      expect([...emptySettledClasses(inv(hunts), "WS01")]).toEqual([]);
    });

    it("a partly read artifact keeps its other line and says its named sources were not read", () => {
      const hunts = [job({ artifacts: [TS], unreadArtifacts: [{ name: TS, rows: 4 }] })];
      const states = inv(hunts)
        .hunts.map((l) => l.state)
        .sort();
      expect(states).toEqual(["archive-only", "unread"]);
      expect(renderCollectionInventory(inv(hunts))).toContain("partly read");
    });

    it("the signature changes with the unread list", () => {
      const base = job({ artifacts: [TS], emptyArtifacts: [TS] });
      expect(inventorySignature([{ ...base, unreadArtifacts: [{ name: TS, rows: 0 }] }])).not.toBe(
        inventorySignature([base]),
      );
    });

    it("a malformed unread list from an old velo-hunt.json never throws", () => {
      const raw = [{ ...job({ artifacts: [TS] }), unreadArtifacts: [null, "x", { name: 7 }, { name: TS }] }];
      const clean = sanitizeHuntJobs(raw);
      expect(clean[0].unreadArtifacts).toEqual([{ name: TS, rows: 0 }]);
      expect(() => inv(clean)).not.toThrow();
    });
  });

  it("renders nothing for an empty case", () => {
    expect(renderCollectionInventory(buildCollectionInventory({ events: [] }))).toBe("");
  });
});
