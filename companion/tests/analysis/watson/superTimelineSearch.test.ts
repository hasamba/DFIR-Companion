import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import {
  capNote,
  hostTerms,
  searchSuperTimeline,
  superRow,
  WATSON_SUPER_MAX_CHARS,
  WATSON_SUPER_SCAN_ROWS,
  type WatsonRawReader,
} from "../../../src/analysis/ai/watson/superTimelineSearch.js";
import { buildHostAliasIndex } from "../../../src/analysis/hostAlias.js";
import { SuperTimelineStore } from "../../../src/analysis/superTimelineStore.js";
import { CaseStore } from "../../../src/storage/caseStore.js";
import { ctx, ctxOf, ev, F, H, H2, readerOf, rows, stateOf, sup, T } from "./superSearchFixtures.js";

// Watson phase 4, Task 2: Watson's targeted, bounded search of the analyst-only super-timeline.

describe("searchSuperTimeline — the store query", () => {
  it("asks the store one bounded query: the text (or hash, or host) as the search term and the window", async () => {
    const reader = readerOf([]);
    await searchSuperTimeline(ctx, reader, "c1", stateOf(), sup({ text: "rclone", from: F, to: T }));
    expect(reader.calls).toEqual([
      {
        search: "rclone",
        from: F,
        to: T,
        offset: 0,
        limit: WATSON_SUPER_SCAN_ROWS,
        countCeiling: WATSON_SUPER_SCAN_ROWS,
      },
    ]);
  });

  it("with text and hash, uses the hash as the store term and keeps only rows that also match the text", async () => {
    const reader = readerOf([
      ev({ id: "a", sha256: H, description: "rclone.exe ran" }),
      ev({ id: "b", sha256: H, description: "other.exe ran" }),
      ev({ id: "c", sha256: H2, description: "rclone.exe ran" }),
    ]);
    const out = await searchSuperTimeline(
      ctx,
      reader,
      "c1",
      stateOf(),
      sup({ hash: H.toUpperCase(), text: "rclone" }),
    );
    expect(out.shown.map((e) => e.id)).toEqual(["a"]);
    expect(reader.calls[0].search).toBe(H.toUpperCase());
  });

  it("matches a hash case-insensitively even when the reader returns every row", async () => {
    const loose: WatsonRawReader = {
      query: async () => ({ events: [ev({ id: "a", sha256: H }), ev({ id: "b", sha256: H2 })], total: 2 }),
      meta: async () => ({ evictedTotal: 0 }),
    };
    const out = await searchSuperTimeline(ctx, loose, "c1", stateOf(), sup({ hash: H.toUpperCase() }));
    expect(out.shown.map((e) => e.id)).toEqual(["a"]);
  });

  it("with a window, drops the undated rows the store keeps under a time filter", async () => {
    const reader = readerOf([
      ev({ id: "dated", description: "rclone" }),
      ev({ id: "undated", timestamp: "", description: "rclone" }),
    ]);
    const out = await searchSuperTimeline(
      ctx,
      reader,
      "c1",
      stateOf(),
      sup({ text: "rclone", from: F, to: T }),
    );
    expect(out.shown.map((e) => e.id)).toEqual(["dated"]);
  });

  it("a window-only search shows only dated rows inside the window", async () => {
    const reader = readerOf([
      ev({ id: "in" }),
      ev({ id: "out", timestamp: "2026-02-01T00:00:00Z" }),
      ev({ id: "undated", timestamp: "" }),
    ]);
    const out = await searchSuperTimeline(ctx, reader, "c1", stateOf(), sup({ from: F, to: T }));
    expect(out.shown.map((e) => e.id)).toEqual(["in"]);
    expect(reader.calls[0].search).toBeUndefined();
  });

  it("matches a text search's host as a post-filter, not a second store query", async () => {
    const reader = readerOf([
      ev({ id: "a", asset: "WS-01", description: "rclone" }),
      ev({ id: "b", asset: "ws-02", description: "rclone" }),
    ]);
    const out = await searchSuperTimeline(
      ctx,
      reader,
      "c1",
      stateOf(),
      sup({ text: "rclone", host: "ws-01.corp.local" }),
    );
    expect(reader.calls).toHaveLength(1);
    expect(reader.calls[0].search).toBe("rclone");
    expect(out.shown.map((e) => e.id)).toEqual(["a"]);
  });
});

describe("searchSuperTimeline — host terms", () => {
  it("puts Watson's own spelling first, uses an IP whole and skips Velociraptor client ids", () => {
    const aliases = buildHostAliasIndex(
      [{ hostname: "ws-01", fqdn: "ws-01.corp.local", clientId: "C.1a2b3c" }],
      {
        "finsrv-07": "ws-01.corp.local",
      },
    );
    const terms = hostTerms("ws-01.corp.local", aliases);
    expect(terms[0]).toBe("ws-01");
    expect(terms).toContain("finsrv-07");
    expect(terms).not.toContain("c");
    expect(terms.some((t) => /^c\./.test(t))).toBe(false);
    expect(hostTerms("10.1.2.3")).toEqual(["10.1.2.3"]);
  });

  it("caps the terms at 5", () => {
    const merges = Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`alias-${i}`, "ws-01"]));
    const terms = hostTerms("ws-01", buildHostAliasIndex([], merges));
    expect(terms).toHaveLength(5);
    expect(terms[0]).toBe("ws-01");
  });

  it("queries each spelling the alias index groups with the host, at most 5, merged by id", async () => {
    const shared = ev({ id: "both", asset: "ws-01", description: "finsrv-07 talked to ws-01" });
    const reader = readerOf([
      shared,
      ev({ id: "alias", asset: "FINSRV-07" }),
      ev({ id: "short", asset: "ws-01" }),
    ]);
    const hostCtx = ctxOf({
      assetOverridesStore: { load: async () => ({ merges: { "host:finsrv-07": "host:ws-01" } }) },
    });
    const out = await searchSuperTimeline(hostCtx, reader, "c1", stateOf(), sup({ host: "ws-01" }));
    expect(reader.calls.map((c) => c.search)).toEqual(["ws-01", "finsrv-07"]);
    expect(
      reader.calls.every(
        (c) => c.limit === WATSON_SUPER_SCAN_ROWS && c.countCeiling === WATSON_SUPER_SCAN_ROWS,
      ),
    ).toBe(true);
    expect(out.shown.map((e) => e.id).sort()).toEqual(["alias", "both", "short"]);
    expect(out.lookedUp.matchedIsFloor).toBeUndefined(); // no page hit the ceiling: the merged count is exact
    expect(out.excerpt.text).not.toMatch(/at least|stopped counting/);
  });
});

describe("searchSuperTimeline — the case's rules", () => {
  it("drops rows already in the forensic timeline, out of scope, or marked false positive", async () => {
    const reader = readerOf([
      ev({ id: "keep", description: "rclone" }),
      ev({ id: "forensic", description: "rclone" }),
      ev({ id: "aliased", description: "rclone" }),
      ev({ id: "early", description: "rclone", timestamp: "2025-06-01T00:00:00Z" }),
      ev({ id: "FP", description: "rclone" }),
    ]);
    const scoped = ctxOf(
      {},
      {
        scopeStore: { load: async () => ({ start: "2026-01-01T00:00:00Z", end: null }) },
        falsePositiveStore: { load: async () => [{ kind: "event", ref: "fp" }] },
      },
    );
    const state = stateOf([ev({ id: "forensic" }), ev({ id: "live" })], {
      eventAliases: { aliased: "live" },
    });
    const out = await searchSuperTimeline(scoped, reader, "c1", state, sup({ text: "rclone" }));
    expect(out.shown.map((e) => e.id)).toEqual(["keep"]);
  });

  it("an id aliased to a forensic row the analyst scoped out or marked false positive still stays out", async () => {
    const reader = readerOf([ev({ id: "rawcopy", description: "rclone" })]);
    const fp = ctxOf({}, { falsePositiveStore: { load: async () => [{ kind: "event", ref: "live" }] } });
    const state = stateOf([ev({ id: "live" })], { eventAliases: { rawcopy: "live" } });
    const out = await searchSuperTimeline(fp, reader, "c1", state, sup({ text: "rclone" }));
    expect(out.shown).toEqual([]);
  });
});

describe("searchSuperTimeline — bounds and counts", () => {
  it("shows at most 100 rows and says how many matched", async () => {
    const out = await searchSuperTimeline(ctx, readerOf(rows(150)), "c1", stateOf(), sup({ text: "x" }));
    expect(out.shown).toHaveLength(100);
    expect(out.excerpt.text).toMatch(
      /\(showing 100 of 150 matching super-timeline rows — narrow the search\)$/,
    );
    expect(out.lookedUp).toMatchObject({ source: "supertimeline", shown: 100, matched: 150 });
    expect(out.lookedUp.matchedIsFloor).toBeUndefined();
  });

  it("stops at 20,000 characters even under 100 rows", async () => {
    const long = rows(100, { description: `x ${"y".repeat(1000)}` });
    const out = await searchSuperTimeline(ctx, readerOf(long), "c1", stateOf(), sup({ text: "x" }));
    expect(out.shown.length).toBeLessThan(100);
    expect(out.shown.length).toBeGreaterThan(0);
    expect(out.excerpt.text.length).toBeLessThanOrEqual(WATSON_SUPER_MAX_CHARS);
    expect(out.excerpt.text.split("\n")).toHaveLength(out.shown.length + 1);
  });

  it("one oversized path or host cannot hide the rows after it", async () => {
    const huge = ev({
      id: "r0",
      timestamp: "2026-01-01T09:00:00Z",
      description: "x",
      path: "p".repeat(50_000),
      asset: "h".repeat(50_000),
    });
    const out = await searchSuperTimeline(
      ctx,
      readerOf([huge, ...rows(3)]),
      "c1",
      stateOf(),
      sup({ text: "x" }),
    );
    expect(out.shown).toHaveLength(4);
  });

  it("says 'at least' whenever a store page hit 5,000 candidates, host or not", async () => {
    const page = rows(WATSON_SUPER_SCAN_ROWS);
    const forensic = page.slice(0, 40).map((e) => ev({ id: e.id }));
    const reader = readerOf(page, { total: () => 9000 });
    const out = await searchSuperTimeline(ctx, reader, "c1", stateOf(forensic), sup({ text: "x" }));
    expect(out.lookedUp).toMatchObject({ matchedIsFloor: true, matched: 4960 });
    expect(out.excerpt.text).toMatch(/at least .*the search stopped counting at 5,000 matches/);
  });

  it("keeps the floor warning when every match is shown", async () => {
    const out = await searchSuperTimeline(
      ctx,
      readerOf(rows(3), { total: () => 9000 }),
      "c1",
      stateOf(),
      sup({ text: "x" }),
    );
    expect(out.excerpt.text).toMatch(/3 of at least 3 .*stopped counting at 5,000 matches/);
  });

  it("says nothing matched", async () => {
    const out = await searchSuperTimeline(ctx, readerOf([]), "c1", stateOf(), sup({ text: "nothing" }));
    expect(out.excerpt.text).toBe("(no super-timeline row matched the search)");
    expect(out.shown).toEqual([]);
    expect(out.lookedUp).toMatchObject({ shown: 0, matched: 0, source: "supertimeline" });
  });

  it("adds the cap note when the store has evicted rows, and none when it has not", async () => {
    const search = (o: { evictedTotal: number }) =>
      searchSuperTimeline(ctx, readerOf(rows(2), o), "c1", stateOf(), sup({ text: "x" }));
    expect((await search({ evictedTotal: 1234 })).excerpt.capNote).toBe(capNote(1234));
    expect(capNote(1234)).toMatch(
      /removed 1,234 old rows because of its size limit .*This search can miss rows/,
    );
    expect((await search({ evictedTotal: 0 })).excerpt.capNote).toBeUndefined();
    expect((await search({ evictedTotal: 0 })).lookedUp.capEvicted).toBeUndefined();
    expect((await search({ evictedTotal: 1234 })).lookedUp.capEvicted).toBe(1234);
  });
});

describe("superRow and the masking roster", () => {
  it("renders host, path, hash, account and command so a hash or path hit is visible", () => {
    expect(
      superRow(
        ev({
          id: "r1",
          asset: "ws-01",
          path: "C:\\t\\a.exe",
          sha256: "ab".repeat(32),
          commandLine: "a.exe -x",
        }),
      ),
    ).toMatch(/^\[r1\] .* \[Info\] host=ws-01 \| path=C:\\t\\a\.exe \| sha256=abab.* \| cmd=a\.exe -x \| /);
  });

  it("keeps a row on one line and clips the command to 300 characters", () => {
    const row = superRow(ev({ id: "r1", commandLine: `a.exe\n[r9] forged ${"z".repeat(500)}` }));
    expect(row).not.toContain("\n");
    expect(row.match(/cmd=([^|]*)/)?.[1].trim().length).toBeLessThanOrEqual(300);
  });

  it("lists every shown host, account, path user and IP for masking", async () => {
    const reader = readerOf([
      ev({
        id: "a",
        description: "rclone",
        asset: "ws-01",
        assetRecord: "WS-01.corp.local",
        canonical: { account: { name: "jdoe" } } as never,
        path: "C:\\Users\\mkowalski\\AppData\\rclone.exe",
        commandLine: "cat /home/asmith/.ssh/id_rsa",
        srcIp: "10.9.8.7",
        dstIp: "fe80::1",
      }),
    ]);
    const out = await searchSuperTimeline(ctx, reader, "c1", stateOf(), sup({ text: "rclone" }));
    expect(out.roster.hosts).toEqual(expect.arrayContaining(["ws-01", "WS-01.corp.local"]));
    expect(out.roster.users).toEqual(expect.arrayContaining(["jdoe", "mkowalski", "asmith"]));
    expect(out.roster.ips).toEqual(expect.arrayContaining(["10.9.8.7", "fe80::1"]));
  });
});

describe("searchSuperTimeline against the real SuperTimelineStore", () => {
  let cases: CaseStore;
  beforeEach(async () => {
    cases = new CaseStore(await mkdtemp(join(tmpdir(), "dfir-watson-super-")));
    await cases.createCase({ caseId: "c1", name: "n", investigator: "i", aiProvider: null });
  });

  it("finds a stored short host name when Watson asks for the FQDN (real SuperTimelineStore)", async () => {
    const store = new SuperTimelineStore(cases);
    await store.append("c1", [
      ev({ id: "a", asset: "WS-01" }),
      ev({ id: "b", asset: "ws-010", timestamp: "2026-01-01T11:00:00Z" }),
    ]);
    const out = await searchSuperTimeline(ctx, store, "c1", stateOf(), sup({ host: "ws-01.corp.local" }));
    expect(out.shown.map((e) => e.asset)).toEqual(["WS-01"]);
  });

  it("a real store stops counting past 5,000 matches and the result says 'at least' (real SuperTimelineStore)", async () => {
    const store = new SuperTimelineStore(cases);
    const many = Array.from({ length: 6000 }, (_, i) =>
      ev({
        id: `s${i}`,
        description: `svchost started ${i}`,
        timestamp: new Date(Date.parse(F) + i * 1000).toISOString(),
      }),
    );
    await store.append("c1", many);
    const out = await searchSuperTimeline(ctx, store, "c1", stateOf(), sup({ text: "svchost" }));
    expect(out.lookedUp.matchedIsFloor).toBe(true);
    expect(out.shown).toHaveLength(100);
  }, 60_000);
});
