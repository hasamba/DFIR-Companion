import { describe, it, expect } from "vitest";
import {
  readQuarantineTime,
  readQuarantineType,
  readQuarantineXattr,
  quarantineOverlay,
  markSharedIdentifiers,
  QUARANTINE_VARIANTS_MAX,
  canonicalUuid,
} from "../../src/analysis/quarantineRecord.js";
import { parseMacos } from "../../src/analysis/macosImport.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";
import type { SiemEvent, SiemIoc } from "../../src/analysis/siemImport.js";

// #933 item 7, prerequisite phase: a quarantine record says what it establishes.

const UUID = "550E8400-E29B-41D4-A716-446655440000";
const row = (over: Record<string, string> = {}) => ({
  LSQuarantineEventIdentifier: UUID,
  LSQuarantineTimeStamp: "716403200.5",
  LSQuarantineAgentBundleIdentifier: "com.apple.Safari",
  LSQuarantineAgentName: "Safari",
  LSQuarantineDataURLString: "https://cdn.example.invalid/installer.dmg",
  LSQuarantineSenderName: "",
  LSQuarantineSenderAddress: "",
  LSQuarantineTypeNumber: "0",
  LSQuarantineOriginTitle: "Promo",
  LSQuarantineOriginURLString: "https://lure.example.invalid/promo",
  LSQuarantineOriginAlias: "",
  ...over,
});
const overlay = (r: Record<string, string>) => {
  const sink = new Map<string, SiemIoc>();
  const o = quarantineOverlay(r, sink);
  return { ...o, iocs: [...sink.values()].map((i) => `${i.type}:${i.value}`) };
};

describe("readQuarantineTime — decoded by declared representation, never by magnitude", () => {
  it("the native column holding a number is Cocoa seconds", () => {
    expect(readQuarantineTime("716403200.5", "LSQuarantineTimeStamp")).toEqual({
      iso: "2023-09-14T16:53:20.500Z",
      encoding: "cocoa-seconds",
    });
    expect(readQuarantineTime("-5", "LSQuarantineTimeStamp").encoding).toBe("unreadable");
  });
  it("an ISO string is ISO under any header", () => {
    expect(readQuarantineTime("2026-05-02T09:30:00Z", "LSQuarantineTimeStamp")).toEqual({
      iso: "2026-05-02T09:30:00Z",
      encoding: "iso",
    });
    expect(readQuarantineTime("2026-05-02T09:30:00Z", "timestamp").encoding).toBe("iso");
  });
  it("a number under a generic header establishes no epoch; a column named for its epoch declares it", () => {
    expect(readQuarantineTime("660060258.698253", "timestamp")).toEqual({ iso: "", encoding: "unreadable" });
    expect(readQuarantineTime("1789257600", "time").encoding).toBe("unreadable");
    expect(readQuarantineTime("1789257600", "unix_time")).toEqual({
      iso: "2026-09-13T00:00:00.000Z",
      encoding: "unix-seconds",
    });
    expect(readQuarantineTime("1789257600", "epoch").encoding).toBe("unix-seconds");
    expect(readQuarantineTime("1789257600000", "unix_ms").iso).toBe("2026-09-13T00:00:00.000Z");
    expect(readQuarantineTime("1789257600000", "epoch_ms").encoding).toBe("unix-ms");
    // the magnitude never decides: seconds under a milliseconds column are 1970
    expect(readQuarantineTime("1789257600", "unix_ms").iso).toBe("1970-01-21T17:00:57.600Z");
  });
  it("an impossible calendar date is unreadable, never rolled over", () => {
    expect(readQuarantineTime("2026-04-31T00:00:00+02:00", "timestamp").encoding).toBe("unreadable");
    expect(readQuarantineTime("2023-02-29T00:00:00Z", "timestamp").encoding).toBe("unreadable");
    expect(readQuarantineTime("2024-02-29T00:00:00Z", "timestamp").encoding).toBe("iso");
    expect(readQuarantineTime("2026-01-01T24:00:00Z", "timestamp").encoding).toBe("unreadable");
  });
  it("a non-ISO date string is unreadable, never asserted as UTC", () => {
    expect(readQuarantineTime("May 7, 2026 @ 16:31:04.000", "LSQuarantineTimeStamp").encoding).toBe(
      "unreadable",
    );
    expect(readQuarantineTime("2026-05-07T16:31:04", "LSQuarantineTimeStamp").encoding).toBe("unreadable"); // no zone
    expect(readQuarantineTime("2026-05-07T16:31:04+02:00", "LSQuarantineTimeStamp").iso).toBe(
      "2026-05-07T14:31:04.000Z",
    );
  });
  it("garbage and empty are unreadable", () => {
    expect(readQuarantineTime("yesterday", "LSQuarantineTimeStamp").encoding).toBe("unreadable");
    expect(readQuarantineTime("", "LSQuarantineTimeStamp").encoding).toBe("unreadable");
  });
});

describe("readQuarantineType — Apple's LSQuarantineType", () => {
  it("names the table and nothing else", () => {
    expect(readQuarantineType("0")).toEqual({ typeNumber: 0, kind: "web download" });
    expect(readQuarantineType("1").kind).toBe("other download");
    expect(readQuarantineType("2").kind).toBe("email attachment");
    expect(readQuarantineType("3").kind).toBe("message attachment");
    expect(readQuarantineType("4").kind).toBe("calendar attachment");
    expect(readQuarantineType("5").kind).toBe("other attachment");
    expect(readQuarantineType("9")).toEqual({ typeNumber: 9, kind: "type 9 (not in the table)" });
    expect(readQuarantineType("")).toEqual({ kind: "kind not in this record" });
    expect(readQuarantineType("x")).toEqual({ kind: "kind not readable", typeRaw: "x" });
  });
});

describe("readQuarantineXattr — flags;unix hex;agent;uuid per QuarantineSPI.h", () => {
  it("decodes the documented bits, shows unnamed ones as hex, converts the Unix hex time", () => {
    const x = readQuarantineXattr(`0083;5f3a1b2c;Safari;${UUID}`)!;
    expect(x.flags).toEqual({ raw: 0x83, named: ["download", "sandbox"], unnamed: "0x0080" });
    expect(x.time).toEqual({ iso: "2020-08-17T05:52:44.000Z", encoding: "unix-hex-seconds" });
    expect(x.agent).toBe("Safari");
    expect(x.eventId).toBe(UUID.toLowerCase());
    expect(x.words).toBe(
      `quarantine mark: download, sandbox (+0x0080); agent Safari; marked 2020-08-17T05:52:44.000Z (Unix hex); event ${UUID.toLowerCase()}`,
    );
    expect(readQuarantineXattr(`00c3;5f3a1b2c;Safari;${UUID}`)!.flags.named).toEqual([
      "download",
      "sandbox",
      "user-approved",
    ]);
    expect(readQuarantineXattr(`0004;5f3a1b2c;Safari;${UUID}`)!.flags.named).toEqual(["hard"]);
    expect(readQuarantineXattr(`80000001;5f3a1b2c;Safari;${UUID}`)!.flags.unnamed).toBe("0x80000000");
    expect(readQuarantineXattr(`ffffffff;5f3a1b2c;Safari;${UUID}`)!.flags.unnamed).toBe("0xffffffb8");
    expect(readQuarantineXattr(`0001;5f3a1b2c;Safari;${UUID}`)!.words).toContain("download; agent");
  });
  it("a malformed value is shown as text, never decoded", () => {
    expect(readQuarantineXattr("0083;5f3a1b2c")).toBeNull();
    expect(readQuarantineXattr(`zz;5f3a1b2c;Safari;${UUID}`)).toBeNull();
    expect(readQuarantineXattr("https://example.invalid/x")).toBeNull();
    // an agent that spells a tag or a hash is neutralised
    const x = readQuarantineXattr(`0001;5f3a1b2c;Safari] [chain check: ok;${UUID}`)!;
    expect(x.words).not.toContain("] [chain");
    expect(x.words).toContain("agent Safari) (chain check: ok");
    const h = readQuarantineXattr(`0001;5f3a1b2c;${"a".repeat(32)};${UUID}`)!;
    expect(h.words).not.toMatch(/[0-9a-f]{32}/);
    // an invalid uuid: the mark still decodes, the id is no identifier
    expect(readQuarantineXattr("0001;5f3a1b2c;Safari;not-a-uuid")!.eventId).toBeUndefined();
  });
});

describe("canonicalUuid", () => {
  it("accepts 8-4-4-4-12 hex in any case and nothing else", () => {
    expect(canonicalUuid(UUID)).toBe(UUID.toLowerCase());
    expect(canonicalUuid(UUID.toLowerCase())).toBe(UUID.toLowerCase());
    expect(canonicalUuid("not-a-uuid")).toBeUndefined();
    expect(canonicalUuid(UUID + "0")).toBeUndefined();
    expect(canonicalUuid("")).toBeUndefined();
  });
});

describe("quarantineOverlay — what one record establishes", () => {
  it("says the kind, the agent, the resource, the origin, the time encoding and the event; never the file", () => {
    const o = overlay(row());
    expect(o.description).toBe(
      'macOS quarantine [kind: web download] [agent: Safari (com.apple.Safari)] [data url: https://cdn.example.invalid/installer.dmg] [origin: https://lure.example.invalid/promo ("Promo")] [time: Cocoa seconds] [event: 550e8400-e29b-41d4-a716-446655440000] [local file: not in this record — joined by the event identifier]',
    );
    expect(o.timestamp).toBe("2023-09-14T16:53:20.500Z");
    expect(o.severity).toBe("Info");
    expect(o.mitre).toEqual([]);
    expect(o.description).not.toMatch(/installer\.dmg(?!\])/);
    expect(o.envelope).toMatchObject({
      kind: "web download",
      typeNumber: 0,
      agent: "Safari",
      bundleId: "com.apple.Safari",
      dataUrl: "https://cdn.example.invalid/installer.dmg",
      originUrl: "https://lure.example.invalid/promo",
      originTitle: "Promo",
      eventId: UUID.toLowerCase(),
      timeEncoding: "cocoa-seconds",
      localFile: "not in this record",
    });
  });
  it("indicators: the data url and its host; an http origin and its host; never a sender, never a non-http scheme", () => {
    const o = overlay(
      row({ LSQuarantineSenderName: "Mallory", LSQuarantineSenderAddress: "mallory@example.invalid" }),
    );
    expect(o.iocs).toContain("url:https://cdn.example.invalid/installer.dmg");
    expect(o.iocs).toContain("domain:cdn.example.invalid");
    expect(o.iocs).toContain("url:https://lure.example.invalid/promo");
    expect(o.iocs).toContain("domain:lure.example.invalid");
    expect(o.iocs.some((i) => i.includes("mallory"))).toBe(false);
    expect(o.description).toContain("[sender: Mallory <mallory@example.invalid>]");
    const mail = overlay(
      row({
        LSQuarantineTypeNumber: "2",
        LSQuarantineOriginURLString: "mailto:mallory@example.invalid",
        LSQuarantineDataURLString: "file:///Users/a/Downloads/x.zip",
      }),
    );
    expect(mail.iocs).toEqual([]);
    expect(mail.description).toContain("[kind: email attachment]");
    const ip = overlay(row({ LSQuarantineDataURLString: "http://203.0.113.9/x.pkg" }));
    expect(ip.iocs).toContain("ip:203.0.113.9");
    expect(ip.iocs.some((i) => i.startsWith("domain:203"))).toBe(false);
  });
  it("identity: the uuid plus every shown fact; a re-dump folds, a different fact does not", () => {
    const a = overlay(row());
    const b = overlay(row());
    expect(a.aggKey).toBe(b.aggKey);
    const variants: Record<string, string>[] = [
      { LSQuarantineOriginTitle: "Other" },
      { LSQuarantineDataURLString: "https://cdn.example.invalid/other.dmg" },
      { LSQuarantineTimeStamp: "716403300" },
      { LSQuarantineSenderAddress: "x@example.invalid" },
      { LSQuarantineAgentName: "Chrome" },
    ];
    for (const v of variants) {
      expect(overlay(row(v)).aggKey, JSON.stringify(v)).not.toBe(a.aggKey);
    }
    // no uuid: keyed on the facts including the time; two a month apart are two
    const n1 = overlay(row({ LSQuarantineEventIdentifier: "" }));
    const n2 = overlay(row({ LSQuarantineEventIdentifier: "", LSQuarantineTimeStamp: "719000000" }));
    expect(n1.aggKey).not.toBe(n2.aggKey);
    expect(n1.description).toContain("[event identifier not in this record]");
    // an invalid id is no identifier but is a shown fact
    const i1 = overlay(row({ LSQuarantineEventIdentifier: "not-a-uuid-1" }));
    const i2 = overlay(row({ LSQuarantineEventIdentifier: "not-a-uuid-2" }));
    expect(i1.aggKey).not.toBe(i2.aggKey);
    expect(i1.description).toContain("[event identifier not decodable: not-a-uuid-1]");
    expect(i1.envelope.eventId).toBeUndefined();
    expect(i1.envelope.eventIdRaw).toBe("not-a-uuid-1");
    // case folds
    expect(overlay(row({ LSQuarantineEventIdentifier: UUID.toLowerCase() })).aggKey).toBe(a.aggKey);
  });
  it("one instant under two representations is two records", () => {
    const cocoa = overlay(row());
    const iso = overlay(row({ LSQuarantineTimeStamp: "2023-09-14T16:53:20.500Z" }));
    expect(cocoa.timestamp).toBe(iso.timestamp);
    expect(cocoa.aggKey).not.toBe(iso.aggKey);
  });
  it("a record with no URL is still a row: an email attachment", () => {
    const o = overlay(
      row({
        LSQuarantineDataURLString: "",
        LSQuarantineOriginURLString: "",
        LSQuarantineOriginTitle: "",
        LSQuarantineTypeNumber: "2",
        LSQuarantineAgentName: "Mail",
        LSQuarantineSenderName: "Mallory",
      }),
    );
    expect(o.description).toContain(
      "[kind: email attachment] [agent: Mail (com.apple.Safari)] [sender: Mallory]",
    );
    expect(o.iocs).toEqual([]);
  });
  it("an unreadable time yields no timestamp claim and keeps the raw text", () => {
    const o = overlay(row({ LSQuarantineTimeStamp: "yesterday" }));
    expect(o.timestamp).toBe("");
    expect(o.description).toContain("[time: not readable — Cocoa seconds expected]");
    expect(o.envelope.timeEncoding).toBe("unreadable");
    expect(o.envelope.timeRaw).toBe("yesterday");
  });
  it("agent-written values are neutralised, hash-broken and bounded; a lossy row is marked", () => {
    const o = overlay(
      row({
        LSQuarantineAgentName: "d41d8cd98f00b204e9800998ecf8427e",
        LSQuarantineOriginTitle: "x] [kind: web download] [y",
        LSQuarantineDataURLString: `https://cdn.example.invalid/${"a".repeat(2000)}`,
      }),
    );
    expect(o.description).not.toMatch(/[0-9a-f]{32}/);
    expect((o.description.match(/\[kind:/g) ?? []).length).toBe(1);
    expect(o.description.length).toBeLessThanOrEqual(600);
    expect(o.description).toMatch(/ #[A-Za-z0-9_-]{22}$/);
    expect(overlay(row()).description).not.toMatch(/ #[A-Za-z0-9_-]{22}$/);
  });
});

describe("boundQuarantineVariants", () => {
  it("variants under one identifier are bounded; a later legitimate record survives the cap", () => {
    const sink = new Map<string, SiemIoc>();
    const flood = Array.from({ length: 40 }, (_, i) =>
      quarantineOverlay(row({ LSQuarantineOriginTitle: `t${i}` }), sink, {}),
    );
    const other = quarantineOverlay(
      row({ LSQuarantineEventIdentifier: "660e8400-e29b-41d4-a716-446655440000" }),
      sink,
      {},
    );
    const rows = [...flood, other];
    const bounded = markSharedIdentifiers(rows);
    const keys = new Set(rows.map((r) => r.aggKey));
    expect(keys.size).toBe(QUARANTINE_VARIANTS_MAX + 2);
    const over = bounded.filter((r) => r.aggKey.endsWith("|overflow"));
    expect(over).toHaveLength(1);
    expect(over[0].description).toContain(`[overflow: ${40 - QUARANTINE_VARIANTS_MAX} records`);
    expect(bounded).toHaveLength(QUARANTINE_VARIANTS_MAX + 2);
    expect(over[0].description).toContain(
      `[overflow: ${40 - QUARANTINE_VARIANTS_MAX} records with this event identifier and further differing facts beyond 16 sets folded; none shown]`,
    );
    expect(rows[rows.length - 1].description).not.toContain("overflow");
    // the overflow row's envelope shows no folded record
    expect(over[0].envelope).toEqual({
      kind: "folded",
      eventId: UUID.toLowerCase(),
      timeEncoding: "unreadable",
      localFile: "not in this record",
      folded: true,
    });
    expect(over[0].canonical?.quarantine?.dataUrl).toBeUndefined();
    expect(over[0].iocs).toEqual([]);
  });
});

describe("markSharedIdentifiers", () => {
  it("one uuid with two fact sets is two rows, both marked; a re-dump is one", () => {
    const sink = new Map<string, SiemIoc>();
    const opts = {};
    const rows = [
      quarantineOverlay(row(), sink, opts),
      quarantineOverlay(
        row({ LSQuarantineDataURLString: "https://cdn.example.invalid/other.dmg" }),
        sink,
        opts,
      ),
      quarantineOverlay(row(), sink, opts),
    ];
    markSharedIdentifiers(rows);
    expect(new Set(rows.map((r) => r.aggKey)).size).toBe(2);
    expect(
      rows.every((r) => r.description.includes("[event identifier shared by records with different facts]")),
    ).toBe(true);
    const single = [quarantineOverlay(row(), new Map(), opts), quarantineOverlay(row(), new Map(), opts)];
    markSharedIdentifiers(single);
    expect(single.every((r) => !r.description.includes("shared by"))).toBe(true);
  });
});

describe("through parseMacos and correlateEvents", () => {
  const csv = (rows: Record<string, string>[]) => {
    const headers = Object.keys(rows[0]);
    return [
      headers.join(","),
      ...rows.map((r) => headers.map((h) => `"${(r[h] ?? "").replace(/"/g, '""')}"`).join(",")),
    ].join("\n");
  };
  const afterImport = (events: SiemEvent[]): ForensicEvent[] =>
    correlateEvents(
      events.map(({ aggKey: _k, ...e }, i) => ({
        ...e,
        id: `q${i}`,
        relatedFindingIds: [],
        sourceScreenshots: [],
        sources: e.sources ?? ["macOS Quarantine"],
      })),
    );

  it("an alias-only converted dump is routed as quarantine, and a URL-less native row is kept", () => {
    const alias = {
      event_id: UUID,
      timestamp: "2023-09-14T16:53:20.500Z",
      agent: "Safari",
      data_url: "https://cdn.example.invalid/a",
      origin_url: "https://lure.example.invalid/",
      type: "0",
    };
    for (const input of [JSON.stringify([alias]), csv([alias])]) {
      const r = parseMacos(input);
      expect(r.format).toBe("macos-quarantine");
      expect(r.events[0].description).toContain("[kind: web download]");
      expect(r.iocs.map((i) => i.value)).toContain("cdn.example.invalid");
    }
    const mail = parseMacos(
      csv([
        row({
          LSQuarantineDataURLString: "",
          LSQuarantineOriginURLString: "",
          LSQuarantineTypeNumber: "2",
          LSQuarantineAgentName: "Mail",
        }),
      ]),
    );
    expect(mail.events).toHaveLength(1);
  });

  it("a raw Cocoa dump parses to the right date; a json dump is routed too", () => {
    const r = parseMacos(csv([row()]));
    expect(r.format).toBe("macos-quarantine");
    expect(r.events[0].timestamp).toBe("2023-09-14T16:53:20.500Z");
    const j = parseMacos(JSON.stringify([row()]));
    expect(j.format).toBe("macos-quarantine");
    expect(j.events[0].description).toContain("[kind: web download]");
  });
  it("an agent name that is an MD5 never joins a file event carrying that MD5", () => {
    const md5 = "d41d8cd98f00b204e9800998ecf8427e";
    const r = parseMacos(csv([row({ LSQuarantineAgentName: md5 })]));
    const file: ForensicEvent = {
      id: "f1",
      timestamp: "2023-09-14T16:53:21.000Z",
      description: "File created",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      md5,
    };
    expect(correlateEvents([...afterImport(r.events), file])).toHaveLength(2);
  });
  it("routing by dimension: url + agent is a dump; origin_url + referrer alone is not; a generic id is not an event", () => {
    const byUrl = parseMacos(
      JSON.stringify([
        {
          event_id: UUID,
          timestamp: "2023-09-14T16:53:20.500Z",
          agent: "Safari",
          url: "https://cdn.example.invalid/a",
        },
      ]),
    );
    expect(byUrl.format).toBe("macos-quarantine");
    expect(byUrl.iocs.map((i) => i.value)).toContain("cdn.example.invalid");
    const notQuarantine = parseMacos(
      JSON.stringify([
        {
          timestamp: "2023-09-14T16:53:20.500Z",
          origin_url: "https://a.invalid/",
          referrer: "https://b.invalid/",
        },
      ]),
    );
    expect(notQuarantine.format).toBe("macos-unified-log");
    const genericId = overlay({ ...row({ LSQuarantineEventIdentifier: "" }), id: UUID });
    expect(genericId.envelope.eventId).toBeUndefined();
    expect(genericId.description).toContain("[event identifier not in this record]");
  });

  it("a flood of variants under one identifier fills neither the event budget nor the indicator budget", () => {
    const flood = Array.from({ length: 300 }, (_, i) =>
      row({ LSQuarantineDataURLString: `https://h${i}.example.invalid/x`, LSQuarantineOriginTitle: `t${i}` }),
    );
    const other = row({
      LSQuarantineEventIdentifier: "660e8400-e29b-41d4-a716-446655440000",
      LSQuarantineDataURLString: "https://legit.example.invalid/y",
    });
    const r = parseMacos(csv([...flood, other]), { maxEvents: 20, maxIocs: 40 });
    expect(r.events.some((e) => e.description.includes("660e8400-e29b-41d4-a716-446655440000"))).toBe(true);
    expect(r.iocs.map((i) => i.value)).toContain("legit.example.invalid");
  });

  it("a flood of variants under one identifier cannot push a legitimate record out of the budget", () => {
    const flood = Array.from({ length: 300 }, (_, i) => row({ LSQuarantineOriginTitle: `t${i}` }));
    const other = row({ LSQuarantineEventIdentifier: "660e8400-e29b-41d4-a716-446655440000" });
    const r = parseMacos(csv([...flood, other]), { maxEvents: 20 });
    expect(r.events.some((e) => e.description.includes("660e8400-e29b-41d4-a716-446655440000"))).toBe(true);
  });

  it("a long malformed identifier or an unreadable time keeps two records apart after import", () => {
    const longId = (t: string) => row({ LSQuarantineEventIdentifier: `${"x".repeat(90)}${t}` });
    const r1 = parseMacos(csv([longId("a"), longId("b")]));
    expect(r1.events).toHaveLength(2);
    expect(afterImport(r1.events)).toHaveLength(2);
    const bad = (t: string) => row({ LSQuarantineEventIdentifier: "", LSQuarantineTimeStamp: t });
    const r2 = parseMacos(csv([bad("yesterday"), bad("tomorrow")]));
    expect(r2.events).toHaveLength(2);
    expect(afterImport(r2.events)).toHaveLength(2);
  });

  it("the bound holds with aggregation off, and an out-of-range number is unreadable", () => {
    const flood = Array.from({ length: 300 }, (_, i) => row({ LSQuarantineOriginTitle: `t${i}` }));
    const other = row({ LSQuarantineEventIdentifier: "660e8400-e29b-41d4-a716-446655440000" });
    const r = parseMacos(csv([...flood, other]), { aggregate: false });
    expect(r.events.length).toBeLessThanOrEqual(QUARANTINE_VARIANTS_MAX + 2);
    expect(r.events.filter((e) => e.description.includes("|overflow") || (e.count ?? 1) > 1)).toHaveLength(0);
    expect(r.dropped).toBe(300 - QUARANTINE_VARIANTS_MAX - 1); // the fold row stands for one of them
    const fold = r.events.find((e) => e.description.includes("[overflow:"));
    expect(fold?.description).toContain(`[overflow: ${300 - QUARANTINE_VARIANTS_MAX} records`);
    expect(r.events.some((e) => e.description.includes("660e8400-e29b-41d4-a716-446655440000"))).toBe(true);
    expect(readQuarantineTime("999999999999999", "LSQuarantineTimeStamp")).toEqual({
      iso: "",
      encoding: "unreadable",
    });
    const big = (t: string) => row({ LSQuarantineEventIdentifier: "", LSQuarantineTimeStamp: t });
    const r2 = parseMacos(csv([big("999999999999999"), big("999999999999998")]));
    expect(r2.events).toHaveLength(2);
    expect(afterImport(r2.events)).toHaveLength(2);
    expect(r2.events[0].canonical?.quarantine?.timeRaw).toBeDefined();
  });

  it("two unreadable type values are two rows; a long URL mints no prefix indicator", () => {
    const r = parseMacos(csv([row({ LSQuarantineTypeNumber: "x" }), row({ LSQuarantineTypeNumber: "y" })]));
    expect(r.events).toHaveLength(2);
    expect(afterImport(r.events)).toHaveLength(2);
    expect(r.events[0].description).toContain("[kind: kind not readable (x)]");
    expect(r.events[0].canonical?.quarantine?.typeRaw).toBe("x");
    const long = `https://cdn.example.test/${"p".repeat(600)}`;
    const r2 = parseMacos(csv([row({ LSQuarantineDataURLString: long })]));
    expect(r2.iocs.filter((i) => i.type === "url" && i.value.includes("cdn.example.test"))).toHaveLength(0);
    expect(r2.iocs.some((i) => i.type === "domain" && i.value === "cdn.example.test")).toBe(true);
    expect(r2.events[0].canonical?.quarantine?.urlIndicator).toMatch(/omitted/);
  });

  it("an overflow row's canonical time is its (earliest folded) time", () => {
    const stamp = (i: number) => String(1_800_000_000 - 978_307_200 - i * 86_400);
    const flood = Array.from({ length: QUARANTINE_VARIANTS_MAX + 3 }, (_, i) =>
      row({ LSQuarantineOriginTitle: `t${i}`, LSQuarantineTimeStamp: stamp(i) }),
    );
    const r = parseMacos(csv(flood));
    const fold = r.events.find((e) => e.description.includes("[overflow:"));
    expect(fold).toBeDefined();
    expect(fold!.timestamp).toBe(
      new Date((1_800_000_000 - (QUARANTINE_VARIANTS_MAX + 2) * 86_400) * 1000).toISOString(),
    );
    expect(fold!.canonical?.time.normalized).toBe(fold!.timestamp);
    expect(fold!.canonical?.time.observed).toBe(fold!.timestamp);
  });

  it("a unified-log record in a quarantine json array is never a download event", () => {
    const mixed = [
      row(),
      { timestamp: "2026-05-02 10:00:00.000000+0000", eventMessage: "hello", process: "kernel" },
    ];
    const r = parseMacos(JSON.stringify(mixed));
    expect(r.events.filter((e) => e.description.startsWith("macOS quarantine"))).toHaveLength(1);
    expect(r.events.some((e) => e.description.startsWith("macOS log"))).toBe(true);
  });

  it("every declared epoch spelling is read through the import; two declared times are two rows", () => {
    const { LSQuarantineTimeStamp: _t, ...rest } = row();
    const seconds = [
      "unix_time",
      "unixtime",
      "unix_seconds",
      "unixseconds",
      "epoch",
      "epoch_seconds",
      "epochseconds",
    ];
    const millis = [
      "unix_ms",
      "unixms",
      "unix_millis",
      "unixmillis",
      "epoch_ms",
      "epochms",
      "epoch_millis",
      "epochmillis",
    ];
    for (const h of seconds) {
      const r = parseMacos(csv([{ ...rest, [h]: "1789257600" }]));
      expect(r.events[0].timestamp, h).toBe("2026-09-13T00:00:00.000Z");
      expect(r.events[0].description, h).toContain(`[time: Unix seconds (column ${h})]`);
    }
    for (const h of millis) {
      const r = parseMacos(csv([{ ...rest, [h]: "1789257600000" }]));
      expect(r.events[0].timestamp, h).toBe("2026-09-13T00:00:00.000Z");
      expect(r.events[0].description, h).toContain(`[time: Unix milliseconds (column ${h})]`);
    }
    const two = parseMacos(
      csv([
        { ...rest, epoch_seconds: "1789257600" },
        { ...rest, epoch_seconds: "1789344000" },
      ]),
    );
    expect(two.events).toHaveLength(2);
    expect(afterImport(two.events)).toHaveLength(2);
    expect(
      two.events.every((e) =>
        e.description.includes("[event identifier shared by records with different facts]"),
      ),
    ).toBe(true);
  });

  it("a declared epoch beside a generic alias is read; two time columns are no time", () => {
    const { LSQuarantineTimeStamp: _t, ...rest } = row();
    // a generic alias never shadows a declaration
    const r = parseMacos(csv([{ ...rest, timestamp: "1789257600", unix_time: "1789257600" }]));
    expect(r.events[0].timestamp).toBe("");
    expect(r.events[0].description).toContain(
      "[time: not readable — 2 time columns in this record (unix_time, timestamp)]",
    );
    expect(r.events[0].canonical?.quarantine?.timeRaw).toBe(
      "9:unix_time=10:1789257600|9:timestamp=10:1789257600",
    );
    // by any case, in JSON
    const j = parseMacos(JSON.stringify([{ ...rest, unix_time: "1789257600", UNIX_TIME: "1789344000" }]));
    expect(j.events[0].timestamp).toBe("");
    expect(j.events[0].description).toContain("2 time columns in this record (unix_time, UNIX_TIME)");
    // one header twice, in CSV
    const dup = parseMacos(
      `event_id,unix_time,data_url,unix_time\n${UUID},1789257600,https://cdn.example.invalid/a.dmg,1789344000\n`,
    );
    expect(dup.events[0].timestamp).toBe("");
    expect(dup.events[0].description).toContain("2 time columns in this record (unix_time, unix_time)");
    // a delimiter inside a value never makes two column sets one identity
    const a = parseMacos(JSON.stringify([{ ...rest, unix_time: "x|9:timestamp=1:y", timestamp: "z" }]));
    const b = parseMacos(JSON.stringify([{ ...rest, unix_time: "x", timestamp: "y|9:timestamp=1:z" }]));
    expect(a.events[0].aggKey).not.toBe(b.events[0].aggKey);
    expect(afterImport([a.events[0], b.events[0]])).toHaveLength(2);
    // two rows that differ only in a second time column are two rows
    const two = parseMacos(
      csv([
        { ...rest, timestamp: "1789257600", unix_time: "1789257600" },
        { ...rest, timestamp: "1789257600", unix_time: "1789344000" },
      ]),
    );
    expect(two.events).toHaveLength(2);
    expect(afterImport(two.events)).toHaveLength(2);
  });

  it("two dumps that differ only in the origin alias are two rows; the alias is never shown", () => {
    const r = parseMacos(
      csv([
        row({ LSQuarantineOriginAlias: "AAAAbookmark1" }),
        row({ LSQuarantineOriginAlias: "AAAAbookmark2" }),
      ]),
    );
    expect(r.events).toHaveLength(2);
    expect(afterImport(r.events)).toHaveLength(2);
    expect(r.events[0].description).toContain("[origin alias: present (13 characters, not shown)]");
    expect(r.events[0].description).not.toContain("bookmark1");
    expect(r.events[0].description).toMatch(/ #[A-Za-z0-9_-]{22}$/);
    expect(r.events[0].canonical?.quarantine?.originAliasDigest).toMatch(/^[0-9a-f]{32}$/);
  });

  it("two sub-millisecond Cocoa values are two rows, aggregated or not, and after correlation", () => {
    const rows = [
      row({ LSQuarantineTimeStamp: "716403200.5001" }),
      row({ LSQuarantineTimeStamp: "716403200.5002" }),
    ];
    const agg = parseMacos(csv(rows));
    expect(agg.events).toHaveLength(2);
    expect(agg.events.every((e) => e.timestamp === "2023-09-14T16:53:20.500Z")).toBe(true);
    expect(agg.events.every((e) => / #[A-Za-z0-9_-]{22}$/.test(e.description))).toBe(true);
    expect(
      agg.events.every((e) =>
        e.description.includes("[event identifier shared by records with different facts]"),
      ),
    ).toBe(true);
    const flat = parseMacos(csv(rows), { aggregate: false });
    expect(afterImport(flat.events)).toHaveLength(2);
    // a value the ISO carries back exactly is not marked for its time
    const exact = parseMacos(csv([row({ LSQuarantineTimeStamp: "716403200.5" })]));
    expect(exact.events[0].description).not.toMatch(/ #[A-Za-z0-9_-]{22}$/);
    // a non-canonical spelling of the same number is other evidence: marked, and two rows after correlation
    const spelled = [
      row({ LSQuarantineTimeStamp: "716403200.5" }),
      row({ LSQuarantineTimeStamp: "716403200.5000" }),
    ];
    const sp = parseMacos(csv(spelled));
    expect(sp.events).toHaveLength(2);
    expect(sp.events.some((e) => / #[A-Za-z0-9_-]{22}$/.test(e.description))).toBe(true);
    expect(afterImport(sp.events)).toHaveLength(2);
    expect(afterImport(parseMacos(csv(spelled), { aggregate: false }).events)).toHaveLength(2);
    expect(
      afterImport(
        parseMacos(csv([row({ LSQuarantineTimeStamp: "0716403200.5" }), row()]), { aggregate: false }).events,
      ),
    ).toHaveLength(2);
  });

  it("two ISO spellings of one instant are two rows after correlation", () => {
    const rows = [
      row({ LSQuarantineTimeStamp: "2026-05-02T09:30:00+02:00" }),
      row({ LSQuarantineTimeStamp: "2026-05-02T09:30:00+0200" }),
    ];
    const r = parseMacos(csv(rows));
    expect(r.events).toHaveLength(2);
    expect(r.events.every((e) => / #[A-Za-z0-9_-]{22}$/.test(e.description))).toBe(true);
    expect(afterImport(r.events)).toHaveLength(2);
    expect(afterImport(parseMacos(csv(rows), { aggregate: false }).events)).toHaveLength(2);
    // the platform's own spelling is carried back and not marked for its time
    const z = parseMacos(csv([row({ LSQuarantineTimeStamp: "2026-05-02T09:30:00.000Z" })]));
    expect(z.events[0].description).not.toMatch(/ #[A-Za-z0-9_-]{22}$/);
  });

  it("a path-shaped unreadable type never joins a real path event after import", () => {
    const q = parseMacos(csv([row({ LSQuarantineTypeNumber: "/tmp/evil/payload" })]));
    expect(q.events[0].description).toContain("[kind: kind not readable (/tmp/evil/payload)]");
    const file: ForensicEvent = {
      id: "f1",
      timestamp: "2023-09-14T16:53:21.000Z",
      description: "File created",
      severity: "Low",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
      path: "/tmp/evil/payload",
    };
    expect(correlateEvents([...afterImport(q.events), file])).toHaveLength(2);
  });

  it("a converted dump declares its epoch in the column name, through the import", () => {
    const { LSQuarantineTimeStamp: _t, ...rest } = row();
    const r = parseMacos(csv([{ ...rest, unix_time: "1789257600" }]));
    expect(r.events[0].timestamp).toBe("2026-09-13T00:00:00.000Z");
    expect(r.events[0].description).toContain("[time: Unix seconds (column unix_time)]");
    const g = parseMacos(csv([{ ...rest, timestamp: "1789257600" }]));
    expect(g.events[0].timestamp).toBe("");
    expect(g.events[0].description).toContain(
      "[time: not readable — the column names no epoch (a converted dump names it: unix_time or unix_ms)]",
    );
  });
});
