import { describe, it, expect } from "vitest";
import {
  readQuarantineTime,
  readQuarantineType,
  readQuarantineXattr,
  quarantineOverlay,
  markSharedIdentifiers,
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
const overlay = (
  r: Record<string, string>,
  opts: { quarantineTime?: "cocoa" | "unix-seconds" | "unix-ms" } = {},
) => {
  const sink = new Map<string, SiemIoc>();
  const o = quarantineOverlay(r, sink, opts);
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
  it("a number under a generic header establishes no epoch unless declared", () => {
    expect(readQuarantineTime("660060258.698253", "timestamp")).toEqual({ iso: "", encoding: "unreadable" });
    expect(readQuarantineTime("1789257600", "timestamp", "unix-seconds")).toEqual({
      iso: "2026-09-13T00:00:00.000Z",
      encoding: "unix-seconds",
    });
    expect(readQuarantineTime("1789257600000", "time", "unix-ms").iso).toBe("2026-09-13T00:00:00.000Z");
    expect(readQuarantineTime("660060258.698253", "timestamp", "cocoa").iso).toBe("2021-12-01T14:04:18.698Z");
    // the option overrides the native header for a converted dump that kept it
    expect(readQuarantineTime("1789257600", "LSQuarantineTimeStamp", "unix-seconds").iso).toBe(
      "2026-09-13T00:00:00.000Z",
    );
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
    expect(readQuarantineType("x")).toEqual({ kind: "kind not readable" });
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
  it("the import option declares a converted dump's epoch", () => {
    const r = parseMacos(csv([{ ...row(), LSQuarantineTimeStamp: "1789257600" }]), {
      quarantineTime: "unix-seconds",
    });
    expect(r.events[0].timestamp).toBe("2026-09-13T00:00:00.000Z");
    expect(r.events[0].description).toContain("[time: Unix seconds, declared]");
  });
});
