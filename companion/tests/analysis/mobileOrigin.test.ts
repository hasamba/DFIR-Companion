import { describe, expect, it } from "vitest";
import {
  headersMatch,
  readOrigin,
  REGISTRY,
  REGISTRY_PINS,
  REGISTRY_VERSION,
  registryEntry,
} from "../../src/analysis/mobileOriginRegistry.js";
import { parseLeappTsv } from "../../src/analysis/mobileLeappImport.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// #932 item 18 (#988): a LEAPP row's origin is read from its own columns against a registry
// pinned to upstream; a facet with no establishing column is "not established"; nothing here says
// a person acted. Fixtures are generated from the upstream header tuples, never from a device.

/** A TSV from an entry's pinned header tuple, one row per `rows` entry (values by header name). */
function tsv(name: string, rows: Record<string, string>[]): { text: string; filename: string } {
  const entry = registryEntry(name)!;
  const lines = [
    entry.headers.join("\t"),
    ...rows.map((r) => entry.headers.map((h) => r[h] ?? "").join("\t")),
  ];
  return { text: lines.join("\n"), filename: `${name}.tsv` };
}

describe("the registry pin", () => {
  it("names both upstream commits and every entry's exact header tuple", () => {
    expect(REGISTRY_PINS.iLEAPP.commit).toBe("925f3d71e2e0");
    expect(REGISTRY_PINS.ALEAPP.commit).toBe("498491475597");
    expect(REGISTRY_VERSION).toBe("leapp-origin-2026-09-13");
    for (const e of REGISTRY) expect(e.headers.length, e.name).toBeGreaterThan(0);
    const safari = registryEntry("Safari Browser - History")!;
    expect(headersMatch(safari, safari.headers)).toBe(true);
    // A renamed / missing column is `headers-differ`, never a guess; case and spacing are identity.
    expect(
      headersMatch(
        safari,
        safari.headers.map((h) => (h === "Origin" ? "origin" : h)),
      ),
    ).toBe(false);
    expect(headersMatch(safari, safari.headers.slice(1))).toBe(false);
    expect(registryEntry("safari browser - history")).toBeUndefined();
  });
  it("a bare TSV is schema-matches, never producer-verified; an unknown artifact is not covered; a status row is excluded", () => {
    const safari = registryEntry("Safari Browser - History")!;
    const r = readOrigin("ios", "Safari Browser - History", safari.headers, [
      "",
      "t",
      "https://x.example",
      "1",
      "",
      "",
      "1",
      "Local Device",
      "Default",
    ]);
    expect(r.block.registry).toEqual({
      version: REGISTRY_VERSION,
      coverage: "schema-matches",
      pinned: "iLEAPP@925f3d71e2e0",
    });
    expect(r.words).not.toContain("producer-verified");
    const differ = readOrigin("ios", "Safari Browser - History", ["Visit Timestamp", "URL"], ["", ""]);
    expect(differ.block.registry.coverage).toBe("headers-differ");
    expect(differ.words).toContain("headers differ from the pinned release (iLEAPP@925f3d71e2e0)");
    expect(differ.block.facets).toMatchObject({
      acquisition: "not-established",
      locality: "not-established",
      authorship: "not-established",
    });
    const unknown = readOrigin("ios", "Some Other Table", ["A"], ["1"]);
    expect(unknown.block.registry.coverage).toBe("not-covered");
    expect(unknown.words).toBe(`not established — ${REGISTRY_VERSION}`);
    const status = registryEntry("Android Notification History - Status")!;
    const excluded = readOrigin("android", status.name, status.headers, ["1", "0"]);
    expect(excluded.block.registry.coverage).toBe("excluded");
    expect(excluded.words).toContain("excluded (a settings row");
  });
});

describe("facets from the row's own columns", () => {
  it("Safari Origin is a record-origin fact in Safari's words; it never becomes a visit by a person", () => {
    const e = registryEntry("Safari Browser - History")!;
    const local = readOrigin("ios", e.name, e.headers, [
      "",
      "t",
      "https://x.example",
      "1",
      "",
      "",
      "1",
      "Local Device",
      "Default",
    ]);
    expect(local.block.facets).toMatchObject({
      acquisition: "recorded-on-this-device",
      locality: "device-local",
      record: "history",
      authorship: "not-established",
    });
    expect(local.block.evidence).toContainEqual({
      facet: "acquisition",
      column: "Origin",
      value: "Local Device",
    });
    expect(local.words).not.toMatch(/visit(ed)? by|local-visit|the user/i);
    const synced = readOrigin("ios", e.name, e.headers, [
      "",
      "t",
      "https://x.example",
      "1",
      "",
      "",
      "1",
      "iCloud Synced Device",
      "Default",
    ]);
    expect(synced.block.facets.acquisition).toBe("synced-from-another-device");
    // A value the pinned release does not define is a conflict, said, not a guess.
    const odd = readOrigin("ios", e.name, e.headers, [
      "",
      "t",
      "https://x.example",
      "1",
      "",
      "",
      "1",
      "Other",
      "Default",
    ]);
    expect(odd.block.facets.acquisition).toBe("not-established");
    expect(odd.block.conflicts[0]).toContain('Origin reads "Other"');
  });
  it("iCloud Tabs are synced cloud tabs that NAME a device — an association, never a source or an actor", () => {
    const e = registryEntry("Safari Browser - iCloud Tabs")!;
    const r = readOrigin("ios", e.name, e.headers, [
      "",
      "",
      "t",
      "https://x.example",
      "Ana's iPad",
      "UUID-1",
      "T-1",
      "",
    ]);
    expect(r.block.facets).toMatchObject({
      acquisition: "synced",
      locality: "cloud",
      record: "tab",
      authorship: "not-established",
    });
    expect(r.block.device).toEqual({ name: "Ana's iPad", id: "UUID-1" });
    expect(r.words).toContain('row names device "Ana\'s iPad"');
    expect(r.words).not.toMatch(/\bfrom device|placed|by /);
    // An empty establishing column on a row that should have one: a conflict, and not-established.
    const blank = readOrigin("ios", e.name, e.headers, ["", "", "t", "https://x.example", "", "", "T-1", ""]);
    expect(blank.block.facets.acquisition).toBe("not-established");
    expect(blank.block.conflicts[0]).toContain("Device Name is empty");
  });
  it("a tab table establishes no acquisition; a notification is received, not read; a Chromium transition is a navigation fact", () => {
    const bs = registryEntry("Safari Browser - Tabs (BrowserState)")!;
    expect(readOrigin("ios", bs.name, bs.headers, ["", "t", "u", "u", "1", "0"]).block.facets).toMatchObject({
      acquisition: "not-established",
      record: "tab",
    });
    const duet = registryEntry("Notification Duet")!;
    const n = readOrigin("ios", duet.name, duet.headers, [
      "",
      "",
      "",
      "",
      "g",
      "Hi",
      "",
      "body",
      "com.app",
      "",
      "",
      "",
      "",
      "",
      "f",
      "0",
    ]);
    // The bundle id names the app that posted it; that establishes neither delivery nor a read.
    expect(n.block.facets).toMatchObject({
      acquisition: "not-established",
      record: "notification",
      authorship: "not-established",
    });
    const an = registryEntry("Android Notification History")!;
    expect(
      readOrigin("android", an.name, an.headers, ["", "T", "x", "com.pkg", "0", "1"]).block.facets
        .acquisition,
    ).toBe("not-established");
    const wv = registryEntry("Web Visits")!;
    for (const t of ["TYPED", "GENERATED", "LINK"]) {
      const r = readOrigin("android", wv.name, wv.headers, ["", "u", "t", "1", t, "", "", "Chrome"]);
      expect(r.block.facets.authorship, t).toBe("not-established");
      expect(r.block.facets.transition).toBe(t);
      expect(r.block.facets.acquisition).toBe("not-established");
    }
  });
  it("accounts, devices and app inventory: identity columns as associations; the store account as acquisition", () => {
    const acc = registryEntry("Accounts_ce")!;
    expect(
      readOrigin("android", acc.name, acc.headers, ["com.google", "a@example.invalid", ""]).block.account,
    ).toEqual({ name: "a@example.invalid", type: "com.google" });
    const dl = registryEntry("Apple Account - Device List")!;
    const d = readOrigin("ios", dl.name, dl.headers, [
      "",
      "",
      "Ana's iPhone",
      "iPhone14,2",
      "iOS",
      "17",
      "b",
      "SN1",
      "",
      "1",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
    ]);
    expect(d.block.device).toEqual({ name: "Ana's iPhone", id: "SN1" });
    expect(d.block.facets.record).toBe("device");
    const lib = registryEntry("InstalledappsLibrary")!;
    const l = readOrigin("android", lib.name, lib.headers, ["0", "", "buyer@example.invalid", "doc"]);
    expect(l.block.facets).toMatchObject({ acquisition: "from-store-account", record: "app-inventory" });
    expect(l.block.account).toEqual({ name: "buyer@example.invalid" });
    // The registry entry must be the requested platform's: an iOS table imported as Android is
    // said so, never read as iOS.
    const mismatch = readOrigin(
      "android",
      "Safari Browser - History",
      registryEntry("Safari Browser - History")!.headers,
      ["", "t", "u", "1", "", "", "1", "Local Device", "Default"],
    );
    expect(mismatch.block.registry.coverage).toBe("not-covered");
    expect(mismatch.words).toContain("a iLEAPP table imported as android");
    expect(mismatch.block.facets.acquisition).toBe("not-established");
    const gass = registryEntry("installedappsGass")!;
    const g = readOrigin("android", gass.name, gass.headers, ["0", "com.evil", "1", "A".repeat(64)]);
    expect(g.block.app).toEqual({ package: "com.evil", sha256: "a".repeat(64) });
    expect(
      readOrigin("android", gass.name, gass.headers, ["0", "com.evil", "1", "a".repeat(64)]).block.facets
        .record,
    ).toBe("app-inventory");
  });
});

describe("the tag on every row and the identity bound", () => {
  it("every row carries the tag and the counts say what the registry could cover; the device label is the asset", () => {
    const { text, filename } = tsv("Safari Browser - History", [
      { "Visit Timestamp": "2026-05-02 10:00:00", URL: "https://a.example", Origin: "Local Device" },
      { "Visit Timestamp": "2026-05-02 10:00:01", URL: "https://a.example", Origin: "iCloud Synced Device" },
    ]);
    const r = parseLeappTsv(text, filename, { platform: "ios", device: "Ana's iPhone" });
    expect(r.origin).toEqual({
      registry: REGISTRY_VERSION,
      schemaMatches: 2,
      headersDiffer: 0,
      notCovered: 0,
      excluded: 0,
    });
    expect(r.events[0].description).toContain(
      `[origin: recorded-on-this-device, device-local, history — ${REGISTRY_VERSION}]`,
    );
    expect(r.events[1].description).toContain("[origin: synced-from-another-device,");
    expect(r.events.every((e) => e.asset === "Ana's iPhone")).toBe(true);
    expect(r.events[0].canonical?.mobile?.facets.acquisition).toBe("recorded-on-this-device");
    expect(r.events[0].canonical?.event).toMatchObject({ category: "other", type: "mobile-history" });
    const unknown = parseLeappTsv("Name\tValue\na\t1", "Knowledge.tsv");
    expect(unknown.origin.notCovered).toBe(1);
    expect(unknown.events[0].asset).toBeUndefined();
  });
  it("a local and a synced row of the same content are two events; the same reading twice folds", () => {
    const { text, filename } = tsv("Safari Browser - History", [
      { "Visit Timestamp": "2026-05-02 10:00:00", URL: "https://a.example", Origin: "Local Device" },
      { "Visit Timestamp": "2026-05-02 10:00:00", URL: "https://a.example", Origin: "iCloud Synced Device" },
      { "Visit Timestamp": "2026-05-02 10:00:00", URL: "https://a.example", Origin: "iCloud Synced Device" },
    ]);
    const r = parseLeappTsv(text, filename, { platform: "ios" });
    expect(r.events).toHaveLength(2);
  });
  it("the whole description is digest-bounded: two long rows with a long device name stay distinct at 600", () => {
    const long = "x".repeat(450);
    const { text, filename } = tsv("Safari Browser - iCloud Tabs", [
      {
        Title: `${long}AAAA`,
        URL: "https://a.example",
        "Device Name": `${"d".repeat(70)}1`,
        "Device UUID": "U",
      },
      {
        Title: `${long}BBBB`,
        URL: "https://a.example",
        "Device Name": `${"d".repeat(70)}2`,
        "Device UUID": "U",
      },
    ]);
    const r = parseLeappTsv(text, filename, { platform: "ios" });
    expect(r.events).toHaveLength(2);
    for (const e of r.events) {
      expect(e.description.length).toBeLessThanOrEqual(600);
      expect(e.description).toMatch(/#[0-9a-f]{16}$/);
    }
    expect(r.events[0].description).not.toBe(r.events[1].description);
    // Two rows that differ ONLY in the device name past the clipped tag are still two rows.
    const sameTitle = tsv("Safari Browser - iCloud Tabs", [
      { Title: "t", URL: "https://a.example", "Device Name": `${"d".repeat(70)}1`, "Device UUID": "U" },
      { Title: "t", URL: "https://a.example", "Device Name": `${"d".repeat(70)}2`, "Device UUID": "U" },
    ]);
    expect(parseLeappTsv(sameTitle.text, sameTitle.filename, { platform: "ios" }).events).toHaveLength(2);
  });
  it("a row imported before the tag existed joins its tagged re-import in correlation; two readings never join", () => {
    const { text, filename } = tsv("Safari Browser - History", [
      { "Visit Timestamp": "2026-05-02 10:00:00", URL: "https://a.example", Origin: "Local Device" },
      { "Visit Timestamp": "2026-05-02 10:00:00", URL: "https://a.example", Origin: "iCloud Synced Device" },
    ]);
    const fresh = parseLeappTsv(text, filename, { platform: "ios" }).events;
    const ev = (e: (typeof fresh)[number], id: string): ForensicEvent => ({
      ...e,
      id,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    });
    const legacy: ForensicEvent = {
      ...ev(fresh[0], "old1"),
      description: fresh[0].description.replace(/ \[origin: [^\]]*\]/, ""),
      canonical: undefined,
    };
    const out = correlateEvents([legacy, ev(fresh[0], "new1"), ev(fresh[1], "new2")]);
    expect(out).toHaveLength(2);
    expect(out.some((e) => e.description.includes("recorded-on-this-device"))).toBe(true);
    expect(out.some((e) => e.description.includes("synced-from-another-device"))).toBe(true);
    // The other order too.
    expect(correlateEvents([ev(fresh[0], "new1"), legacy, ev(fresh[1], "new2")])).toHaveLength(2);
    // Two tagged readings of one and the same text (the tag alone differs — built by hand, since
    // every parsed column is in the detail too): the legacy row stays its own row and the two
    // readings never meet — in every order.
    const base = fresh[0].description.replace(/ \[origin: [^\]]*\]/, "");
    const tagged = (id: string, reading: string): ForensicEvent => ({
      ...ev(fresh[0], id),
      description: base.replace(/\]: /, `] [origin: ${reading} — leapp-origin-x]: `),
    });
    const local2 = tagged("new1b", "recorded-on-this-device, device-local, history");
    const synced2 = tagged("new2b", "synced-from-another-device, device-local, history");
    const legacyOfBoth = { ...legacy, id: "old2" };
    for (const order of [
      [legacyOfBoth, local2, synced2],
      [local2, legacyOfBoth, synced2],
      [synced2, local2, legacyOfBoth],
    ]) {
      const out2 = correlateEvents(order);
      expect(out2, order.map((e) => e.id).join(",")).toHaveLength(3);
    }
    // One tagged reading of that text: the legacy row joins it.
    expect(correlateEvents([legacyOfBoth, local2])).toHaveLength(1);
    // A non-LEAPP row with the same text and time never absorbs a tagged LEAPP row.
    const foreign: ForensicEvent = {
      ...legacy,
      id: "x1",
      description: legacy.description.replace(/^iLEAPP/, "Other tool"),
    };
    expect(correlateEvents([foreign, ev(fresh[0], "new1")])).toHaveLength(2);
  });
});
