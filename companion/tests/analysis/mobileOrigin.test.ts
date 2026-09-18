import { describe, expect, it } from "vitest";
import {
  headersMatch,
  pinnedClocks,
  readOrigin,
  REGISTRY,
  REGISTRY_PINS,
  REGISTRY_VERSION,
  registryEntry,
} from "../../src/analysis/mobileOriginRegistry.js";
import { parseLeappTsv } from "../../src/analysis/mobileLeappImport.js";
import { correlateEvents } from "../../src/analysis/correlate.js";
import {
  APP_CORROBORATION_MARKER,
  markAppCorroboration,
} from "../../src/analysis/mobileBackgroundActivity.js";
import { INFECTION_WINDOW_MARKER, markInfectionWindow } from "../../src/analysis/mobileInfectionWindow.js";
import type { ForensicEvent, IOC } from "../../src/analysis/stateTypes.js";

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

/** readOrigin's positional `cells` array, built from an entry's header order and a row keyed by
 * header name — for many-column entries (App Data's 12), a name-keyed row is much less
 * error-prone than counting positions by hand. */
function cellsFor(entryName: string, row: Record<string, string>): string[] {
  const entry = registryEntry(entryName)!;
  return entry.headers.map((h) => row[h] ?? "");
}

describe("the registry pin", () => {
  it("names both upstream commits and every entry's exact header tuple", () => {
    expect(REGISTRY_PINS.iLEAPP.commit).toBe("6dc251d857c0");
    expect(REGISTRY_PINS.ALEAPP.commit).toBe("ce0880dc232c");
    expect(REGISTRY_VERSION).toBe("leapp-origin-2026-09-18");
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
      pinned: "iLEAPP@6dc251d857c0",
    });
    expect(r.words).not.toContain("producer-verified");
    const differ = readOrigin("ios", "Safari Browser - History", ["Visit Timestamp", "URL"], ["", ""]);
    expect(differ.block.registry.coverage).toBe("headers-differ");
    expect(differ.words).toContain("headers differ from the pinned release (iLEAPP@6dc251d857c0)");
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

// #932 item 16: four iOS entries (usage, power, permission, network) added to the registry so an
// app-identity corroboration pass can join across them; Notification Duet gains an `app` field so
// notifications join too.
describe("item 16 — usage/power/permission/network entries, and Notification Duet's app field", () => {
  it("knowledgeC App Usage reads an app identity, no acquisition claim (no establishing column)", () => {
    const r = readOrigin(
      "ios",
      "knowledgeC - App Usage",
      registryEntry("knowledgeC - App Usage")!.headers,
      cellsFor("knowledgeC - App Usage", {
        "Start Time": "2026-01-01 00:00:00",
        "End Time": "2026-01-01 00:05:00",
        "Time Added": "2026-01-01 00:05:00",
        Application: "com.example.app",
      }),
    );
    expect(r.block.registry.coverage).toBe("schema-matches");
    expect(r.block.facets).toMatchObject({ record: "usage", acquisition: "not-established" });
    expect(r.block.app).toEqual({ package: "com.example.app" });
  });

  it("PowerLog Application Runtime reads app identity; the seconds columns are never interpreted", () => {
    const r = readOrigin(
      "ios",
      "PowerLog - Application Runtime",
      registryEntry("PowerLog - Application Runtime")!.headers,
      cellsFor("PowerLog - Application Runtime", {
        Timestamp: "2026-01-01 00:00:00",
        "Bundle ID": "com.example.app",
        "Background Time (seconds)": "9999",
        "Screen-on Time (seconds)": "0",
      }),
    );
    expect(r.block.facets.record).toBe("power");
    expect(r.block.app).toEqual({ package: "com.example.app" });
    // Presence, not magnitude: nothing in the block or the words carries the seconds value.
    expect(r.words).not.toMatch(/9999/);
    expect(JSON.stringify(r.block)).not.toMatch(/9999/);
  });

  it("Application Permissions (modern TCC schema) carries Access via evidence and words, never dropped", () => {
    const r = readOrigin(
      "ios",
      "Application Permissions",
      registryEntry("Application Permissions")!.headers,
      cellsFor("Application Permissions", {
        "Last Modified Timestamp": "2026-01-01 00:00:00",
        "Bundle ID": "com.example.app",
        Service: "Camera",
        Access: "Not allowed",
      }),
    );
    expect(r.block.facets.record).toBe("permission");
    expect(r.block.app).toEqual({ package: "com.example.app" });
    expect(r.block.evidence).toContainEqual({ facet: "access", column: "Access", value: "Not allowed" });
    expect(r.words).toContain("access Not allowed");
  });

  it("the legacy TCC schema (no Last Modified column) reads headers-differ, not permission", () => {
    const r = readOrigin(
      "ios",
      "Application Permissions",
      ["Bundle ID", "Service", "Access", "Prompt Count"],
      ["com.example.app", "Camera", "Allowed", "2"],
    );
    expect(r.block.registry.coverage).toBe("headers-differ");
    expect(r.block.facets.record).not.toBe("permission");
  });

  it("App Data (netusage) identifies by Bundle Name, never Process Name; ZKIND is read as stored", () => {
    const r = readOrigin(
      "ios",
      "App Data",
      registryEntry("App Data")!.headers,
      cellsFor("App Data", {
        "Live Usage Timestamp": "2026-01-01 00:00:00",
        "Process First Usage Timestamp": "2026-01-01 00:00:00",
        "Process Timestamp": "2026-01-01 00:00:00",
        "Bundle Name": "com.example.app",
        "Process Name": "com.example.app-daemon",
        "ZKIND (as stored)": "7",
        "Wifi In (Bytes)": "12345",
      }),
    );
    expect(r.block.facets.record).toBe("network");
    expect(r.block.app).toEqual({ package: "com.example.app" });
    expect(r.block.app?.package).not.toContain("daemon");
  });

  it("Notification Duet now reads app.package from Bundle ID (never Bundle ID 2), unaffected words/tag", () => {
    const e = registryEntry("Notification Duet")!;
    const r = readOrigin(
      "ios",
      e.name,
      e.headers,
      cellsFor(e.name, {
        "SEGB Timestamp": "2026-01-01 00:00:00",
        "Bundle ID": "com.example.app",
        "Bundle ID 2": "com.example.other",
      }),
    );
    expect(r.block.app).toEqual({ package: "com.example.app" });
    // The tag/words builder never renders `app` — adding the field changes no existing behavior.
    expect(r.words).not.toContain("com.example.app");
  });

  it("every pre-existing iOS entry still reads schema-matches after the pin move to 6dc251d857c0", () => {
    for (const name of [
      "Safari Browser - History",
      "Safari Browser - iCloud Tabs",
      "Safari Browser - Tabs (BrowserState)",
      "Safari Browser - Tabs (SafariTabs)",
      "Notification Duet",
      "Account Data",
      "Apple Account - Device List",
    ]) {
      const e = registryEntry(name)!;
      const r = readOrigin(
        "ios",
        name,
        e.headers,
        e.headers.map(() => "x"),
      );
      expect(r.block.registry.coverage, name).toBe("schema-matches");
    }
  });
});

// #1298 (932.15 family): seven ALEAPP AppOps / usagestats artifacts join the registry — the
// Android granted/used-permission prerequisite. Every Android tuple below is typed out from the
// upstream `data_headers` read at the pinned commit, NOT taken from `entry.headers`: a registry
// tuple that drifts from upstream must fail here (#1336 — the notification entry pinned 17 of 23
// columns and the old fixture, built from the entry's own tuple, could never notice).
const ALEAPP_UPSTREAM: Record<string, readonly string[]> = {
  "Web History": [
    "Last Visit Time",
    "URL",
    "Title",
    "Visit Count",
    "Typed Count",
    "ID",
    "Hidden",
    "Browser Name",
  ],
  "Web Visits": [
    "Visit Timestamp",
    "URL",
    "Title",
    "Duration",
    "Transition Type",
    "Qualifier(s)",
    "From Visit URL",
    "Browser Name",
  ],
  "Search Terms": ["Last Visit Time", "Search Term", "URL", "Title", "Visit Count", "Browser Name"],
  "Android Notification History": [
    "Posted Time",
    "Title",
    "Text",
    "Package Name",
    "User ID",
    "UID",
    "Package Index",
    "Channel Name",
    "Channel Name Index",
    "Channel ID",
    "Channel ID Index",
    "Conversation ID",
    "Conversation ID Index",
    "Major Version",
    "Image Type",
    "Image Bitmap Filename",
    "Image Resource ID",
    "Image Resource ID Package",
    "Image Data Length",
    "Image Data Offset",
    "Image URI",
    "Protobuf File Name",
    "Timestamp From Protobuf File Name",
  ],
  "Android Notification History - Status": ["Status", "User"],
  "Android Notification History - Snoozed": ["Reminder Time", "Snoozed Notification"],
  Accounts_ce: ["Account Type", "Account Name", "Password"],
  installedappsGass: ["User", "Bundle ID", "Version Code", "SHA-256 Hash"],
  InstalledappsLibrary: ["User", "Purchase Time", "Account", "Doc ID"],
  // appops.py line 143 / 167
  "App Ops Permissions": [
    "Access Timestamp",
    "Reject Timestamp",
    "Package Name",
    "ID",
    "Proxy Package Name",
    "Proxy Package UID",
    "Permission",
  ],
  "App Ops Permissions - Legacy": [
    "Timestamp TP",
    "Timestamp TC",
    "Timestamp TB",
    "Timestamp TF",
    "Timestamp TFS",
    "Timestamp TT",
    "Package Name",
    "Duration",
    "Proxy Package Name",
    "Proxy Package UID",
    "Permission",
  ],
  // appOpsAccesses.py
  "App Ops Recent Accesses": [
    "Access Timestamp",
    "Reject Timestamp",
    "Package Name",
    "UID",
    "Permission",
    "Op Code",
    "Attribution Tag",
    "App State At Access",
    "Access Flag",
    "Access Duration (ms)",
    "Op Mode",
    "Proxy Package Name",
    "Proxy Attribution Tag",
    "Proxy UID",
    "Source File",
  ],
  // appOpsModes.py
  "App Ops Permission Modes": [
    "Package Name",
    "UID",
    "Android User",
    "Permission",
    "Op Code",
    "Mode",
    "Mode Stored Against",
    "Source File",
  ],
  // permissionAccessState.py, two processors
  "App Op Modes (Permission Store)": [
    "Package Name",
    "App ID",
    "Android User",
    "App Op",
    "Op Code",
    "Mode",
    "Mode Stored Against",
  ],
  "Permission Grants (Permission Store)": [
    "Package Name",
    "App ID",
    "Android User",
    "Permission",
    "Granted",
    "Permission Flags",
  ],
  // usagestats.py
  "Usage Stats": [
    "User (UID)",
    "Timestamp / Last Time Active",
    "Usage Type",
    "Time Active (ms)",
    "Time Active (sec)",
    "Last Time Service Used",
    "Total Time Service Used (ms)",
    "Last Time Visible",
    "Total Time Visible (ms)",
    "Last Time Component Used",
    "App Launch Count",
    "Package",
    "Event Type",
    "Class",
    "Event Flags (as stored)",
    "Shortcut ID",
    "Standby Bucket (high 16 bits)",
    "Standby Reason (low 16 bits)",
    "Notification Channel",
    "Instance ID",
    "Task Root Package",
    "Task Root Class",
    "Locus ID",
    "Interaction Category",
    "Interaction Action",
    "Interval",
  ],
};

/** readOrigin against the UPSTREAM tuple (not the entry's), a row keyed by header name. */
function upstreamRead(name: string, row: Record<string, string>) {
  const headers = ALEAPP_UPSTREAM[name];
  return readOrigin(
    "android",
    name,
    headers,
    headers.map((h) => row[h] ?? ""),
  );
}

describe("#1298 — ALEAPP AppOps / usagestats entries, pinned and cross-checked against upstream", () => {
  it("every Android entry's tuple is exactly the upstream data_headers at the pinned commit", () => {
    const android = REGISTRY.filter((e) => e.platform === "android").map((e) => e.name);
    expect(android.sort()).toEqual(Object.keys(ALEAPP_UPSTREAM).sort());
    for (const [name, headers] of Object.entries(ALEAPP_UPSTREAM)) {
      const entry = registryEntry(name)!;
      expect(entry, name).toBeDefined();
      expect(headersMatch(entry, headers), name).toBe(true);
      expect(entry.headers.length, name).toBe(headers.length);
    }
  });

  it("#1336 — Android Notification History reads schema-matches on a real 23-column export, with its package typed", () => {
    const r = upstreamRead("Android Notification History", {
      "Posted Time": "2026-05-02 10:00:00",
      Title: "hi",
      "Package Name": "com.example.chat",
    });
    expect(r.block.registry.coverage).toBe("schema-matches");
    expect(r.block.facets.record).toBe("notification");
    expect(r.block.app).toEqual({ package: "com.example.chat" });
  });

  it("App Ops Permissions: a permission record with a typed package; no outcome column, no acquisition, no authorship", () => {
    const r = upstreamRead("App Ops Permissions", {
      "Reject Timestamp": "2026-05-02 10:00:00",
      "Package Name": "com.example.app",
      Permission: "CAMERA",
    });
    expect(r.block.registry.coverage).toBe("schema-matches");
    expect(r.block.registry.pinned).toBe("ALEAPP@ce0880dc232c");
    expect(r.block.facets).toMatchObject({
      record: "permission",
      locality: "device-local",
      acquisition: "not-established",
      authorship: "not-established",
    });
    expect(r.block.app).toEqual({ package: "com.example.app" });
    expect(r.block.evidence.find((e) => e.facet === "access")).toBeUndefined();
    expect(r.words).toBe(`not-established, device-local, permission — ${REGISTRY_VERSION}`);
    expect(r.words).not.toMatch(/granted by|the user|malicious/i);
  });

  it("App Ops Permissions - Legacy is registered as the same kind of record", () => {
    const r = upstreamRead("App Ops Permissions - Legacy", {
      "Timestamp TT": "2026-05-02 10:00:00",
      "Package Name": "com.example.app",
      Permission: "READ_SMS",
    });
    expect(r.block.registry.coverage).toBe("schema-matches");
    expect(r.block.facets.record).toBe("permission");
    expect(r.block.app).toEqual({ package: "com.example.app" });
  });

  it("the four mode/state tables carry Op Mode / Mode / Granted verbatim, and the words name the column that said it", () => {
    // Values as ALEAPP writes them: OP_MODES at android-15.0.0_r1 (appOpsAccesses.py) is ALLOWED /
    // IGNORED / ERRORED / DEFAULT / FOREGROUND, or the stored integer outside that set; Granted is
    // Yes / No from AOSP's own isPermissionGranted port, or the raw flags value when undecidable.
    // Three different facts (a mode at access time, a configured mode, a stored grant) — so the
    // words say which column spoke, never one shared label for all three.
    const cases: [string, string, string, string][] = [
      ["App Ops Recent Accesses", "Op Mode", "ALLOWED", "(op mode ALLOWED)"],
      ["App Ops Permission Modes", "Mode", "ERRORED", "(mode ERRORED)"],
      ["App Op Modes (Permission Store)", "Mode", "7", "(mode 7)"],
      ["Permission Grants (Permission Store)", "Granted", "Yes", "(granted Yes)"],
    ];
    for (const [name, column, value, words] of cases) {
      const r = upstreamRead(name, { "Package Name": "com.example.app", [column]: value });
      expect(r.block.registry.coverage, name).toBe("schema-matches");
      expect(r.block.facets.record, name).toBe("permission");
      expect(r.block.app, name).toEqual({ package: "com.example.app" });
      expect(r.block.evidence, name).toContainEqual({ facet: "access", column, value });
      expect(r.words, name).toContain(words);
      expect(r.words, name).not.toContain("(access ");
    }
    // A stored `No` never reads like a `Yes`; an empty cell says nothing at all.
    const no = upstreamRead("Permission Grants (Permission Store)", {
      "Package Name": "com.x",
      Granted: "No",
    });
    expect(no.words).toContain("(granted No)");
    expect(no.words).not.toContain("Yes");
    const blank = upstreamRead("Permission Grants (Permission Store)", { "Package Name": "com.x" });
    expect(blank.block.evidence.find((e) => e.facet === "access")).toBeUndefined();
    expect(blank.words).not.toContain("granted");
    // The iOS TCC reading is unchanged: its column is literally `Access`.
    const tcc = registryEntry("Application Permissions")!;
    const t = readOrigin(
      "ios",
      tcc.name,
      tcc.headers,
      cellsFor(tcc.name, { "Bundle ID": "com.a", Access: "Not allowed" }),
    );
    expect(t.words).toContain("(access Not allowed)");
  });

  it("a renamed or missing column on a new entry is headers-differ, never a guess", () => {
    const h = [...ALEAPP_UPSTREAM["Permission Grants (Permission Store)"]];
    const renamed = h.map((x) => (x === "Granted" ? "Is Granted" : x));
    const r = readOrigin(
      "android",
      "Permission Grants (Permission Store)",
      renamed,
      renamed.map(() => ""),
    );
    expect(r.block.registry.coverage).toBe("headers-differ");
    expect(r.block.app).toBeUndefined();
    const short = readOrigin("android", "Usage Stats", ALEAPP_UPSTREAM["Usage Stats"].slice(0, 25), []);
    expect(short.block.registry.coverage).toBe("headers-differ");
  });

  it("pinnedClocks: an entry's declared clocks are upstream's own datetime columns, only when the headers match the pin", () => {
    expect(
      pinnedClocks(
        "android",
        "App Ops Permissions - Legacy",
        ALEAPP_UPSTREAM["App Ops Permissions - Legacy"],
      ),
    ).toEqual([0, 1, 2, 3, 4, 5]);
    expect(pinnedClocks("android", "Usage Stats", ALEAPP_UPSTREAM["Usage Stats"])).toEqual([1, 5, 7, 9]);
    expect(
      pinnedClocks("android", "App Ops Recent Accesses", ALEAPP_UPSTREAM["App Ops Recent Accesses"]),
    ).toEqual([0, 1]);
    // No declaration → the importer's generic picker; a mismatched tuple → the generic picker too.
    expect(pinnedClocks("android", "Web Visits", ALEAPP_UPSTREAM["Web Visits"])).toBeUndefined();
    expect(pinnedClocks("android", "Usage Stats", ALEAPP_UPSTREAM["Usage Stats"].slice(1))).toBeUndefined();
    expect(pinnedClocks("ios", "Usage Stats", ALEAPP_UPSTREAM["Usage Stats"])).toBeUndefined();
    // An `unknown`-platform import matches, exactly as readOrigin lets it.
    expect(pinnedClocks("unknown", "Usage Stats", ALEAPP_UPSTREAM["Usage Stats"])).toEqual([1, 5, 7, 9]);
  });

  it("Usage Stats: a usage record identified by Package; the duration columns are never a facet", () => {
    const r = upstreamRead("Usage Stats", {
      "User (UID)": "0",
      "Timestamp / Last Time Active": "2026-05-02 10:00:00",
      "Usage Type": "packages",
      "Time Active (ms)": "123456",
      Package: "com.example.app",
    });
    expect(r.block.registry.coverage).toBe("schema-matches");
    expect(r.block.facets).toMatchObject({ record: "usage", acquisition: "not-established" });
    expect(r.block.app).toEqual({ package: "com.example.app" });
    expect(r.block.evidence.map((e) => e.column)).not.toContain("Time Active (ms)");
  });

  it("end to end: a Usage Stats row whose first clock is empty is dated by the next datetime column — never by a duration", () => {
    const headers = ALEAPP_UPSTREAM["Usage Stats"];
    const row = (cells: Record<string, string>) => headers.map((h) => cells[h] ?? "").join("\t");
    const text = [
      headers.join("\t"),
      row({
        "User (UID)": "0",
        "Time Active (ms)": "123456",
        "Time Active (sec)": "123",
        "Last Time Visible": "2026-05-02 10:00:00",
        Package: "com.example.app",
      }),
      row({ "User (UID)": "0", "Time Active (ms)": "999", Package: "com.example.app" }),
    ].join("\n");
    const r = parseLeappTsv(text, "Usage Stats.tsv", { platform: "android" });
    expect(r.origin.schemaMatches).toBe(2);
    expect(r.events).toHaveLength(2);
    // aggregateEvents sorts, so find each row by its content, never by position.
    const dated = r.events.find((e) => e.description.includes("123456"))!;
    const durationsOnly = r.events.find((e) => e.description.includes("999"))!;
    expect(dated.timestamp).toBe("2026-05-02T10:00:00Z");
    expect(dated.description).toContain("[Last Time Visible: 2026-05-02 10:00:00]");
    expect(dated.canonical?.mobile?.facets.record).toBe("usage");
    // Only durations populated: undated, and no duration is ever shown as the row's clock.
    expect(r.undated).toBe(1);
    expect(durationsOnly.timestamp).toBe("");
    expect(durationsOnly.description).not.toMatch(/\[Time Active \((ms|sec)\): /);
  });

  it("end to end: a Legacy AppOps row is dated by whichever Timestamp T* column is populated, in upstream order", () => {
    const headers = ALEAPP_UPSTREAM["App Ops Permissions - Legacy"];
    const row = (cells: Record<string, string>) => headers.map((h) => cells[h] ?? "").join("\t");
    const text = [
      headers.join("\t"),
      row({
        "Timestamp TT": "2026-05-02 10:00:00",
        "Package Name": "com.example.app",
        Permission: "READ_SMS",
      }),
      row({
        "Timestamp TC": "2026-05-01 09:00:00",
        "Timestamp TT": "2026-05-02 10:00:00",
        "Package Name": "com.example.app",
        Permission: "READ_SMS",
      }),
    ].join("\n");
    const r = parseLeappTsv(text, "App Ops Permissions - Legacy.tsv", { platform: "android" });
    expect(r.origin.schemaMatches).toBe(2);
    expect(r.undated).toBe(0);
    const byClock = (name: string) => r.events.find((e) => e.description.includes(`[${name}: `))!;
    expect(byClock("Timestamp TT").timestamp).toBe("2026-05-02T10:00:00Z");
    // Both TC and TT populated: TC wins, upstream order — TT stays in the rendered cells.
    const tc = byClock("Timestamp TC");
    expect(tc.timestamp).toBe("2026-05-01T09:00:00Z");
    expect(tc.description).toContain("2026-05-02 10:00:00");
  });

  it("end to end: a real 23-column Android Notification History row is dated by Posted Time and typed by package (#1336)", () => {
    const headers = ALEAPP_UPSTREAM["Android Notification History"];
    const row = (cells: Record<string, string>) => headers.map((h) => cells[h] ?? "").join("\t");
    const text = [
      headers.join("\t"),
      row({
        "Posted Time": "2026-05-02 10:00:00",
        Title: "hi",
        "Package Name": "com.example.chat",
        "Timestamp From Protobuf File Name": "2026-05-02 10:00:05",
      }),
    ].join("\n");
    const r = parseLeappTsv(text, "Android Notification History.tsv", { platform: "android" });
    expect(r.origin).toMatchObject({ schemaMatches: 1, headersDiffer: 0 });
    expect(r.events[0].timestamp).toBe("2026-05-02T10:00:00Z");
    expect(r.events[0].description).toContain("[Posted Time: 2026-05-02 10:00:00]");
    expect(r.events[0].canonical?.mobile?.app).toEqual({ package: "com.example.chat" });
  });

  it("end to end: which AppOps clock is populated is the outcome, and the row is dated by it and names it", () => {
    const headers = ALEAPP_UPSTREAM["App Ops Permissions"];
    const row = (cells: Record<string, string>) => headers.map((h) => cells[h] ?? "").join("\t");
    const text = [
      headers.join("\t"),
      row({
        "Reject Timestamp": "2026-05-02 10:00:00",
        "Package Name": "com.example.app",
        Permission: "CAMERA",
      }),
      row({
        "Access Timestamp": "2026-05-03 11:00:00",
        "Package Name": "com.example.app",
        Permission: "CAMERA",
      }),
    ].join("\n");
    const r = parseLeappTsv(text, "App Ops Permissions.tsv", {
      platform: "android",
      device: "Subject Pixel",
    });
    expect(r.origin.schemaMatches).toBe(2);
    expect(r.events).toHaveLength(2);
    const [rejected, accessed] = r.events;
    expect(rejected.timestamp).toBe("2026-05-02T10:00:00Z");
    expect(rejected.description).toContain("[Reject Timestamp: 2026-05-02 10:00:00]");
    expect(accessed.timestamp).toBe("2026-05-03T11:00:00Z");
    expect(accessed.description).toContain("[Access Timestamp: 2026-05-03 11:00:00]");
    for (const e of r.events) {
      expect(e.asset).toBe("Subject Pixel");
      expect(e.canonical?.mobile?.facets.record).toBe("permission");
      expect(e.canonical?.mobile?.app).toEqual({ package: "com.example.app" });
      expect(e.description).toContain(`permission — ${REGISTRY_VERSION}]`);
    }
  });

  it("end to end: a Permission Grants table has no clock — its rows import undated, never with an invented time", () => {
    const headers = ALEAPP_UPSTREAM["Permission Grants (Permission Store)"];
    const text = [
      headers.join("\t"),
      ["com.example.app", "10123", "0", "android.permission.READ_SMS", "Yes", "USER_SET"].join("\t"),
    ].join("\n");
    const r = parseLeappTsv(text, "Permission Grants (Permission Store).tsv", { platform: "android" });
    expect(r.origin.schemaMatches).toBe(1);
    expect(r.undated).toBe(1);
    expect(r.events[0].timestamp).toBe("");
    expect(r.events[0].description).toContain("(granted Yes)");
    expect(r.events[0].canonical?.mobile?.app).toEqual({ package: "com.example.app" });
  });

  // Consumer safety: the typed package on an Android permission/usage row must not leak into the
  // passes that read `app.package` today. (mobileAppPresenceComparator.ts reads the backup-
  // generation ledger, never a timeline row — structurally unaffected, no test to write.)
  it("markAppCorroboration is iOS-only: two Android rows naming one package on one device get no note", () => {
    const tsvOf = (name: string, cells: Record<string, string>) => {
      const headers = ALEAPP_UPSTREAM[name];
      return [headers.join("\t"), headers.map((h) => cells[h] ?? "").join("\t")].join("\n");
    };
    const a = parseLeappTsv(
      tsvOf("App Ops Permissions", {
        "Access Timestamp": "2026-05-02 10:00:00",
        "Package Name": "com.example.app",
        Permission: "CAMERA",
      }),
      "App Ops Permissions.tsv",
      { platform: "android", device: "Subject Pixel" },
    ).events[0];
    const u = parseLeappTsv(
      tsvOf("Usage Stats", {
        "Timestamp / Last Time Active": "2026-05-02 11:00:00",
        Package: "com.example.app",
      }),
      "Usage Stats.tsv",
      { platform: "android", device: "Subject Pixel" },
    ).events[0];
    const rows = [a, u].map((e, i) => ({
      ...e,
      id: `r${i}`,
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    })) as ForensicEvent[];
    for (const e of markAppCorroboration(rows)) expect(e.description).not.toContain(APP_CORROBORATION_MARKER);
  });

  it("markInfectionWindow: an Android permission row naming a live-malicious package is placed, never a sign — only an app-inventory row is", () => {
    const tsvOf = (name: string, cells: Record<string, string>) => {
      const headers = ALEAPP_UPSTREAM[name];
      return [headers.join("\t"), headers.map((h) => cells[h] ?? "").join("\t")].join("\n");
    };
    const perm = parseLeappTsv(
      tsvOf("App Ops Permissions", {
        "Access Timestamp": "2026-05-01 10:00:00",
        "Package Name": "com.evil.app",
        Permission: "CAMERA",
      }),
      "App Ops Permissions.tsv",
      { platform: "android", device: "Subject Pixel" },
    ).events[0];
    const rows = [
      { ...perm, id: "p1", mitreTechniques: [], relatedFindingIds: [], sourceScreenshots: [] },
    ] as ForensicEvent[];
    const iocs: IOC[] = [
      {
        id: "i1",
        type: "process",
        value: "com.evil.app",
        firstSeen: "2026-05-01T00:00:00Z",
        enrichments: [
          {
            source: "VirusTotal",
            verdict: "malicious",
            fetchedAt: "2026-05-01T00:00:00Z",
            assertionId: "a1",
            status: "live",
          },
        ],
      },
    ];
    // Alone, the permission row is not an earliest sign: nothing to place it against.
    for (const e of markInfectionWindow(rows, iocs, "2026-06-01T00:00:00Z"))
      expect(e.description).not.toContain(INFECTION_WINDOW_MARKER);
    // With an inventory sign later than it, it is placed BEFORE that sign like any other mobile row.
    const inv = parseLeappTsv(
      tsvOf("installedappsGass", {
        User: "0",
        "Bundle ID": "com.evil.app",
        "Version Code": "1",
        "SHA-256 Hash": "a".repeat(64),
      }),
      "installedappsGass.tsv",
      { platform: "android", device: "Subject Pixel" },
    ).events[0];
    const dated = {
      ...inv,
      id: "g1",
      timestamp: "2026-05-03T00:00:00Z",
      mitreTechniques: [],
      relatedFindingIds: [],
      sourceScreenshots: [],
    } as ForensicEvent;
    const marked = markInfectionWindow([...rows, dated], iocs, "2026-06-01T00:00:00Z");
    expect(marked[0].description).toContain("before the earliest sign");
  });
});
