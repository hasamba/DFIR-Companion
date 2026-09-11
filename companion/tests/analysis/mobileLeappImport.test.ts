import { describe, it, expect } from "vitest";
import { parseLeappTsv } from "../../src/analysis/mobileLeappImport.js";

const TSV = [
  "Timestamp\tApp Name\tBundle ID\tAction",
  "2026-05-02 10:00:00\tSignal\torg.whispersystems.signal\tinstalled",
  "2026-05-02 11:30:00\tUnknown Sideload\tcom.example.invalid.app\tinstalled",
].join("\n");

describe("parseLeappTsv", () => {
  it("reports an empty result for empty input", () => {
    const r = parseLeappTsv("", "");
    expect(r.total).toBe(0);
    expect(r.format).toBe("empty");
  });

  it("reads a TSV export and places each row on the timeline", () => {
    const r = parseLeappTsv(TSV, "Installed Apps.tsv");
    expect(r.total).toBe(2);
    expect(r.events).toHaveLength(2);
    expect(r.events[0].severity).toBe("Info");
  });

  it("names the artifact from the filename, which is where iLEAPP puts it", () => {
    const r = parseLeappTsv(TSV, "Installed Apps.tsv");
    expect(r.events[0].description).toContain("Installed Apps");
  });

  it("carries the row's own columns into the description", () => {
    const r = parseLeappTsv(TSV, "Installed Apps.tsv");
    expect(r.events[0].description).toContain("Signal");
    expect(r.events[0].description).toContain("org.whispersystems.signal");
  });

  it("stamps iLEAPP or ALEAPP from the source hint", () => {
    const ios = parseLeappTsv(TSV, "Installed Apps.tsv", { platform: "ios" });
    const android = parseLeappTsv(TSV, "Installed Apps.tsv", { platform: "android" });
    expect(ios.events[0].sources).toContain("iLEAPP");
    expect(android.events[0].sources).toContain("ALEAPP");
  });

  it("finds the timestamp column whatever it is called", () => {
    const alt = ["Start Time\tDetail", "2026-05-02 12:00:00\tsomething happened"].join("\n");
    const r = parseLeappTsv(alt, "Knowledge.tsv");
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp).toMatch(/^2026-05-02T12:00:00/);
  });

  // #932 item 12: a row with no usable time is EVIDENCE with no clock, not a parse failure. It is
  // kept undated; the pipeline renders "(undated)" and every consumer already handles "".
  it("keeps a row whose every time cell is empty, undated", () => {
    const partial = ["Timestamp\tDetail", "\tno time here", "2026-05-02 12:00:00\treal"].join("\n");
    const r = parseLeappTsv(partial, "Knowledge.tsv");
    expect(r.events).toHaveLength(2);
    expect(r.undated).toBe(1);
    const undated = r.events.find((e) => e.description.includes("no time here"))!;
    expect(undated.timestamp).toBe("");
    expect(undated.description).not.toMatch(/\[/); // no clock prefix when there is no clock
  });

  it("extracts a URL appearing in any column as an IOC", () => {
    const withUrl = ["Timestamp\tURL", "2026-05-02 12:00:00\thttps://lure.example.invalid/app.apk"].join(
      "\n",
    );
    const r = parseLeappTsv(withUrl, "Browser History.tsv");
    expect(r.iocs.map((i) => i.value)).toContain("lure.example.invalid");
  });

  it("imports a table with no time column at all as undated evidence", () => {
    const apps = [
      "Name\tBundle ID\tSource",
      "Signal\torg.whispersystems.signal\tApp Store",
      "Unknown Sideload\tcom.example.invalid.app\thttps://lure.example.invalid/app.apk",
    ].join("\n");
    const r = parseLeappTsv(apps, "Installed Apps.tsv", { platform: "ios" });
    expect(r.total).toBe(2);
    expect(r.events).toHaveLength(2);
    expect(r.undated).toBe(2);
    expect(r.format).toBe("leapp-tsv");
    for (const e of r.events) {
      expect(e.timestamp).toBe("");
      expect(e.severity).toBe("Info");
      expect(e.description).toMatch(/^iLEAPP Installed Apps: /);
    }
    expect(r.iocs.map((i) => i.value)).toContain("lure.example.invalid");
  });
});

// Which clock a row carries is part of the evidence: "Created" and "Last Modified" are different
// facts, and a file's chosen column is not the same for every row.
describe("parseLeappTsv — the row's clock keeps its meaning", () => {
  it("takes the first populated time column per row and names it in the description", () => {
    const tsv = [
      "Timestamp\tLast Modified\tPath",
      "2026-05-02 10:00:00\t2026-05-03 09:00:00\t/a",
      "\t2026-05-03 09:00:00\t/b",
    ].join("\n");
    const r = parseLeappTsv(tsv, "Files.tsv", { platform: "ios" });
    expect(r.events).toHaveLength(2);
    expect(r.undated).toBe(0);
    const a = r.events.find((e) => e.description.includes("/a"))!;
    const b = r.events.find((e) => e.description.includes("/b"))!;
    expect(a.timestamp).toMatch(/^2026-05-02T10:00:00/);
    expect(a.description).toContain("[Timestamp: 2026-05-02 10:00:00]");
    expect(a.description).toContain("Last Modified: 2026-05-03 09:00:00"); // the unused clock stays as prose
    expect(b.timestamp).toMatch(/^2026-05-03T09:00:00/);
    expect(b.description).toContain("[Last Modified: 2026-05-03 09:00:00]");
  });

  it("keeps two rows whose only difference is which clock carries the same value", () => {
    const tsv = [
      "Timestamp\tLast Modified\tPath",
      "2026-05-02 10:00:00\t\t/same",
      "\t2026-05-02 10:00:00\t/same",
    ].join("\n");
    const r = parseLeappTsv(tsv, "Files.tsv");
    expect(r.events).toHaveLength(2);
    expect(r.events.map((e) => /\[(Timestamp|Last Modified):/.exec(e.description)?.[1]).sort()).toEqual([
      "Last Modified",
      "Timestamp",
    ]);
  });

  it("skips a populated clock that does not parse and takes the next one that does", () => {
    const tsv = ["Timestamp\tLast Modified\tPath", "N/A\t2026-05-03 09:00:00\t/a", "N/A\t\t/b"].join("\n");
    const r = parseLeappTsv(tsv, "Files.tsv");
    const a = r.events.find((e) => e.description.includes("/a"))!;
    const b = r.events.find((e) => e.description.includes("/b"))!;
    expect(a.timestamp).toMatch(/^2026-05-03T09:00:00/);
    expect(a.description).toContain("[Last Modified: 2026-05-03 09:00:00]");
    // Nothing parses: undated, and the raw text stays visible rather than becoming the timestamp.
    expect(b.timestamp).toBe("");
    expect(b.description).toContain("[Timestamp: N/A]");
    expect(r.undated).toBe(1);
  });

  it("does not fold two rows that differ only by letter case", () => {
    const tsv = ["Name\tPath", "a\t/sdcard/Download/x", "a\t/sdcard/download/x"].join("\n");
    const r = parseLeappTsv(tsv, "Files.tsv");
    expect(r.events).toHaveLength(2);
  });

  it("keeps two rows that differ only in time as two events, and folds byte-identical rows", () => {
    const tsv = [
      "Timestamp\tApp",
      "2026-05-02 10:00:00\tSignal",
      "2026-05-02 11:00:00\tSignal",
      "2026-05-02 11:00:00\tSignal",
    ].join("\n");
    const r = parseLeappTsv(tsv, "Usage.tsv");
    expect(r.events).toHaveLength(2);
    expect(r.events.find((e) => e.timestamp.startsWith("2026-05-02T11"))?.count).toBe(2);
  });
});

// The description is the identity every later step keys on (correlation, the import diff, the
// super-timeline content key), so two long rows must not collapse into one description.
describe("parseLeappTsv — long rows stay distinct", () => {
  const prefix = "x".repeat(450);
  it("gives two rows that share a 400-character prefix two descriptions with their own digest tail", () => {
    const tsv = ["Name\tBlob", `a\t${prefix}AAAA`, `a\t${prefix}BBBB`].join("\n");
    const r = parseLeappTsv(tsv, "Blobs.tsv");
    expect(r.events).toHaveLength(2);
    const [d1, d2] = r.events.map((e) => e.description);
    expect(d1).not.toBe(d2);
    expect(d1).toMatch(/#[0-9a-f]{16}$/);
    expect(d2).toMatch(/#[0-9a-f]{16}$/);
  });

  it("bounds every prefix component so a long header and filename never push the tail out", () => {
    const header = `${"h".repeat(300)} time`; // the contains-pass accepts any header naming a time
    const tsv = [
      `Name\t${header}\tBlob`,
      `a\t2026-05-02 10:00:00\t${prefix}AAAA`,
      `a\t2026-05-02 10:00:00\t${prefix}BBBB`,
    ].join("\n");
    const r = parseLeappTsv(tsv, `${"f".repeat(200)}.tsv`);
    expect(r.events).toHaveLength(2);
    for (const e of r.events) {
      expect(e.description.length).toBeLessThanOrEqual(600);
      expect(e.description).toMatch(/#[0-9a-f]{16}$/);
    }
    expect(r.events[0].description).not.toBe(r.events[1].description);
  });
});

describe("parseLeappTsv — comma fallback", () => {
  it("keeps the columns aligned through a quoted comma", () => {
    const csv = [
      "Timestamp,Title,URL",
      '2026-05-02 10:00:00,"Hello, world",https://lure.example.invalid/x',
    ].join("\n");
    const r = parseLeappTsv(csv, "Browser History.csv");
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp).toMatch(/^2026-05-02T10:00:00/);
    expect(r.events[0].description).toContain("Title: Hello, world");
    expect(r.iocs.map((i) => i.value)).toContain("lure.example.invalid");
  });
});
