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

  it("skips a row whose timestamp cell is empty", () => {
    const partial = ["Timestamp\tDetail", "\tno time here", "2026-05-02 12:00:00\treal"].join("\n");
    const r = parseLeappTsv(partial, "Knowledge.tsv");
    expect(r.events).toHaveLength(1);
  });

  it("extracts a URL appearing in any column as an IOC", () => {
    const withUrl = ["Timestamp\tURL", "2026-05-02 12:00:00\thttps://lure.example.invalid/app.apk"].join(
      "\n",
    );
    const r = parseLeappTsv(withUrl, "Browser History.tsv");
    expect(r.iocs.map((i) => i.value)).toContain("lure.example.invalid");
  });

  it("returns nothing usable when no column looks like a timestamp", () => {
    const noTime = ["Name\tValue", "a\tb"].join("\n");
    const r = parseLeappTsv(noTime, "Settings.tsv");
    expect(r.events).toHaveLength(0);
  });
});
