import { describe, it, expect } from "vitest";
import { loadDashboardModule } from "../helpers/dashboardModule.js";

// #1496: the probe that decides whether the import asks "which host did this file come from?".
// Structural, with the server resolver's own vocabulary: a record key present, no collector key
// with a real value anywhere in the sample. It is a UX hint — the server decides nothing from it.

interface ProbeApi {
  probeBareWindowsExport: (text: string) => { bare: boolean; computers: string[] };
}

const api = loadDashboardModule<ProbeApi>("dashboard-import-severity.js", [], {
  localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
  document: { getElementById: () => null },
});

const OLD = "WIN-UK1GV882OK6";
const NEW = "DESKTOP-16OJFO6";

describe("probeBareWindowsExport", () => {
  it("a bare Chainsaw JSON export: asks, and names the machines it saw", () => {
    const text = JSON.stringify([
      { Computer: OLD, EventID: 4104, SystemData: { Computer: OLD } },
      { Computer: NEW, EventID: 1, SystemData: { Computer: NEW } },
      { Computer: OLD, EventID: 4624 },
    ]);
    expect(api.probeBareWindowsExport(text)).toEqual({ bare: true, computers: [OLD, NEW] });
  });

  it("a Velociraptor hunt export with Fqdn on a row does not ask", () => {
    const text = [
      JSON.stringify({ Fqdn: "desktop-16ojfo6.example.com", Computer: OLD, EventID: 4624 }),
      JSON.stringify({ Fqdn: "desktop-16ojfo6.example.com", Computer: NEW, EventID: 4624 }),
    ].join("\n");
    expect(api.probeBareWindowsExport(text).bare).toBe(false);
  });

  it("an absent collector value ('-') is no collector; the nested spellings count as record keys", () => {
    const text = [
      JSON.stringify({ Fqdn: "-", _Event: { System: { Computer: OLD } } }),
      JSON.stringify({ Hostname: "n/a", Event: { System: { Computer: NEW } } }),
    ].join("\n");
    expect(api.probeBareWindowsExport(text)).toEqual({ bare: true, computers: [OLD, NEW] });
  });

  it("a file with no record key (THOR, a process list) does not ask", () => {
    expect(api.probeBareWindowsExport(JSON.stringify([{ pid: 4, name: "System" }])).bare).toBe(false);
    expect(api.probeBareWindowsExport("not json at all").bare).toBe(false);
  });

  it("a Hayabusa CSV: a Computer column with no real collector value asks, and names the machines", () => {
    const bare =
      '"Timestamp","Computer","Channel","EventID"\n"t1","WIN-UK1GV882OK6","Sec","4624"\n"t2","DESKTOP-16OJFO6, lab","Sec","4624"\n';
    expect(api.probeBareWindowsExport(bare)).toEqual({
      bare: true,
      computers: ["WIN-UK1GV882OK6", "DESKTOP-16OJFO6, lab"],
    });
    const withFqdn = '"Timestamp","Fqdn","Computer"\n"t1","desktop-16ojfo6.example.com","WIN-UK1GV882OK6"\n';
    expect(api.probeBareWindowsExport(withFqdn).bare).toBe(false);
  });

  it("a CSV whose Hostname column holds only absent values ('-', 'n/a', blank) still asks", () => {
    const text =
      '"Timestamp","Hostname","Computer"\n"t1","-","WIN-UK1GV882OK6"\n"t2","n/a","WIN-UK1GV882OK6"\n"t3","","DESKTOP-16OJFO6"\n';
    expect(api.probeBareWindowsExport(text)).toEqual({
      bare: true,
      computers: ["WIN-UK1GV882OK6", "DESKTOP-16OJFO6"],
    });
  });

  it("lists at most five distinct names, case-insensitively", () => {
    const rows = ["A", "a", "B", "C", "D", "E", "F", "G"].map((c) => JSON.stringify({ Computer: c }));
    expect(api.probeBareWindowsExport(rows.join("\n")).computers).toEqual(["A", "B", "C", "D", "E"]);
  });
});
