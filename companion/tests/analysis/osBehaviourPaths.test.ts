// The #1593 own-child and AppX firewall rules on the native Hayabusa and Windows Event XML paths (#1621).
//
// #1593 wired both rules into the collector ledger, which only the Velociraptor and Chainsaw importers
// run. A Velociraptor `Windows.Hayabusa.Rules.json` routes by name to the NATIVE Hayabusa importer, and
// an Event Viewer XML export goes through the SIEM Windows mapping — neither ran them. Every rule here
// LOWERS a grade, so the bounds and the negatives are the important half: an intruder's powershell.exe
// opening lsass.exe stays High on every path, and a path whose rows lack the fields stays silent.
import { describe, expect, it } from "vitest";
import { parseHayabusaTimeline } from "../../src/analysis/hayabusaImport.js";
import { parseEvtxXml, parseEvtxXmlProgress } from "../../src/analysis/evtxXmlImport.js";
import { detectImportKind } from "../../src/analysis/importDetect.js";
import { OWN_CHILD_MARKER } from "../../src/analysis/processParentage.js";
import { APPX_FIREWALL_NOTE } from "../../src/analysis/appxFirewallChurn.js";
import { envelopeAgrees } from "../../src/analysis/osBehaviourRules.js";
import type { SiemEvent, SiemImportOptions } from "../../src/analysis/siemImport.js";
import {
  access,
  CMD,
  create,
  firewall,
  G,
  HOST,
  LSASS,
  PWSH,
  row,
  T0,
  toEventXml,
} from "./fixtures/osBehaviourRows.js";

type Rows = object[];
const ALL: SiemImportOptions = { minSeverity: "Info", aggregate: false };

// Hayabusa grades by the rule's Level; the access rows are raised to "high" so a demotion is visible.
const high = (r: object): Record<string, unknown> => ({ ...r, Level: "high" });
const hayabusa = (rows: Rows, opts = ALL): SiemEvent[] =>
  parseHayabusaTimeline(rows.map((r) => JSON.stringify(r)).join("\n"), opts).events;
const xml = (rows: Rows, opts = ALL): SiemEvent[] => parseEvtxXml(toEventXml(rows), opts).events;

const child = () => create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.pwsh, PWSH, `${HOST}\\vagrant`);
const ownAccess = (at = T0 + 50) => high(access(at, PWSH, G.pwsh, CMD, G.cmd));
const lsassAccess = () =>
  high(access(T0 + 60, PWSH, G.pwsh, LSASS, G.lsass, "Credential Dumping Tools Accessing LSASS Memory"));

const PATHS: [string, (rows: Rows, opts?: SiemImportOptions) => SiemEvent[]][] = [
  ["native Hayabusa", hayabusa],
  ["Windows Event XML", xml],
];

// Hayabusa's rendered row names the rule, not the target image; the XML row names the target.
const OWN = /Proc Access|TargetImage=\S*cmd\.exe/i;
const eid = (events: SiemEvent[], id: number, re = /./): SiemEvent[] =>
  events.filter((e) => new RegExp(`\\(EID ${id}\\b`).test(e.description) && re.test(e.description));
const accessGrade = (events: SiemEvent[], target: RegExp): string =>
  eid(events, 10, target)[0]?.severity ?? "missing";

describe.each(PATHS)("#1621 — %s: a parent's handle to its own child at creation", (_name, parse) => {
  it("is Info with the own-child note, linked by GUID", () => {
    const [own] = eid(parse([child(), ownAccess()]), 10);
    expect(own.severity).toBe("Info");
    expect(own.description).toContain(OWN_CHILD_MARKER);
  });

  it("NEGATIVE: an intruder's powershell.exe opening lsass.exe stays High in the same import", () => {
    const events = parse([child(), ownAccess(), lsassAccess()]);
    expect(accessGrade(events, /lsass/i)).toBe("High");
    expect(accessGrade(events, OWN)).toBe("Info");
  });

  it("keeps its grade without a creation record, or with another parent's GUID", () => {
    expect(accessGrade(parse([ownAccess()]), OWN)).toBe("High");
    const other = create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.other, PWSH, `${HOST}\\vagrant`);
    expect(accessGrade(parse([other, ownAccess()]), OWN)).toBe("High");
  });

  it("keeps its grade more than one second after the creation", () => {
    expect(accessGrade(parse([child(), ownAccess(T0 + 1_500)]), OWN)).toBe("High");
  });

  it("fails closed on conflicting creation records for the child", () => {
    const other = create(T0, CMD, "cmd.exe /c whoami", G.cmd, G.other, PWSH, `${HOST}\\vagrant`);
    expect(accessGrade(parse([child(), other, ownAccess()]), OWN)).toBe("High");
  });

  it("keeps its grade when a remote thread (EID 8) or tampering record (EID 25) targets the child", () => {
    const threadInto = row(8, T0 + 80, "Proc Injection", "medium", {
      SourceProcessGuid: G.pwsh,
      SourceImage: PWSH,
      TargetProcessGuid: G.cmd,
      TargetImage: CMD,
      StartAddress: "0x0000000000A10000",
    });
    const tamper = row(25, T0 + 80, "Process Tampering", "high", {
      ProcessGuid: G.cmd,
      Image: CMD,
      Type: "Image is replaced",
    });
    expect(accessGrade(parse([child(), ownAccess(), threadInto]), OWN)).toBe("High");
    expect(accessGrade(parse([tamper, child(), ownAccess()]), OWN)).toBe("High");
  });

  it("the demoted row falls below a Medium floor; the lsass access does not", () => {
    const events = parse([child(), ownAccess(), lsassAccess()], { minSeverity: "Medium", aggregate: false });
    expect(eid(events, 10).map((e) => e.severity)).toEqual(["High"]);
    expect(eid(events, 10)[0].description).toMatch(/lsass/i);
  });
});

describe.each(PATHS)("#1621 — %s: AppX package-update firewall churn", (_name, parse) => {
  // The XML mapping already files an unknown firewall EID as Info, so the proof is the rule's note:
  // a row the rule did not claim carries none (and keeps whatever grade its path gave it).
  const noted = (rows: Rows): boolean[] =>
    [...eid(parse(rows), 2052), ...eid(parse(rows), 2097)].map((e) =>
      e.description.includes(APPX_FIREWALL_NOTE),
    );

  it("both halves of an update pair are Info with the note", () => {
    const events = parse([firewall(2052, T0, "1.29.289.0"), firewall(2097, T0 + 30, "1.29.379.0")]);
    const fw = [...eid(events, 2052), ...eid(events, 2097)];
    expect(fw).toHaveLength(2);
    for (const e of fw) {
      expect(e.severity).toBe("Info");
      expect(e.description).toContain(APPX_FIREWALL_NOTE);
    }
  });

  it("a lone add, a pair more than 10 minutes apart, or a netsh change is not claimed", () => {
    expect(noted([firewall(2097, T0, "1.29.379.0")])).toEqual([false]);
    expect(noted([firewall(2052, T0, "1.29.289.0"), firewall(2097, T0 + 11 * 60_000, "1.29.379.0")])).toEqual(
      [false, false],
    );
    const netsh = { app: "C:\\Windows\\System32\\netsh.exe" };
    expect(
      noted([firewall(2052, T0, "1.29.289.0", netsh), firewall(2097, T0 + 30, "1.29.379.0", netsh)]),
    ).toEqual([false, false]);
  });
});

describe("#1621 — native Hayabusa: the rules need the parsed record", () => {
  it("a Windows.Hayabusa.Rules export routes to the native Hayabusa importer", () => {
    const text = [child(), ownAccess()].map((r) => JSON.stringify(r)).join("\n");
    expect(detectImportKind("Windows.Hayabusa.Rules.json", text)).toBe("hayabusa");
  });

  it("a plain timeline row (rendered Details, no `_Event`) stays silent and keeps its grade", () => {
    const plain = (r: object): object => {
      const { _Event: _dropped, ...rest } = r as Record<string, unknown>;
      return rest;
    };
    expect(accessGrade(hayabusa([plain(child()), plain(ownAccess())]), /./)).toBe("High");
  });

  it("NEGATIVE: a top-level EventData or a second wrapper cannot supply the GUID link for lsass", () => {
    // An lsass access whose embedded record is genuine, with forged link data beside it.
    const forged = { SourceProcessGUID: G.pwsh, TargetProcessGUID: G.cmd };
    const lsass = lsassAccess();
    const inner = (lsass._Event as { EventData: Record<string, unknown> }).EventData;
    const topLevel = { ...lsass, EventData: { ...inner, ...forged } };
    const second = { ...lsass, Event: { ...(lsass._Event as object), EventData: { ...inner, ...forged } } };
    for (const bad of [topLevel, second]) {
      expect(envelopeAgrees(bad, String(lsass.Timestamp))).toBe(false);
      expect(accessGrade(hayabusa([child(), bad]), /lsass/i)).toBe("High");
    }
  });

  it("a row whose envelope disagrees with its embedded record fails closed", () => {
    const moved = { ...ownAccess(), Computer: "OTHER01" };
    expect(accessGrade(hayabusa([child(), moved]), /./)).toBe("High");
    const lateAt = new Date(T0 + 5_050).toISOString();
    expect(envelopeAgrees({ ...ownAccess(), Timestamp: lateAt }, lateAt)).toBe(false);
    const relabelled = { ...ownAccess(), EID: 1 };
    expect(envelopeAgrees(relabelled, new Date(T0 + 50).toISOString())).toBe(false);
    expect(envelopeAgrees(ownAccess(), new Date(T0 + 50).toISOString())).toBe(true);
  });
});

describe("#1621 — Windows Event XML: one answer on both builders, provenance kept", () => {
  const rows = [
    child(),
    ownAccess(),
    lsassAccess(),
    firewall(2052, T0, "1.29.289.0"),
    firewall(2097, T0 + 30, "1.29.379.0"),
  ];

  it("the sync parse and the import route's progress parse agree", async () => {
    const text = toEventXml(rows);
    const sync = parseEvtxXml(text, { minSeverity: "Info" });
    const progress = await parseEvtxXmlProgress(text, { minSeverity: "Info" });
    expect(progress.events).toEqual(sync.events);
    expect(progress.iocs).toEqual(sync.iocs);
  });

  it("an IOC from a demoted row points at the row's final aggKey", () => {
    const r = parseEvtxXml(toEventXml(rows), { minSeverity: "Info" });
    const own = eid(r.events, 10, OWN)[0];
    expect(own.severity).toBe("Info");
    const keys = new Set(r.events.map((e) => e.aggKey));
    for (const ioc of r.iocs) for (const k of ioc.sourceAggKeys ?? []) expect(keys.has(k)).toBe(true);
    expect(own.aggKey).toBeTruthy();
    expect(r.iocs.some((i) => i.sourceAggKeys?.includes(own.aggKey ?? ""))).toBe(true);
  });
});
