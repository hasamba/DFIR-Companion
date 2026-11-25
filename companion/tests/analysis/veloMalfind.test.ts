// Windows.Detection.Malfind — Velociraptor's YARA scan of private executable memory, one row per
// flagged region. It reached the generic mapper, which titled a row by the process name alone, showed
// no details, and keyed every region of one process together, so distinct regions folded into one
// row. Values here are invented; only the column layout follows the artifact.
import { describe, expect, it } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";

const ART = "Windows.Detection.Malfind";

const region = (range: string, over: Record<string, unknown> = {}): Record<string, unknown> => ({
  CreateTime: "2026-06-01T08:00:00.1234567Z",
  Pid: 4321,
  Name: "example.exe",
  _Address: 1,
  AddressRange: range,
  Protection: "xrw",
  SectionSize: 65536,
  HexHeader: "4d 5a",
  DataMagic: "data",
  SectionData: "4d5a90000300",
  YaraHit: [
    {
      Rule: "Example_Shellcode_Rule",
      Meta: { description: "example shellcode marker" },
      Tags: [],
      String: { Name: "$s1", Offset: 16, HexData: ["00000010 41 41"], Data: "AA" },
    },
  ],
  ProcessChain: [
    {
      Pid: "4321",
      Ppid: "1000",
      Name: "example.exe",
      CommandLine: '"C:\\Program Files\\Example\\example.exe" /run',
      Exe: "C:\\Program Files\\Example\\example.exe",
    },
  ],
  FlowId: "F.EXAMPLE",
  ClientId: "C.example",
  Fqdn: "WS-LAB-01",
  ...over,
});

const parse = (rows: Record<string, unknown>[]) =>
  parseVelociraptorJson(JSON.stringify({ [ART]: rows })).events;
const split = (d: string): [string, string] => {
  const i = d.indexOf(" - ");
  return i < 0 ? [d, ""] : [d.slice(0, i), d.slice(i + 3)];
};

describe("Velociraptor Windows.Detection.Malfind", () => {
  it("titles the region: process, PID, address and protection", () => {
    const [e] = parse([region("0a1b0000-0a1c0000")]);
    const [title] = split(e.description);
    expect(title).toBe(
      `Velociraptor [${ART}]: executable memory region flagged in example.exe (PID 4321) at 0x0a1b0000 — protection xrw`,
    );
    expect(e.processName).toBe("example.exe");
    expect(e.mitreTechniques).toContain("T1055");
  });

  it("puts the YARA hit, the first bytes and the command line in the details", () => {
    const [e] = parse([region("0a1b0000-0a1c0000")]);
    const [, rest] = split(e.description);
    expect(rest).toContain("YARA Example_Shellcode_Rule: example shellcode marker");
    expect(rest).toContain("first bytes 4d 5a (MZ header)");
    expect(rest).toContain('example.exe" /run');
    expect(rest).not.toContain("4d5a90000300"); // the raw section dump stays out of the description
  });

  it("reads Velociraptor's 'xrw' as read-write-execute, not as a protection that does not corroborate", () => {
    const [e] = parse([region("0a1b0000-0a1c0000")]);
    expect(e.message).not.toContain("does not corroborate injection");
    expect(e.message?.toLowerCase()).toContain("execute");
  });

  it("keeps two regions of one process apart", () => {
    expect(parse([region("0a1b0000-0a1c0000"), region("0b000000-0b010000")])).toHaveLength(2);
  });

  it("keeps the current grade and time", () => {
    const [e] = parse([region("0a1b0000-0a1c0000")]);
    expect(e.severity).toBe("Medium");
    expect(e.timestamp).toContain("2026-06-01T08:00:00");
  });

  it("names the scan when the export carries no artifact name", () => {
    const [e] = parseVelociraptorJson(JSON.stringify([region("0a1b0000-0a1c0000")])).events;
    expect(e?.description.startsWith("Velociraptor Malfind: executable memory region flagged in")).toBe(true);
  });

  it("does not throw on a row with only the region columns", () => {
    const [e] = parse([{ Protection: "xrw", AddressRange: "00001000-00002000", Name: "x.exe", Fqdn: "H" }]);
    expect(e.description).toContain("executable memory region flagged in x.exe");
  });

  // #2881: the description was capped AFTER the host suffix, so a long CommandLine that put the core
  // within ~12 chars of the 1200-char cap left "… @ WS-LA" — and past the cap dropped the host.
  it("keeps the '@ HOST' suffix whole however long the CommandLine is", () => {
    for (let n = 850; n <= 1250; n++) {
      const proc = { Pid: "4321", Name: "example.exe", CommandLine: "c".repeat(n) };
      const [e] = parse([region("0a1b0000-0a1c0000", { ProcessChain: [proc] })]);
      expect(e.description.length).toBeLessThanOrEqual(1200);
      expect(e.description.endsWith(" @ WS-LAB-01")).toBe(true);
    }
  });
});
