import { describe, it, expect } from "vitest";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import {
  joinSubjectParts,
  renderSubjectField,
  stripImagePrefix,
  subjectBudget,
  subjectFieldCap,
} from "../../src/analysis/renderCommandLine.js";

// #1416 — the Sysmon EID 1 description capped CommandLine at 140 chars, and the evidence in a real
// command line sits in its TAIL. These four rows are the real INC-2026-028 shapes (Chainsaw-normalized
// Sysmon EID 1): the C2 socket, the meterpreter stage, the secretsdump target and the `whoami` all
// sat past the cap and never reached the AI.
const SIM = "C:\\Users\\Public\\ElpacoConfluenceSim";
const PWSH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const ROWS = [
  {
    image: `${SIM}\\Program Files\\Atlassian\\Confluence\\AnyDesk.exe`,
    args: "/d /v:off /c echo ELPACO-CANARY AnyDesk.exe --connect 45.227.254.124:443 --direct",
    tail: "45.227.254.124:443",
  },
  {
    image: `${SIM}\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\HAHLGiDDb.exe`,
    args: "/d /v:off /c echo ELPACO-CANARY HAHLGiDDb.exe --reported-meterpreter-stage 91.191.209.46:12385 --actual-loopback 127.0.0.1:12385",
    tail: "91.191.209.46:12385",
  },
  {
    image: `${SIM}\\Users\\noname\\Desktop\\Attacker\\share\\secretsdump.exe`,
    args: "/d /v:off /c echo ELPACO-CANARY secretsdump.exe -hashes :00000000000000000000000000000000 CANARY1@127.0.0.1",
    tail: "CANARY1@127.0.0.1",
  },
  {
    image: `${SIM}\\Program Files\\Atlassian\\Confluence\\tomcat9.exe`,
    args: "/d /v:off /c echo ELPACO-CANARY tomcat9.exe -^> cmd.exe /c whoami",
    tail: "whoami",
  },
];

function sysmonProc(image: string, commandLine: string, parentCommandLine = `"${PWSH}" -nop -w hidden`) {
  return {
    "@timestamp": "2026-02-11T09:46:58.001Z",
    log_name: "Microsoft-Windows-Sysmon/Operational",
    computer_name: "CONF-APP01.example.com",
    event_id: 1,
    level: "Information",
    event_data: {
      UtcTime: "2026-02-11 09:46:58.000",
      Image: image,
      CommandLine: commandLine,
      ParentImage: PWSH,
      ParentCommandLine: parentCommandLine,
      User: "ELPACO\\svc_confluence",
    },
  };
}
function elastic(...sources: object[]): string {
  return JSON.stringify({ data: sources.map((s) => ({ _index: "win", _type: "winevtx", _source: s })) });
}

describe("stripImagePrefix", () => {
  const image = "C:\\Windows\\System32\\cmd.exe";
  it("drops a quoted image the previous field already carries and marks the cut", () => {
    expect(stripImagePrefix(`"${image}" /c whoami`, image)).toBe("… /c whoami");
  });
  it("drops a bare image too, case-insensitively (Windows paths)", () => {
    expect(stripImagePrefix("c:\\windows\\system32\\CMD.EXE /c whoami", image)).toBe("… /c whoami");
  });
  it("keeps a command line that does not begin with the image", () => {
    expect(stripImagePrefix("cmd.exe /c whoami", image)).toBe("cmd.exe /c whoami");
  });
  it("keeps a command line that is the image alone — there are no arguments to show", () => {
    expect(stripImagePrefix(`"${image}"`, image)).toBe(`"${image}"`);
    expect(stripImagePrefix(image, image)).toBe(image);
  });
  it("never strips a bare-image prefix that is only a longer path's beginning", () => {
    expect(stripImagePrefix(`${image}.bak /x`, image)).toBe(`${image}.bak /x`);
  });
  it("is a no-op without an image", () => {
    expect(stripImagePrefix(`"${image}" /c whoami`, "")).toBe(`"${image}" /c whoami`);
  });
});

describe("subjectFieldCap", () => {
  it("gives the four command-shaped fields a wider cap and every other field 140", () => {
    for (const k of ["CommandLine", "ParentCommandLine", "ScriptBlockText", "Payload"]) {
      expect(subjectFieldCap(k)).toBeGreaterThanOrEqual(400);
    }
    for (const k of ["Image", "TargetFilename", "QueryName", "ImageLoaded"])
      expect(subjectFieldCap(k)).toBe(140);
  });
});

describe("renderSubjectField", () => {
  const lookup = (fields: Record<string, string>) => (name: string) => fields[name] ?? "";
  it("renders key=value, and strips the Image prefix from CommandLine", () => {
    const part = renderSubjectField(
      "CommandLine",
      `"${ROWS[0].image}" ${ROWS[0].args}`,
      lookup({ Image: ROWS[0].image }),
    );
    expect(part.key).toBe("CommandLine");
    expect(part.text).toBe(`CommandLine=… ${ROWS[0].args}`);
  });
  it("strips the ParentImage prefix from ParentCommandLine", () => {
    const part = renderSubjectField(
      "ParentCommandLine",
      `"${PWSH}" -nop -w hidden`,
      lookup({ ParentImage: PWSH }),
    );
    expect(part.text).toBe("ParentCommandLine=… -nop -w hidden");
  });
  it("reads NewProcessName for a Security 4688 CommandLine", () => {
    const part = renderSubjectField("CommandLine", `${PWSH} -enc AAAA`, lookup({ NewProcessName: PWSH }));
    expect(part.text).toBe("CommandLine=… -enc AAAA");
  });
  it("caps a plain field at 140 and a command field at its wider cap", () => {
    const long = "x".repeat(1000);
    expect(renderSubjectField("TargetFilename", long, lookup({})).text).toHaveLength(
      "TargetFilename=".length + 140,
    );
    expect(renderSubjectField("CommandLine", long, lookup({})).text).toHaveLength(
      "CommandLine=".length + subjectFieldCap("CommandLine"),
    );
  });
});

describe("joinSubjectParts", () => {
  const p = (key: string, v: string) => ({ key, text: `${key}=${v}` });
  it("joins with the ' - ' separator and leaves a line under budget alone", () => {
    expect(joinSubjectParts([p("Image", "a.exe"), p("CommandLine", "… /x")], 600)).toBe(
      "Image=a.exe - CommandLine=… /x",
    );
  });
  it("trims ParentCommandLine first when the whole line would overrun, and CommandLine keeps its tail", () => {
    const cmd = `… ${"c".repeat(300)} 45.227.254.124:443`;
    const parent = `… ${"p".repeat(300)} PARENT-TAIL`;
    const out = joinSubjectParts(
      [p("Image", "a.exe"), p("CommandLine", cmd), p("ParentCommandLine", parent)],
      450,
    );
    expect(out.length).toBeLessThanOrEqual(450);
    expect(out).toContain("45.227.254.124:443");
    expect(out).toContain("ParentCommandLine=… ppp");
    expect(out).not.toContain("PARENT-TAIL");
    expect(out).toMatch(/ParentCommandLine=… p+…$/);
  });
  it("trims CommandLine only when ParentCommandLine alone cannot make room", () => {
    const cmd = `… ${"c".repeat(380)} CMD-TAIL`;
    const parent = "… -nop";
    const out = joinSubjectParts([p("CommandLine", cmd), p("ParentCommandLine", parent)], 300);
    expect(out.length).toBeLessThanOrEqual(300);
    expect(out).toContain("ParentCommandLine=… -nop");
    expect(out).toMatch(/CommandLine=… c+…/);
  });
  it("has no budget when none is given", () => {
    const cmd = "c".repeat(2000);
    expect(joinSubjectParts([p("CommandLine", cmd)])).toBe(`CommandLine=${cmd}`);
  });
});

describe("subjectBudget", () => {
  it("is what the head and the host leave of the 600-char description, minus the separator", () => {
    expect(subjectBudget("Sysmon Process create (EID 1) - X\\y", " @ HOST")).toBe(600 - 35 - 7 - 3);
  });
});

describe("Sysmon EID 1 description keeps the command-line tail (#1416)", () => {
  for (const row of ROWS) {
    it(`carries ${row.tail} into the description and stays under 600 chars`, () => {
      const r = parseSiemExport(elastic(sysmonProc(row.image, `"${row.image}" ${row.args}`)));
      expect(r.events).toHaveLength(1);
      const d = r.events[0].description;
      expect(d.length).toBeLessThanOrEqual(600);
      expect(d).toContain(row.tail);
      // The path is rendered once, under Image; CommandLine carries the arguments after the marker.
      expect(d).toContain(`Image=${row.image}`);
      expect(d).toContain(`CommandLine=… ${row.args}`);
      expect(d).toContain("ParentCommandLine=… -nop -w hidden");
      expect(d).toContain("@ CONF-APP01.example.com");
    });
  }

  it("keeps a command line that does not repeat its Image verbatim (grep habits intact)", () => {
    const r = parseSiemExport(
      elastic(sysmonProc("C:\\Windows\\System32\\taskeng.exe", "taskeng.exe {GUID}")),
    );
    expect(r.events[0].description).toContain("CommandLine=taskeng.exe {GUID}");
  });

  it("gives up ParentCommandLine before CommandLine when both are long", () => {
    const image = ROWS[1].image;
    const cmd = `"${image}" ${ROWS[1].args}`;
    const parent = `"${PWSH}" -nop -w hidden -c ${"Q".repeat(350)} PARENT-TAIL`;
    const r = parseSiemExport(elastic(sysmonProc(image, cmd, parent)));
    const d = r.events[0].description;
    expect(d.length).toBeLessThanOrEqual(600);
    expect(d).toContain(ROWS[1].tail);
    expect(d).toContain("--actual-loopback 127.0.0.1:12385");
    expect(d).toContain("ParentCommandLine=… -nop -w hidden -c QQQ");
    expect(d).not.toContain("PARENT-TAIL");
    expect(d).toMatch(/ @ CONF-APP01\.example\.com$/);
  });
});
