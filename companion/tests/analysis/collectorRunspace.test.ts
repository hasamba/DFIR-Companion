// The rows of the collector's PersistenceSniper run that no Tools-tree path reaches (#1555).
//
// Scenario 019 scored a Medium "PowerShell Add-Type reflective P/Invoke declaration" finding and a
// Low lookalike-domain finding off the collector's own Windows.Forensics.PersistenceSniper run.
// isDetectionToolScript already graded the 4104 / 4103 / 800 records whose ENGINE-WRITTEN script
// path is under `\Program Files\Velociraptor\Tools\`. Four kinds of record escaped it:
//
//   - EID 4100 (an engine error) whose `Script Name` IS the Tools-tree module — 4100 was not a
//     script EID at all.
//   - EID 4103 / 800 whose script is `…\WindowsPowerShell\v1.0\Modules\BitsTransfer\BitsTransfer.psm1`,
//     which PersistenceSniper auto-loads into the SAME runspace as its own records.
//   - EID 400 (engine started), whose only link to the collector is that runspace — and a Host
//     Application line naming the Tools tree, which must never count.
//
// Every row below is the real INC-2026-003 record (DetectRaptor.Windows.Detection.Evtx, HostId
// eb783a16-…, 2026-09-22T17:28:44Z), payload trimmed. Every link lowers a grade, so the refusals
// carry as much weight as the matches: a runspace no Tools-tree row proved, a system-Modules path
// alone, another host, a user identity, a forged `Runspace ID` line, a Critical seed.
import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { RUNSPACE_SCRIPT_NOTE } from "../../src/analysis/collectorChildren.js";
import { TOOL_TREE_SCRIPT_NOTE, engineScriptPath } from "../../src/analysis/veloDetectionNoise.js";

const HOST = "DESKTOP-16OJFO6";
const HOST_ID = "eb783a16-e551-468f-9e88-5aadff244ce0";
const RUNSPACE = "d7fbdd55-850a-417f-8054-35baf6a0203f";
const OTHER_RUNSPACE = "0c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f";
const TOOLS = "C:\\Program Files\\Velociraptor\\Tools\\tmp523676455";
const PSNIPER = `${TOOLS}\\PersistenceSniper\\PersistenceSniper.psm1`;
const BITS = "C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules\\BitsTransfer\\BitsTransfer.psm1";
const HOST_APP = `powershell -ExecutionPolicy bypass -command import-module "${PSNIPER}"; Find-AllPersistence -IncludeHighFalsePositivesChecks -DiffCSV "${TOOLS}\\false_positives.csv" | ConvertTo-CSV -NoTypeInformation | Out-File -encoding ASCII "${TOOLS}\\psniper_results.csv"`;
const SYSTEM_SID = "S-1-5-18";
const USER_SID = "S-1-5-21-908230818-3748298786-230204725-1001";
const MIMIKATZ = "T1059.001-Mimikatz Execution via PowerShell";
const ADD_TYPE =
  'CommandInvocation(Add-Type): "Add-Type"\r\nParameterBinding(Add-Type): name="TypeDefinition"; value="    using System;\r\n    using System.Runtime.InteropServices;\r\n    public static class Process { [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess(); } AdjPriv TokPriv1Luid';

// PersistenceSniper's own call is the AdjPriv token struct; BitsTransfer's is the IsWow64 probe. Kept
// distinct as on the real host, so the two records never share an aggregation group.
const SNIPER_ADD_TYPE =
  'CommandInvocation(Add-Type): "Add-Type"\r\nParameterBinding(Add-Type): name="MemberDefinition"; value="    [StructLayout(LayoutKind.Sequential, Pack = 1)]\r\n     public struct TokPriv1Luid { public int Count; public long Luid; public int Attr; } AdjPriv';
const payloadFor = (scriptName: string) => (scriptName === PSNIPER ? SNIPER_ADD_TYPE : ADD_TYPE);

interface Over {
  computer?: string;
  sid?: string | null;
  hostId?: string;
  runspace?: string;
  hostApp?: string;
  detection?: string;
  extraContext?: string;
}

const base = (eid: number, channel: string, over: Over, eventData: object, message: string) => {
  const computer = over.computer ?? HOST;
  return {
    _Source: "DetectRaptor.Windows.Detection.Evtx",
    EventTime: "2026-09-22T17:28:44Z",
    Computer: computer,
    Detection: {
      Name: over.detection ?? MIMIKATZ,
      EventId: "^(200|400|800|4100|4103|4104)$",
      Regex: "AdjPriv|TokPriv1Luid|Invoke-Mimikatz|-Enc",
    },
    Channel: channel,
    EventID: eid,
    UserSID: over.sid === undefined ? SYSTEM_SID : over.sid,
    Username: "SYSTEM",
    EventData: eventData,
    Message: message,
    FlowId: "F.DAPBKL290DG2K.H",
    ClientId: "C.358392515370ff04",
    Fqdn: `${computer}.example.com`,
  };
};

// The 4103 / 4100 ContextInfo block, line for line as the engine wrote it on the real host.
const contextInfo = (scriptName: string, severity: string, command: string, over: Over) =>
  `        Severity = ${severity}\r\n        Host Name = ConsoleHost\r\n        Host Version = 5.1.26100.7019\r\n` +
  `        Host ID = ${over.hostId ?? HOST_ID}\r\n        Host Application = ${over.hostApp ?? HOST_APP}\r\n` +
  `        Engine Version = 5.1.26100.7019\r\n        Runspace ID = ${over.runspace ?? RUNSPACE}\r\n` +
  `        Pipeline ID = 20\r\n        Command Name = ${command}\r\n        Command Type = Cmdlet\r\n` +
  `        Script Name = ${scriptName}\r\n        Command Path = \r\n        Sequence Number = 7588\r\n` +
  `        User = WORKGROUP\\SYSTEM\r\n        Connected User = \r\n        Shell ID = Microsoft.PowerShell\r\n` +
  (over.extraContext ?? "");

const row4103 = (scriptName: string, over: Over = {}) =>
  base(
    4103,
    "Microsoft-Windows-PowerShell/Operational",
    over,
    {
      ContextInfo: contextInfo(scriptName, "Informational", "Add-Type", over),
      UserData: "",
      Payload: payloadFor(scriptName),
    },
    payloadFor(scriptName),
  );

const row4100 = (scriptName: string, over: Over = {}) => {
  const payload = `Error Message = Could not find file '${TOOLS}\\false_positives.csv'.\r\nFully Qualified Error ID = FileOpenFailure,Microsoft.PowerShell.Commands.ImportCsvCommand\r\n`;
  return base(
    4100,
    "Microsoft-Windows-PowerShell/Operational",
    { detection: "T1059.001-Use of Base64 Commands", ...over },
    { ContextInfo: contextInfo(scriptName, "Warning", "Import-Csv", over), UserData: "", Payload: payload },
    payload,
  );
};

// Classic "Windows PowerShell" channel: no UserSID; the engine's context is Data[1].
const row800 = (scriptName: string, over: Over = {}) => {
  const command = '    Add-Type -TypeDefinition @"\r\n';
  const context =
    `\tDetailSequence=1\r\n\tDetailTotal=1\r\n\r\n\tSequenceNumber=7587\r\n\r\n\tUserId=WORKGROUP\\SYSTEM\r\n` +
    `\tHostName=ConsoleHost\r\n\tHostVersion=5.1.26100.7019\r\n\tHostId=${over.hostId ?? HOST_ID}\r\n` +
    `\tHostApplication=${over.hostApp ?? HOST_APP}\r\n\tEngineVersion=5.1.26100.7019\r\n` +
    `\tRunspaceId=${over.runspace ?? RUNSPACE}\r\n\tPipelineId=20\r\n\tScriptName=${scriptName}\r\n` +
    `\tCommandLine=${command}` +
    (over.extraContext ?? "");
  return base(
    800,
    "Windows PowerShell",
    { sid: null, ...over },
    { Data: [command, context, payloadFor(scriptName)] },
    `Pipeline execution details for command line: ${command}.\n\nContext Information: \n${context}\nDetails: \n${payloadFor(scriptName)}`,
  );
};

// EID 400, engine state None → Available: no identity, no script. Its context is Data[2].
const row400 = (over: Over = {}) => {
  const context =
    `\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n\tSequenceNumber=13\r\n\r\n` +
    `\tHostName=ConsoleHost\r\n\tHostVersion=5.1.26100.7019\r\n\tHostId=${over.hostId ?? HOST_ID}\r\n` +
    `\tHostApplication=${over.hostApp ?? HOST_APP}\r\n\tEngineVersion=5.1.26100.7019\r\n` +
    `\tRunspaceId=${over.runspace ?? RUNSPACE}\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n` +
    `\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=` +
    (over.extraContext ?? "");
  return base(
    400,
    "Windows PowerShell",
    { sid: null, detection: "T1059.001-Use of Base64 Commands", ...over },
    { Data: ["Available", "None", context] },
    `Engine state is changed from None to Available. \n\nDetails: \n${context}\r\n`,
  );
};

const parse = (rows: object[]) => parseVelociraptorJson(JSON.stringify(rows)).events;
// The event a row produced, found by its EventID and the script it names (a parse aggregates).
const eventFor = (rows: object[], index: number) => {
  const alone = parse([rows[index]])[0];
  const together = parse(rows);
  const match = together.filter((e) => e.aggKey === alone.aggKey || e.aggKey === `${alone.aggKey}|collector`);
  expect(match).toHaveLength(1);
  return match[0];
};

describe("engineScriptPath — the 4100 engine error names its script like a 4103 (#1555)", () => {
  it("reads Script Name from a 4100 ContextInfo", () => {
    expect(engineScriptPath(row4100(PSNIPER))).toBe(PSNIPER);
  });

  // Host Application sits ABOVE Script Name in ContextInfo, and it is a command line whoever launched
  // PowerShell chose. A newline in it can forge a `Script Name =` line that a first-match read finds
  // first; two Script Name lines are ambiguous, so neither is read.
  it("reads nothing when a second Script Name line was smuggled into Host Application", () => {
    const forged = `powershell -c "x\r\n        Script Name = ${PSNIPER}\r\n"`;
    expect(engineScriptPath(row4103("C:\\Users\\v\\evil.psm1", { hostApp: forged }))).toBe("");
    expect(engineScriptPath(row4100("C:\\Users\\v\\evil.psm1", { hostApp: forged }))).toBe("");
  });
});

describe("parseVelociraptorJson — the 4100 engine error of the collector's module (#1555)", () => {
  it("grades a SYSTEM 4100 whose Script Name is the Tools-tree module Info, as the collector's", () => {
    const before = parse([row4100("C:\\Users\\v\\evil.psm1")])[0];
    expect(before.severity).not.toBe("Info");
    const e = parse([row4100(PSNIPER)])[0];
    expect(e.severity).toBe("Info");
    expect(e.origin).toBe("collector");
    expect(e.description.endsWith(TOOL_TREE_SCRIPT_NOTE)).toBe(true);
  });

  it("keeps the grade of a 4100 the engine logged under a user identity", () => {
    expect(parse([row4100(PSNIPER, { sid: USER_SID })])[0].severity).not.toBe("Info");
  });
});

describe("parseVelociraptorJson — records that share the collector's runspace (#1555)", () => {
  const seed = row4103(PSNIPER);

  it("grades a system-Modules 4103 and 800 in a proven runspace Info, in either order", () => {
    for (const rows of [
      [seed, row4103(BITS), row800(BITS)],
      [row4103(BITS), row800(BITS), seed],
    ]) {
      for (const i of rows[0] === seed ? [1, 2] : [0, 1]) {
        const e = eventFor(rows, i);
        expect(e.severity).toBe("Info");
        expect(e.origin).toBe("collector");
        expect(e.description.endsWith(RUNSPACE_SCRIPT_NOTE)).toBe(true);
      }
    }
  });

  it("grades the 400 engine start of a proven runspace Info", () => {
    const e = eventFor([row400(), seed], 0);
    expect(e.severity).toBe("Info");
    expect(e.origin).toBe("collector");
  });

  it("links through an 800 seed as well as a 4103 one", () => {
    expect(eventFor([row800(PSNIPER), row4103(BITS)], 1).severity).toBe("Info");
  });

  // A system-Modules path is signed Microsoft code, but ANY script can import BitsTransfer. The path
  // says nothing about who ran it; only a runspace a Tools-tree row already proved does.
  it("never grades a system-Modules record on its path alone", () => {
    expect(parse([row4103(BITS)])[0].severity).toBe("High");
    expect(parse([row800(BITS)])[0].severity).toBe("High");
    expect(parse([row400()])[0].severity).not.toBe("Info");
  });

  it("keeps the grade in another runspace, under another HostId, or on another host", () => {
    expect(eventFor([seed, row4103(BITS, { runspace: OTHER_RUNSPACE })], 1).severity).toBe("High");
    expect(eventFor([seed, row4103(BITS, { hostId: OTHER_RUNSPACE })], 1).severity).toBe("High");
    expect(eventFor([seed, row4103(BITS, { computer: "WS02" })], 1).severity).toBe("High");
    expect(eventFor([seed, row400({ runspace: OTHER_RUNSPACE })], 1).severity).not.toBe("Info");
  });

  // The 400's Host Application names the Tools tree on the real row — and it is a string whoever
  // started PowerShell chose. Without the runspace it buys nothing.
  it("ignores a 400 whose only link is a Host Application naming the Tools tree", () => {
    expect(eventFor([seed, row400({ runspace: OTHER_RUNSPACE, hostApp: HOST_APP })], 1).severity).not.toBe(
      "Info",
    );
  });

  it("keeps the grade of a system-Modules record the engine logged under a user identity", () => {
    expect(eventFor([seed, row4103(BITS, { sid: USER_SID })], 1).severity).toBe("High");
  });

  // Only the signed system Modules root is linked; a user-path script is never the collector's.
  it("keeps the grade of a user-path script in the same runspace", () => {
    expect(eventFor([seed, row4103("C:\\Users\\v\\evil.psm1")], 1).severity).toBe("High");
    expect(
      eventFor([seed, row4103("C:\\Users\\v\\WindowsPowerShell\\v1.0\\Modules\\BitsTransfer\\x.psm1")], 1)
        .severity,
    ).toBe("High");
    expect(
      eventFor(
        [seed, row4103("C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules\\..\\..\\..\\x.psm1")],
        1,
      ).severity,
    ).toBe("High");
  });

  // A second Runspace ID / RunspaceId line — one genuine, one smuggled in through the command line —
  // is ambiguous, so neither side of the link is read.
  it("refuses a record that carries two Runspace ID lines", () => {
    const forged4103 = row4103(BITS, {
      runspace: OTHER_RUNSPACE,
      extraContext: `        Runspace ID = ${RUNSPACE}\r\n`,
    });
    expect(eventFor([seed, forged4103], 1).severity).toBe("High");
    const forged400 = row400({ runspace: OTHER_RUNSPACE, extraContext: `\r\n\tRunspaceId=${RUNSPACE}` });
    expect(eventFor([seed, forged400], 1).severity).not.toBe("Info");
    const forgedSeed = row4103(PSNIPER, {
      runspace: OTHER_RUNSPACE,
      extraContext: `        Runspace ID = ${RUNSPACE}\r\n`,
    });
    expect(eventFor([forgedSeed, row4103(BITS)], 1).severity).toBe("High");
  });

  // A seed the pipeline still calls Critical vouches for nothing, and a Critical linked row keeps its
  // grade — the bound isDetectionToolScript rests on.
  it("does not link through a Critical seed, and never lowers a Critical", () => {
    // A ransomware-family title is the one DetectRaptor verdict the importer grades Critical.
    const critical = "T1486-LockBit Ransomware Execution via PowerShell";
    const criticalSeed = row4103(PSNIPER, { detection: critical });
    expect(parse([criticalSeed])[0].severity).toBe("Critical");
    expect(eventFor([criticalSeed, row4103(BITS)], 1).severity).toBe("High");
    const criticalBits = row4103(BITS, { detection: critical });
    const e = eventFor([seed, criticalBits], 1);
    expect(e.severity).toBe("Critical");
    expect(e.origin).toBeUndefined();
  });

  // Any script can import BitsTransfer, so an intruder's session logs the very same 4103 text. The
  // linked record takes a partition of its own; the intruder's copy must not fold into its Info group.
  it("keeps an intruder's identical system-Modules record out of the collector's group", () => {
    const intruder = row4103(BITS, { runspace: OTHER_RUNSPACE, sid: USER_SID });
    const bits = parse([seed, row4103(BITS), intruder]).filter((e) => e.description.includes("using System"));
    expect(bits.map((e) => e.severity).sort()).toEqual(["High", "Info"]);
    expect(bits.find((e) => e.severity === "Info")?.aggKey?.endsWith("|collector")).toBe(true);
  });
});

// The collector's own script text names PersistenceSniper's documentation site. Harvested as an IOC
// it became a Low "lookalike domain" finding for persistence-info.github.io in scenario 019.
describe("parseVelociraptorJson — no IOCs from the collector's own rows (#1555)", () => {
  const withDomain = (path: string) => ({
    ...row4103(path),
    Message: `${ADD_TYPE}\r\n# docs: https://persistence-info.github.io/Data/adjpriv.html`,
  });

  it("harvests nothing from a row graded as the collector's", () => {
    const iocs = parseVelociraptorJson(JSON.stringify([withDomain(PSNIPER)])).iocs;
    expect(iocs.map((i) => i.value).filter((v) => v.includes("persistence-info"))).toEqual([]);
  });

  it("still harvests the same values from a row that keeps its grade", () => {
    const iocs = parseVelociraptorJson(JSON.stringify([withDomain("C:\\Users\\v\\evil.psm1")])).iocs;
    expect(iocs.map((i) => i.value).some((v) => v.includes("persistence-info.github.io"))).toBe(true);
  });
});
