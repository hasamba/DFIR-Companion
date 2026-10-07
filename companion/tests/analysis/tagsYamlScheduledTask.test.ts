import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger } from "../../src/analysis/tagger.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// `win_scheduled_task` read a bare '4698' / '4702' in the message, so a GUID or hash holding those
// digits graded a process launch as a scheduled task (persistence). The message side now needs the
// id behind its key (`EventID: 4698`, `EID 4702`).
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

function ruleIds(fields: { message?: string; description?: string }): string[] {
  const event = {
    id: "e1",
    ...fields,
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: [],
  } as unknown as ForensicEvent;
  return runTagger([event], RULES).perEvent[0]?.ruleIds ?? [];
}

const MSIEXEC_UNINSTALL_MESSAGE = [
  "Process Create:",
  "UtcTime: 2017-03-20 11:11:32.040",
  "ProcessId: 6024",
  "Image: C:\\Windows\\SysWOW64\\msiexec.exe",
  'CommandLine: "C:\\Windows\\system32\\msiexec.exe"  /q /X{11111111-2222-3333-4444-2846987CA9A0}',
  "User: NT AUTHORITY\\SYSTEM",
  "Hashes: SHA1=0123456789ABCDEF0123456789ABCDEF01234567," +
    "MD5=00112233445566778899AABBCCDDEEFF," +
    "SHA256=EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF11111111111111112222222222222222",
  "ParentImage: C:\\Program Files (x86)\\Common Files\\McAfee\\Installer\\9.0.8010.0\\McInst.exe",
  'ParentCommandLine: "c:\\program files (x86)\\common files\\mcafee\\installer\\9.0.8010.0\\mcinst.exe" /install bcaredistbkupd.inf',
].join("\n");

describe("win_scheduled_task", () => {
  it("does not match a process launch whose GUID contains 4698", () => {
    expect(
      ruleIds({
        message: MSIEXEC_UNINSTALL_MESSAGE,
        description:
          'Sysmon Process create (EID 1) - Image=C:\\Windows\\SysWOW64\\msiexec.exe - CommandLine="C:\\Windows\\system32\\msiexec.exe" /q /X{11111111-2222-3333-4444-2846987CA9A0}',
      }),
    ).not.toContain("win_scheduled_task");
  });

  it("does not match a bare 4702 inside a path or hash", () => {
    expect(
      ruleIds({ message: "Image: C:\\Program Files (x86)\\McAfee\\Temp\\qxz4702\\McCertUpd.exe" }),
    ).not.toContain("win_scheduled_task");
  });

  it("matches a task event named by its description id", () => {
    expect(
      ruleIds({ description: "Windows Security Task created (EID 4698) - TaskName=\\Example" }),
    ).toContain("win_scheduled_task");
    expect(
      ruleIds({ description: "Windows Task Scheduler Task registered (EID 106 TaskScheduler)" }),
    ).toContain("win_scheduled_task");
  });

  it("matches a task event named by an EventID key in the message", () => {
    expect(ruleIds({ message: "EventID: 4698\nTaskName: \\Example" })).toContain("win_scheduled_task");
    expect(ruleIds({ message: '{"event_id": 4702}' })).toContain("win_scheduled_task");
  });

  it("matches the Windows task-created text", () => {
    expect(ruleIds({ message: "A scheduled task was created." })).toContain("win_scheduled_task");
  });
});
