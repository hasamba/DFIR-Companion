import { describe, it, expect } from "vitest";
import { extractAccounts } from "../../src/analysis/assetGraph.js";

// The DOMAIN\user regex guards against adjacent path separators, but a path SEGMENT CONTAINING A
// SPACE resets that guard: in "…\Explorer\Shell Folders\Common Startup" the match starts after the
// space, so "Folders\Common" is emitted as if it were an account. Every string below is copied
// verbatim from real case timelines (fairhaven-rdp-gt / veridia-breach), where this manufactured
// enough fake shared accounts to chain unrelated hosts into confident-looking lateral paths.
describe("extractAccounts — path segments containing a space are not accounts", () => {
  const PATH_NOISE: ReadonlyArray<[string, string]> = [
    ["Registry set: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common Startup", "Folders\\Common"],
    ["ImageLoaded=C:\\Program Files\\Windows Defender\\MpOAV.dll", "Files\\Windows"],
    ["Registry set: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\MigrateProxy = DWORD", "Settings\\MigrateProxy"],
    ["Registry set: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\ClearPageFileAtShutdown", "Manager\\Memory"],
    ["Registry set: HKU\\S-1-5-21-1013\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\File MRU\\Item 9", "MRU\\Item"],
    ["Registry set: HKCU\\Software\\Microsoft\\Office\\16.0\\Word\\Reading Locations\\Document 12\\Datetime", "Locations\\Document"],
    ["Sysmon Process create (EID 1) - Image=C:\\Program Files\\Google\\Drive File Stream\\97.0.1.0\\GoogleDriveFS.exe", "Stream\\97.0.1"],
    ["NewProcessName=C:\\Program Files\\Palo Alto Networks\\GlobalProtect\\PanGPS.exe", "Files\\Palo"],
    ["TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring", "Defender\\Real-Time"],
    ["Process created: \"C:\\Program Files\\Cisco Spark\\Webex.exe\" --autostart", "Files\\Cisco"],
  ];

  for (const [description, bogus] of PATH_NOISE) {
    it(`does not read "${bogus}" out of a path`, () => {
      expect(extractAccounts(description)).not.toContain(bogus);
    });
  }
});

describe("extractAccounts — registry hive roots are not accounts", () => {
  // HKU\<SID> is a registry path, not a logon. Worse, the user half is capped at 20 chars, so the
  // SID's RID is truncated away and DIFFERENT users on different hosts collapse into one identical
  // "account" — which then looks like a single principal roaming the whole estate.
  it("does not read a hive\\SID pair out of a registry TargetObject", () => {
    const d = "Image=C:\\Windows\\System32\\RuntimeBroker.exe - TargetObject=HKU\\S-1-5-21-1474774169-3792502490-1226900992-1001\\Software";
    expect(extractAccounts(d).some((a) => a.startsWith("HKU\\"))).toBe(false);
  });

  for (const hive of ["HKU", "HKLM", "HKCU", "HKCR", "HKCC"]) {
    it(`does not treat ${hive}\\… as an account`, () => {
      expect(extractAccounts(`Registry set: ${hive}\\Software`).some((a) => a.startsWith(`${hive}\\`))).toBe(false);
    });
  }
});

describe("extractAccounts — real accounts still extracted", () => {
  // Verbatim shapes from the same timelines. Account references are preceded by prose, never by a
  // path token — that is exactly what separates them from the noise above.
  it("extracts a user account from a 4624 logon line", () => {
    const d = "Windows Security Successful logon (EID 4624) - FAIRHAVEN\\eleanor.voss, NT AUTHORITY\\SYSTEM - LogonType=3";
    const accts = extractAccounts(d);
    expect(accts).toContain("FAIRHAVEN\\eleanor.voss");
    expect(accts).toContain("NT AUTHORITY\\SYSTEM".replace("NT ", "")); // regex yields the truncated AUTHORITY\SYSTEM
  });

  it("extracts a machine account and a service account", () => {
    expect(extractAccounts("Successful logon (EID 4624) - FAIRHAVEN\\WS-HR-01$, LogonType=3")).toContain("FAIRHAVEN\\WS-HR-01$");
    expect(extractAccounts("Logon with explicit credentials (EID 4648) - FAIRHAVEN\\svc_sqlagent")).toContain("FAIRHAVEN\\svc_sqlagent");
  });

  it("extracts an account mentioned after a path elsewhere in the same description", () => {
    // The prose break (", " / " - ") between the path and the account must keep the account visible.
    const d = "Process created: C:\\Program Files\\Zip\\7z.exe - by CORP\\jdoe";
    expect(extractAccounts(d)).toContain("CORP\\jdoe");
  });

  it("still extracts a simple DOMAIN\\user with no path context at all", () => {
    expect(extractAccounts("logon by CORP\\jdoe")).toEqual(["CORP\\jdoe"]);
  });

  it("still extracts UPN accounts", () => {
    expect(extractAccounts("mail from eleanor.voss@fairhaven.gov")).toContain("eleanor.voss@fairhaven.gov");
  });
});
