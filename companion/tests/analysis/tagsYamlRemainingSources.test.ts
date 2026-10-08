import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { compileText } from "../../src/analysis/taggerStore.js";
import { runTagger, applyToForensicEvent } from "../../src/analysis/tagger.js";
import { parseSiemExport } from "../../src/analysis/siemImport.js";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { parseCloudTrail } from "../../src/analysis/awsImport.js";
import { parseCloudActivity } from "../../src/analysis/cloudActivityImport.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Two batches of rules ported tag-for-tag from public Timesketch rulesets:
//   • Windows registry persistence / blinding the built-in grader does not reach (the write itself,
//     not a command line) — the key renders in `description` as `TargetObject=…`
//   • the upstream Timesketch AWS CloudTrail + GCS rules — the eventName / methodName renders at the
//     head of `description`.
// These run the REAL importers over the SHIPPED ruleset, so a port that names a key or call the
// importer never emits cannot read as live while being dead.
const RULES = compileText(
  readFileSync(fileURLToPath(new URL("../../data/tags.yaml", import.meta.url)), "utf8"),
);

type Tagged = { severity: string; ruleIds: string[]; mitre: string[] };

function applyTag(mapped: Partial<ForensicEvent>): Tagged {
  const event = {
    ...mapped,
    id: "e1",
    relatedFindingIds: [],
    sourceScreenshots: [],
    mitreTechniques: mapped.mitreTechniques ?? [],
  } as unknown as ForensicEvent;
  const proposal = runTagger([event], RULES).perEvent[0];
  const after = proposal ? applyToForensicEvent(event, proposal) : event;
  return { severity: after.severity, ruleIds: proposal?.ruleIds ?? [], mitre: after.mitreTechniques ?? [] };
}

function windows(rec: Record<string, unknown>): Tagged {
  const mapped = parseSiemExport(JSON.stringify([{ "@timestamp": "2026-01-02T03:04:05Z", ...rec }]));
  return applyTag(mapped.events[0]);
}

function sysmon(eid: number, data: Record<string, string>, message?: string): Tagged {
  return windows({
    channel: "Microsoft-Windows-Sysmon/Operational",
    computer_name: "H1",
    event_id: eid,
    ...(message ? { message } : {}),
    event_data: data,
  });
}

// A Sysmon 13 value-set on a registry key.
function regSet(key: string, valueName: string, image = "C:\\Windows\\regedit.exe"): Tagged {
  return sysmon(
    13,
    {
      EventType: "SetValue",
      TargetObject: `${key}\\${valueName}`,
      Details: "C:\\Users\\Public\\payload.bin",
      Image: image,
    },
    `Registry value set:\nTargetObject: ${key}\\${valueName}`,
  );
}

// The OTHER registry-write shape: Security 4657 keeps the key in `path` and the value name as a
// separate rendered field — every rule must fire on this shape too, not just Sysmon's.
function reg4657(key: string, valueName: string): Tagged {
  return windows({
    channel: "Security",
    computer_name: "H1",
    event_id: 4657,
    message: "A registry value was modified.",
    event_data: {
      ObjectName: key,
      ObjectValueName: valueName,
      NewValue: "C:\\Users\\Public\\payload.bin",
    },
  });
}

describe("bundled data/tags.yaml — Windows registry persistence", () => {
  it("flags an IFEO debugger hijack High with T1546.012", () => {
    const r = regSet(
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
      "Debugger",
    );
    expect(r.ruleIds).toContain("win_ifeo_persistence");
    expect(r.severity).toBe("High");
    expect(r.mitre).toContain("T1546.012");
  });

  it("flags a SilentProcessExit write", () => {
    const r = regSet(
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\notepad.exe",
      "MonitorProcess",
    );
    expect(r.ruleIds).toContain("win_ifeo_persistence");
  });

  it("flags a Winlogon Shell hijack", () => {
    const r = regSet("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Shell");
    expect(r.ruleIds).toContain("win_logon_script");
    expect(r.mitre).toContain("T1547.004");
  });

  it("flags a service ServiceDll write Medium (T1543.003)", () => {
    const r = regSet("HKLM\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\Parameters", "ServiceDll");
    expect(r.ruleIds).toContain("win_service_imagepath_write");
    expect(r.mitre).toContain("T1543.003");
  });

  it("flags a Defender DisableAntiSpyware write High", () => {
    const r = regSet("HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableAntiSpyware");
    expect(r.ruleIds).toContain("win_defender_registry_tamper");
    expect(r.severity).toBe("High");
  });

  it("flags a windefend Start=4 registry disable", () => {
    const r = regSet("HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend", "Start");
    expect(r.ruleIds).toContain("win_defender_registry_tamper");
  });

  it("flags a COM CLSID InprocServer32 hijack", () => {
    const r = regSet(
      "HKLM\\SOFTWARE\\Classes\\CLSID\\{00000000-0000-0000-0000-000000000000}",
      "InprocServer32",
    );
    expect(r.ruleIds).toContain("win_com_hijack");
    expect(r.mitre).toContain("T1546.015");
  });

  it("flags an LSA Security Packages SSP write High", () => {
    const r = regSet("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "Security Packages");
    expect(r.ruleIds).toContain("win_security_support_provider");
    expect(r.mitre).toContain("T1547.005");
  });

  it("flags a BootExecute write High", () => {
    const r = regSet("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager", "BootExecute");
    expect(r.ruleIds).toContain("win_bootexecute");
    expect(r.mitre).toContain("T1547.006");
  });

  it("flags a RunAsPPL write Medium (direction not in the record)", () => {
    const r = regSet("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "RunAsPPL");
    expect(r.ruleIds).toContain("win_runasppl_write");
  });

  it("flags a sethc.exe overwrite in System32 High (sticky-keys backdoor)", () => {
    const r = sysmon(
      11,
      { TargetFilename: "C:\\Windows\\System32\\sethc.exe", Image: "C:\\Windows\\System32\\cmd.exe" },
      "File created: C:\\Windows\\System32\\sethc.exe",
    );
    expect(r.ruleIds).toContain("win_accessibility_backdoor");
    expect(r.severity).toBe("High");
  });

  it("flags a Startup-folder payload write", () => {
    const r = sysmon(
      11,
      {
        TargetFilename:
          "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe",
        Image: "C:\\Windows\\explorer.exe",
      },
      "File created",
    );
    expect(r.ruleIds).toContain("win_startup_folder_payload");
    expect(r.mitre).toContain("T1547.001");
  });

  it("flags a PowerShell profile .ps1 write", () => {
    const r = sysmon(
      11,
      {
        TargetFilename: "C:\\Users\\u\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
        Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      },
      "File created",
    );
    expect(r.ruleIds).toContain("win_ps_profile_persistence");
  });

  // ── the benign half ──
  it("leaves an ordinary non-service registry write alone", () => {
    const r = regSet("HKLM\\SOFTWARE\\Vendor\\App", "InstallDir");
    expect(r.ruleIds).not.toContain("win_service_imagepath_write");
    expect(r.ruleIds).not.toContain("win_ifeo_persistence");
    expect(r.ruleIds).not.toContain("win_defender_registry_tamper");
  });

  it("fires every registry rule on the Security 4657 shape too (key in path, value in ObjectValueName)", () => {
    const cases: [string, string, (t: Tagged) => boolean][] = [
      [
        "win_ifeo_persistence",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
        (t) => t.ruleIds.includes("win_ifeo_persistence"),
      ],
      [
        "win_service_imagepath_write",
        "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc",
        (t) => t.ruleIds.includes("win_service_imagepath_write"),
      ],
      [
        "win_security_support_provider",
        "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        (t) => t.ruleIds.includes("win_security_support_provider"),
      ],
      [
        "win_bootexecute",
        "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        (t) => t.ruleIds.includes("win_bootexecute"),
      ],
      [
        "win_defender_registry_tamper",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        (t) => t.ruleIds.includes("win_defender_registry_tamper"),
      ],
      [
        "win_terminal_server_write",
        "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
        (t) => t.ruleIds.includes("win_terminal_server_write"),
      ],
      [
        "win_runasppl_write",
        "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        (t) => t.ruleIds.includes("win_runasppl_write"),
      ],
    ];
    const values: Record<string, string> = {
      win_ifeo_persistence: "Debugger",
      win_service_imagepath_write: "ImagePath",
      win_security_support_provider: "Security Packages",
      win_bootexecute: "BootExecute",
      win_defender_registry_tamper: "DisableAntiSpyware",
      win_terminal_server_write: "fDenyTSConnections",
      win_runasppl_write: "RunAsPPL",
    };
    for (const [rule, key, assert] of cases) {
      expect(assert(reg4657(key, values[rule])), `${rule} on 4657`).toBe(true);
    }
  });

  // A file listing already sets `path`; only a CREATE/DELETE marker may grade it (#1666 hazard).
  it("does NOT grade a Velociraptor file listing of an existing sethc.exe", () => {
    const parsed = parseVelociraptorJson(
      JSON.stringify([{ OSPath: "C:\\Windows\\System32\\sethc.exe", Name: "sethc.exe" }]),
    );
    const r = applyTag(parsed.events[0]);
    expect(r.ruleIds).not.toContain("win_accessibility_backdoor");
    expect(r.ruleIds).not.toContain("win_startup_folder_payload");
  });

  it("does NOT grade an MFT listing of a Startup path", () => {
    const r = windows({
      channel: "Velociraptor",
      computer_name: "H1",
      event_id: 0,
      message: "MFT entry",
      event_data: {
        FullPath:
          "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\legit.exe",
      },
    });
    expect(r.ruleIds).not.toContain("win_startup_folder_payload");
  });
});

describe("bundled data/tags.yaml — Windows defense evasion / execution", () => {
  it("flags an AMSI bypass High", () => {
    const r = windows({
      channel: "Microsoft-Windows-Sysmon/Operational",
      computer_name: "H1",
      event_id: 1,
      message: "Process Create",
      event_data: {
        Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine:
          "powershell -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\"",
      },
    });
    expect(r.ruleIds).toContain("win_amsi_bypass");
    expect(r.severity).toBe("High");
  });

  it("flags a firewall disable command High", () => {
    const r = sysmon(1, {
      Image: "C:\\Windows\\System32\\netsh.exe",
      CommandLine: "netsh advfirewall set allprofiles state off",
    });
    expect(r.ruleIds).toContain("win_firewall_disable");
    expect(r.mitre).toContain("T1562.004");
  });

  it("flags an auditpol /clear High", () => {
    const r = sysmon(1, {
      Image: "C:\\Windows\\System32\\auditpol.exe",
      CommandLine: "auditpol /clear /y",
    });
    expect(r.ruleIds).toContain("win_audit_policy_tamper");
    expect(r.mitre).toContain("T1562.002");
  });

  it("flags a mofcomp / .mof compile", () => {
    const r = sysmon(1, {
      Image: "C:\\Windows\\System32\\wbem\\mofcomp.exe",
      CommandLine: "mofcomp C:\\Users\\Public\\evil.mof",
    });
    expect(r.ruleIds).toContain("win_wmi_mof");
  });

  it("flags a netsh portproxy tunnel", () => {
    const r = sysmon(1, {
      Image: "C:\\Windows\\System32\\netsh.exe",
      CommandLine: "netsh interface portproxy add v4tov4 listenport=3389 connectaddress=10.0.0.9",
    });
    expect(r.ruleIds).toContain("win_rdp_portproxy");
  });

  it("flags a Terminal Server fDenyTSConnections write Low (direction not in the record)", () => {
    const r = regSet("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "fDenyTSConnections");
    expect(r.ruleIds).toContain("win_terminal_server_write");
    expect(r.severity).toBe("Low");
  });

  it("leaves a routine `netsh interface ip show config` alone", () => {
    const r = sysmon(1, {
      Image: "C:\\Windows\\System32\\netsh.exe",
      CommandLine: "netsh interface ip show config",
    });
    expect(r.ruleIds).not.toContain("win_rdp_portproxy");
    expect(r.ruleIds).not.toContain("win_firewall_disable");
  });
});

// ─────────────────────────── Timesketch AWS CloudTrail / GCS parity ───────────────────────────
const aws = (eventName: string, eventSource = "ec2.amazonaws.com"): Tagged => {
  const r = parseCloudTrail(
    JSON.stringify({
      Records: [
        {
          eventTime: "2023-06-01T10:00:00Z",
          eventSource,
          eventName,
          awsRegion: "us-east-1",
          sourceIPAddress: "203.0.113.10",
          readOnly: false,
          userIdentity: {
            type: "IAMUser",
            userName: "bob",
            arn: "arn:aws:iam::123:user/bob",
            accountId: "123",
          },
        },
      ],
    }),
  );
  return applyTag(r.events[0]);
};

const gcp = (methodName: string, serviceName: string, serviceData?: unknown): Tagged => {
  const r = parseCloudActivity(
    JSON.stringify([
      {
        protoPayload: {
          methodName,
          serviceName,
          authenticationInfo: { principalEmail: "a@v.com" },
          resourceName: "projects/p/buckets/b",
          ...(serviceData ? { serviceData } : {}),
        },
        insertId: "1",
        timestamp: "2023-06-01T10:00:00Z",
      },
    ]),
  );
  return applyTag(r.events[0]);
};

describe("bundled data/tags.yaml — Timesketch AWS/GCS parity", () => {
  it("tags ConsoleLogin and GetCallerIdentity", () => {
    expect(aws("ConsoleLogin", "signin.amazonaws.com").ruleIds).toContain("ts_aws_console_login");
    expect(aws("GetCallerIdentity", "iam.amazonaws.com").ruleIds).toContain("ts_aws_get_caller_identity");
  });

  it("tags IAM persistence calls", () => {
    expect(aws("CreateAccessKey", "iam.amazonaws.com").ruleIds).toContain("ts_aws_iam_persistence");
    expect(aws("AttachUserPolicy", "iam.amazonaws.com").ruleIds).toContain("ts_aws_iam_persistence");
  });

  it("tags Identity Center calls", () => {
    expect(aws("StartSSO", "sso.amazonaws.com").ruleIds).toContain("ts_aws_identity_center");
    expect(aws("CreatePermissionSet", "sso.amazonaws.com").ruleIds).toContain("ts_aws_identity_center");
  });

  it("tags NetworkChanged families (SG / NACL / RouteTable / VPC / GW)", () => {
    expect(aws("AuthorizeSecurityGroupIngress").ruleIds).toContain("ts_aws_security_group_changed");
    expect(aws("CreateNetworkAcl").ruleIds).toContain("ts_aws_network_acl_changed");
    expect(aws("CreateRouteTable").ruleIds).toContain("ts_aws_route_table_changed");
    expect(aws("CreateVpc").ruleIds).toContain("ts_aws_vpc_changed");
    expect(aws("AttachInternetGateway").ruleIds).toContain("ts_aws_gateway_changed");
  });

  it("tags a GCS bucket create", () => {
    expect(gcp("storage.buckets.create", "storage.googleapis.com").ruleIds).toContain(
      "ts_gcp_bucket_created",
    );
  });

  it("splits setIamPermissions into add / remove / world-readable from the rendered delta", () => {
    const delta = (action: string, member: string) => ({
      policyDelta: {
        bindingDeltas: [{ action, role: "roles/storage.objectViewer", member }],
      },
    });
    expect(
      gcp("storage.setIamPermissions", "storage.googleapis.com", delta("ADD", "user:x@evil.com")).ruleIds,
    ).toContain("ts_gcp_bucket_permission_added");
    expect(
      gcp("storage.setIamPermissions", "storage.googleapis.com", delta("REMOVE", "user:x@evil.com")).ruleIds,
    ).toContain("ts_gcp_bucket_permission_removed");
    const world = gcp("storage.setIamPermissions", "storage.googleapis.com", delta("ADD", "allUsers"));
    expect(world.ruleIds).toContain("ts_gcp_bucket_world_added");
  });

  it("does not tag an unrelated AWS call", () => {
    const r = aws("DescribeInstances");
    expect(r.ruleIds).not.toContain("ts_aws_iam_persistence");
    expect(r.ruleIds).not.toContain("ts_aws_console_login");
  });
});
