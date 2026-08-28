import { describe, it, expect } from "vitest";
import { parseVelociraptorJson } from "../../src/analysis/velociraptorImport.js";
import { buildLoginGraph } from "../../src/analysis/loginGraph.js";
import type { ForensicEvent } from "../../src/analysis/stateTypes.js";

// Windows.EventLogs.CondensedAccountUsage rows, in the artifact's real column shape. It writes "-"
// for every field an event did not carry, which is why the mapper cannot treat a present column as
// a present value.
function usageRow(overrides: object = {}): object {
  return {
    _Source: "Windows.EventLogs.CondensedAccountUsage",
    EventTime: "2026-08-23T17:10:15Z",
    Computer: "DESKTOP-LAB01",
    EventID: 4624,
    Description: "ACCOUNT_LOGGED_ON",
    DomainName: "DESKTOP-LAB01",
    UserName: "labuser",
    LogonId: 614894,
    CredentialsUsedFor4648: "-",
    LogonType: 2,
    LogonTypeDescription: "INTERACTIVE_LOGON",
    AuthenticationPackageName: "Negotiate",
    IpAddress: "127.0.0.1",
    ClientName: "-",
    ...overrides,
  };
}

describe("condensed account-usage rows name the account, not just the verb", () => {
  it("renders the account, logon type and source instead of the bare artifact verb", () => {
    const e = parseVelociraptorJson(JSON.stringify([usageRow()])).events[0];
    expect(e.description).toContain("Successful logon (EID 4624)");
    expect(e.description).toContain("DESKTOP-LAB01\\labuser");
    expect(e.description).toContain("LogonType=2");
    expect(e.description).toContain("IpAddress=127.0.0.1");
    expect(e.description).toContain("[Interactive]");
    expect(e.description).not.toContain("ACCOUNT_LOGGED_ON");
  });

  // The defect that made this mapper necessary: the generic mapper's agg key was (artifact, host,
  // verb), so every logon on a host — whoever made it, however — folded into one event.
  it("keeps two different accounts on one host as two events", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([usageRow(), usageRow({ UserName: "Administrator", LogonId: 1 })]),
    );
    expect(r.events).toHaveLength(2);
  });

  it("keeps the same account's interactive and RDP logons as two events", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        usageRow(),
        usageRow({ LogonType: 10, LogonTypeDescription: "REMOTE_INTERACTIVE_LOGON", IpAddress: "10.1.1.9" }),
      ]),
    );
    expect(r.events).toHaveLength(2);
  });

  it("still folds genuine repeats of the same logon into one counted event", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([
        usageRow({ EventTime: "2026-08-23T17:10:15Z", LogonId: 1 }),
        usageRow({ EventTime: "2026-08-23T17:17:23Z", LogonId: 2 }),
        usageRow({ EventTime: "2026-08-23T17:28:31Z", LogonId: 3 }),
      ]),
    );
    expect(r.events).toHaveLength(1);
    expect(r.events[0].count).toBe(3);
  });

  // The description renders the authentication package, so the key must carry it: folding an NTLM
  // logon into a Negotiate one would print the surviving row's package over every occurrence.
  it("keeps NTLM and Negotiate logons of the same account as two events", () => {
    const r = parseVelociraptorJson(
      JSON.stringify([usageRow(), usageRow({ AuthenticationPackageName: "NTLM" })]),
    );
    expect(r.events).toHaveLength(2);
    expect(r.events.some((e) => e.description.includes("AuthenticationPackage=NTLM"))).toBe(true);
    expect(r.events.some((e) => e.description.includes("AuthenticationPackage=Negotiate"))).toBe(true);
  });

  // LogonId is unique per session and is therefore not in the agg key. Printing one member's session
  // id on an event that folds three would state as fact about all three what is true of one.
  it("does not print a session id on a folded event", () => {
    const r = parseVelociraptorJson(JSON.stringify([usageRow({ LogonId: 1 }), usageRow({ LogonId: 2 })]));
    expect(r.events[0].description).not.toContain("LogonId=");
  });
});

describe("condensed account-usage severity", () => {
  it("grades an ordinary interactive logon Low, with no technique", () => {
    const e = parseVelociraptorJson(JSON.stringify([usageRow()])).events[0];
    expect(e.severity).toBe("Low");
    expect(e.mitreTechniques ?? []).toHaveLength(0);
  });

  it("escalates an RDP logon from a public address", () => {
    const e = parseVelociraptorJson(JSON.stringify([usageRow({ LogonType: 10, IpAddress: "203.0.113.9" })]))
      .events[0];
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1021.001");
  });

  // Windows raises 4648 on every boot as the local session starts: the machine account presents
  // credentials for the font-driver and window-manager session principals. Grading those Medium —
  // which the shared per-EID table does for a PARSED 4648, where the subject process and target
  // server justify it — buries the one row that matters under the six that never do.
  it("floors a machine account's explicit-credential logon to Info", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        usageRow({
          EventID: 4648,
          Description: "LOGON_ATTEMPT_EXPLICIT_CREDENTIALS",
          DomainName: "WORKGROUP",
          UserName: "WIN-LAB02$",
          CredentialsUsedFor4648: "Font Driver Host\\UMFD-0",
          LogonType: "-",
          AuthenticationPackageName: "-",
          IpAddress: "-",
        }),
      ]),
    ).events[0];
    expect(e.severity).toBe("Info");
    expect(e.mitreTechniques ?? []).toHaveLength(0);
  });

  // The floor is scoped to 4648. The same machine account failing to authenticate is evidence in its
  // own right, and dropping it to Info would hide it from the forensic severity gate.
  it("does not floor a machine account's FAILED logon — that is evidence", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        usageRow({
          EventID: 4625,
          Description: "ACCOUNT_FAILED_TO_LOG_ON",
          DomainName: "CORP",
          UserName: "WIN-LAB02$",
          LogonType: 3,
          IpAddress: "10.9.9.9",
        }),
      ]),
    ).events[0];
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1110");
  });

  it("keeps a real user's explicit-credential logon at the table's Medium, naming the target", () => {
    const e = parseVelociraptorJson(
      JSON.stringify([
        usageRow({
          EventID: 4648,
          Description: "LOGON_ATTEMPT_EXPLICIT_CREDENTIALS",
          DomainName: "CORP",
          UserName: "jdoe",
          CredentialsUsedFor4648: "CORP\\svc-backup",
          LogonType: "-",
          IpAddress: "10.4.4.4",
        }),
      ]),
    ).events[0];
    expect(e.severity).toBe("Medium");
    expect(e.mitreTechniques).toContain("T1078");
    expect(e.description).toContain("TargetAccount=CORP\\svc-backup");
  });
});

// The mapper renders the same key=value grammar a parsed 4624 uses precisely so these rows reach the
// Login Graph through canonicalEvent's legacy upgrader, rather than sitting outside it.
describe("condensed account-usage rows reach the Login Graph", () => {
  it("produces an account → host edge with the decoded logon type", () => {
    const r = parseVelociraptorJson(JSON.stringify([usageRow({ LogonType: 10, IpAddress: "10.1.1.9" })]));
    const graph = buildLoginGraph(r.events as unknown as ForensicEvent[]);
    const edge = graph.edges.find((x) => x.logonType === "RemoteInteractive/RDP");
    expect(edge).toBeDefined();
    expect(edge?.outcome).toBe("success");
    expect(graph.nodes.some((n) => n.name.toLowerCase().includes("labuser"))).toBe(true);
  });
});
