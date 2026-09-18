import { describe, expect, it } from "vitest";
import { winRoleBlocks } from "../../src/analysis/winAccountRoles.js";

// #930 item 6: the account a Windows record establishes as ACTING, the initiator when it differs,
// the acting SID, and the typed Kerberos ticket request — read from named fields only.

const f = (ed: Record<string, string>) => (k: string) => ed[k] ?? "";

describe("winRoleBlocks — who acted, who initiated", () => {
  it("4624: the logged-on account (Target) acts; the SID rides on account.id", () => {
    const b = winRoleBlocks(
      4624,
      false,
      f({
        TargetDomainName: "CORP",
        TargetUserName: "svc_sql",
        TargetUserSid: "S-1-5-21-1-2-3-1105",
        SubjectUserName: "-",
      }),
    );
    expect(b.actor).toEqual({ kind: "account", name: "CORP\\svc_sql", domain: "CORP" });
    expect(b.account).toEqual({ id: "S-1-5-21-1-2-3-1105", name: "CORP\\svc_sql", domain: "CORP" });
    expect(b.subject).toBeUndefined();
    expect(b.event).toBeUndefined();
  });
  it("4648: the credential used (Target) acts; the initiating Subject is the subject; typed explicit-credential-logon", () => {
    const b = winRoleBlocks(
      4648,
      false,
      f({
        SubjectDomainName: "CORP",
        SubjectUserName: "jdoe",
        SubjectUserSid: "S-1-5-21-1-2-3-500",
        TargetDomainName: "CORP",
        TargetUserName: "svc_sql",
        TargetServerName: "FS01.corp.local",
      }),
    );
    expect(b.actor).toEqual({ kind: "account", name: "CORP\\svc_sql", domain: "CORP" });
    expect(b.subject).toEqual({
      kind: "account",
      name: "CORP\\jdoe",
      domain: "CORP",
      id: "S-1-5-21-1-2-3-500",
    });
    expect(b.account?.id).toBeUndefined();
    expect(b.event).toEqual({ category: "authentication", type: "explicit-credential-logon" });
  });
  it("4688: the process runs as Target when present, else as the creating Subject", () => {
    const runAs = winRoleBlocks(
      4688,
      false,
      f({
        SubjectDomainName: "CORP",
        SubjectUserName: "jdoe",
        SubjectUserSid: "S-1",
        TargetDomainName: "CORP",
        TargetUserName: "svc_sql",
        TargetUserSid: "S-2",
      }),
    );
    expect(runAs.actor?.name).toBe("CORP\\svc_sql");
    expect(runAs.account?.id).toBe("S-2");
    expect(runAs.subject?.name).toBe("CORP\\jdoe");
    const plain = winRoleBlocks(
      4688,
      false,
      f({
        SubjectDomainName: "CORP",
        SubjectUserName: "jdoe",
        SubjectUserSid: "S-1",
        TargetUserName: "-",
        TargetUserSid: "S-1-0-0",
      }),
    );
    expect(plain.actor?.name).toBe("CORP\\jdoe");
    expect(plain.account?.id).toBe("S-1");
    expect(plain.subject).toBeUndefined();
  });
  it("Sysmon 1: the User field is the acting account", () => {
    const b = winRoleBlocks(1, true, f({ User: "CORP\\svc_sql", Image: "C:\\Windows\\System32\\cmd.exe" }));
    expect(b.actor).toEqual({ kind: "account", name: "CORP\\svc_sql", domain: "CORP" });
    expect(winRoleBlocks(1, true, f({ Image: "x" })).actor).toBeUndefined();
  });
  it("4697 / 5140: the Subject acts; 5140 is typed network / share-access", () => {
    const svc = winRoleBlocks(
      4697,
      false,
      f({
        SubjectDomainName: "CORP",
        SubjectUserName: "svc_sql",
        SubjectUserSid: "S-9",
        ServiceName: "evil",
      }),
    );
    expect(svc.actor?.name).toBe("CORP\\svc_sql");
    expect(svc.account?.id).toBe("S-9");
    expect(svc.event).toBeUndefined();
    const share = winRoleBlocks(
      5140,
      false,
      f({ SubjectDomainName: "CORP", SubjectUserName: "svc_sql", ShareName: "\\\\*\\C$" }),
    );
    expect(share.event).toEqual({ category: "network", type: "share-access" });
    expect(share.actor?.name).toBe("CORP\\svc_sql");
  });
  // #1253: entity() used to always prefer the UPN's OWN realm for `domain`, discarding a
  // separately-recorded, genuinely different NetBIOS domain (e.g. a 4624's TargetDomainName) —
  // the spelling a domain\user caller for the SAME session elsewhere would actually query.
  it("prefers a separately-recorded real domain over the UPN's own realm when they differ", () => {
    expect(
      winRoleBlocks(4624, false, f({ TargetUserName: "jdoe@corp.com", TargetDomainName: "CORP" })).actor,
    ).toEqual({
      kind: "account",
      name: "jdoe@corp.com", // the UPN spelling itself is left alone — only `domain` changes
      domain: "CORP",
    });
  });

  it("a UPN stays a UPN; a missing domain gives an undomained name; '-' and '*' are no account", () => {
    expect(winRoleBlocks(4624, false, f({ TargetUserName: "svc_sql@CORP.LOCAL" })).actor).toEqual({
      kind: "account",
      name: "svc_sql@CORP.LOCAL",
      domain: "CORP.LOCAL",
    });
    expect(winRoleBlocks(4624, false, f({ TargetUserName: "svc_sql" })).actor).toEqual({
      kind: "account",
      name: "svc_sql",
    });
    expect(
      winRoleBlocks(4624, false, f({ TargetUserName: "-", SubjectUserName: "*" })).actor,
    ).toBeUndefined();
  });
});

describe("winRoleBlocks — the Kerberos ticket request", () => {
  const tgs = (ed: Record<string, string>) =>
    winRoleBlocks(
      4769,
      false,
      f({
        TargetUserName: "attacker@CORP.LOCAL",
        TargetDomainName: "CORP.LOCAL",
        ServiceName: "svc_sql",
        TicketEncryptionType: "0x17",
        Status: "0x0",
        IpAddress: "::ffff:10.0.0.66",
        ...ed,
      }),
    );
  it("4769: typed ticket-request; the requester acts; the service account is the object; enc type and outcome are read", () => {
    const b = tgs({});
    expect(b.event).toEqual({ category: "authentication", type: "ticket-request", outcome: "success" });
    expect(b.actor?.name).toBe("attacker@CORP.LOCAL");
    expect(b.object).toEqual({ kind: "account", name: "svc_sql" });
    expect(b.authentication).toEqual({ protocol: "kerberos", mechanism: "0x17" });
  });
  it("a refused request (Status ≠ 0x0) is 'failed'; a machine or krbtgt service is still named (the engine excludes it)", () => {
    expect(tgs({ Status: "0x12" }).event?.outcome).toBe("failed");
    expect(tgs({ ServiceName: "DC01$" }).object?.name).toBe("DC01$");
    expect(tgs({ ServiceName: "krbtgt" }).object?.name).toBe("krbtgt");
  });
  it("4768: typed tgt-request; no object", () => {
    const b = winRoleBlocks(
      4768,
      false,
      f({
        TargetUserName: "svc_legacy",
        TargetDomainName: "CORP",
        TicketEncryptionType: "0x17",
        PreAuthType: "0",
        Status: "0x0",
      }),
    );
    expect(b.event).toEqual({ category: "authentication", type: "tgt-request", outcome: "success" });
    expect(b.object).toBeUndefined();
    expect(b.authentication).toEqual({ protocol: "kerberos", mechanism: "0x17" });
  });
  it("Sysmon never produces a ticket block; a 4769 with no ServiceName has no object", () => {
    expect(winRoleBlocks(4769, true, f({ ServiceName: "x" })).event).toBeUndefined();
    expect(tgs({ ServiceName: "" }).object).toBeUndefined();
  });
});
