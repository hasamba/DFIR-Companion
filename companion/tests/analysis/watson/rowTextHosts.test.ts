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
    ['Computer="ws-fake03.example.com"', ["ws-fake03.example.com", "ws-fake03"]],
    ["DESKTOP-FAKE7Q2 started", ["DESKTOP-FAKE7Q2"]],
    ["Copied to DEV-01, FIN-02 and S1-DC01", ["DEV-01", "FIN-02", "S1-DC01"]],
    ["Workstation Name: fakepc.", ["fakepc"]],
  ])("finds the host in %s", (text, hosts) => {
    expect(descriptionHostNames(text)).toEqual(expect.arrayContaining(hosts));
    expect(descriptionHostNames(text)).not.toContain("fakepc.");
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

  it("lists no identifier shape from a description", () => {
    const r = rosterOf([row({ description: "Exploit for CVE-2021-44228 and MS17-010 over TCP-445" })]);
    expect(r.hosts).toEqual([]);
  });
});
