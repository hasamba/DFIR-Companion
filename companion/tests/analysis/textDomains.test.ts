import { describe, it, expect } from "vitest";
import { extractDomains, hasPlausibleTld } from "../../src/analysis/textDomains.js";

// extractDomains is the ONE free-text domain scraper — siemImport, bashHistoryImport and
// velociraptorImport all read C2 names through it. These tests pin the two halves of its contract:
// a domain an analyst would chase gets extracted, and the dotted tokens that fill Windows free text
// (file names, .NET namespaces, framework paths, registry keys, version strings) do not.
describe("extractDomains", () => {
  it("extracts a domain from quoted script text and lower-cases it", () => {
    expect(extractDomains("$h = 'Winsoftwarehub.TOP'")).toEqual(["winsoftwarehub.top"]);
  });

  it("extracts the host out of a URL, and de-duplicates repeats", () => {
    expect(extractDomains("GET http://cdn.evil-c2.net/a then http://cdn.evil-c2.net/b")).toEqual([
      "cdn.evil-c2.net",
    ]);
  });

  it("returns [] for empty text", () => {
    expect(extractDomains("")).toEqual([]);
  });

  it("rejects a file name that looks like a domain", () => {
    const text =
      "dropped rundll32.exe, loader.dll, svchost.ps1, beacon.dat, report.docx, notes.md, " +
      "Program.cs, Module.vb, History.db, NOTEPAD.EXE-A1B2C3D4.pf";
    expect(extractDomains(text)).toEqual([]);
  });

  it("rejects a Windows path component such as Microsoft.NET", () => {
    expect(extractDomains("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe")).toEqual([]);
  });

  it("rejects a registry key whose value name carries a dot", () => {
    expect(extractDomains("HKLM\\SOFTWARE\\Classes\\WOW6432Node\\Updater.co\\shell")).toEqual([]);
  });

  it("still extracts a UNC host — two backslashes are a share, not a path component", () => {
    expect(extractDomains("copy \\\\stage.evil-c2.net\\pub\\x.bin")).toEqual(["stage.evil-c2.net"]);
  });

  it("rejects a version string (no alphabetic last label to match)", () => {
    expect(extractDomains("built against 10.0.22621.2506 with v4.0.30319")).toEqual([]);
  });

  it("rejects a .NET namespace whose last label is not a real TLD", () => {
    expect(extractDomains("New-Object System.Net.WebClient; [System.IO.File]::ReadAllBytes")).toEqual([]);
  });

  // A CHAINED namespace is rejected above only because greedy matching runs past it to a last label
  // no TLD table would accept ("webclient", "file"). A TERMINAL one has a real TLD sitting at the
  // end — System.Net, System.IO, Microsoft.NET — and sailed straight through until the
  // code-namespace pair check was added. PowerShell script blocks are full of these.
  it.each([
    "using namespace System.Net",
    "[System.IO]::Path",
    "Add-Type -AssemblyName System.Net",
    "loaded Microsoft.NET runtime",
    "at java.net.Socket and java.io directly",
  ])("rejects a terminal code namespace: %s", (text) => {
    expect(extractDomains(text)).toEqual([]);
  });

  // The pair check must not swallow the real domains those namespace roots also spell.
  it.each([
    ["visit microsoft.com for the advisory", "microsoft.com"],
    ["exfil to acct.blob.core.windows.net/share", "acct.blob.core.windows.net"],
    ["beacon to system.example.com", "system.example.com"],
  ])("still extracts a real domain built on a namespace root: %s", (text, expected) => {
    expect(extractDomains(text)).toContain(expected);
  });

  it("rejects an internal AD/mDNS zone", () => {
    expect(extractDomains("logon from WS-01.northstar.local and DC1.corp")).toEqual([]);
  });

  // The local part has to be domain-SHAPED with a plausible TLD for this guard to be the thing
  // rejecting it — "finance.dept@…" is thrown out by hasPlausibleTld instead and proves nothing.
  it("rejects a domain-shaped email local-part but keeps the domain after the @", () => {
    expect(extractDomains("mail from billing.co@evil-c2.net")).toEqual(["evil-c2.net"]);
  });
});

describe("hasPlausibleTld", () => {
  it("accepts any two-letter last label (the ccTLD space)", () => {
    expect(hasPlausibleTld("evil.io")).toBe(true);
  });

  it("accepts a known gTLD", () => {
    expect(hasPlausibleTld("evil.download")).toBe(true);
  });

  it("rejects an invented last label", () => {
    expect(hasPlausibleTld("artifacts.precondition")).toBe(false);
  });
});
