import { describe, it, expect } from "vitest";
import { deriveSemanticKey, nounPhrase } from "../../src/analysis/semanticKey.js";

describe("nounPhrase", () => {
  it("is order-independent — reordered wording produces the same phrase", () => {
    expect(nounPhrase("Encoded PowerShell execution")).toBe(nounPhrase("PowerShell encoded command"));
  });

  it("drops generic DFIR filler and sorts the salient tokens", () => {
    // "execution"/"command"/"suspicious" are filler → dropped; remaining sorted alphabetically
    expect(nounPhrase("Suspicious encoded PowerShell command")).toBe("encoded_powershell");
  });

  it("de-dupes repeated tokens", () => {
    expect(nounPhrase("PowerShell PowerShell encoded")).toBe("encoded_powershell");
  });

  it("caps the number of tokens to keep the key bounded", () => {
    const phrase = nounPhrase("alpha bravo charlie delta echo foxtrot golf");
    expect(phrase.split("_")).toHaveLength(4);
    expect(phrase).toBe("alpha_bravo_charlie_delta"); // first 4 after sort
  });

  it("falls back to a slug of the whole title when only filler survives", () => {
    // every token is a stopword/filler → phrase would be empty, so slug the title instead
    expect(nounPhrase("suspicious activity detected")).toBe("suspicious_activity_detected");
  });

  it("is case- and punctuation-insensitive", () => {
    expect(nounPhrase("Mimikatz: credential DUMPING!")).toBe(nounPhrase("mimikatz credential dumping"));
  });

  // Volatile-token dropping (#69 live finding): numbers/hashes must not dominate the phrase, else
  // IP-heavy or hash-heavy titles key on the IP/hash and collapse genuinely-different findings.
  it("drops pure-numeric tokens (IP octets, event IDs, counts) — descriptive words win", () => {
    // 185/220/101/47/4698 all dropped; only the words anchor the key
    expect(nounPhrase("Beacon callback to 185.220.101.47, EventID 4698")).toBe("beacon_callback_eventid");
  });

  it("drops long hex hash/blob tokens but keeps short letter+digit tokens (dc01, svchost32)", () => {
    // 32-hex hash dropped; "dc01" (len 4) kept
    expect(nounPhrase("update.dll on DC01 sha a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")).toBe("dc01_dll_sha_update");
  });

  it("keeps two different findings that share an IP distinct (no IP-domination collapse)", () => {
    const dns = nounPhrase("DNS query resolved to 185.220.101.47");
    const conn = nounPhrase("Inbound connection from 185.220.101.47 to beacon");
    expect(dns).not.toBe(conn);
  });
});

describe("deriveSemanticKey", () => {
  it("prefixes the dominant (first) ATT&CK technique", () => {
    expect(deriveSemanticKey({ title: "Encoded PowerShell execution", mitreTechniques: ["T1059.001", "T1027"] }))
      .toBe("T1059.001:encoded_powershell");
  });

  it("collapses reworded-but-equivalent findings with the same technique to one key", () => {
    const a = deriveSemanticKey({ title: "Encoded PowerShell execution", mitreTechniques: ["T1059.001"] });
    const b = deriveSemanticKey({ title: "PowerShell encoded command", mitreTechniques: ["T1059.001"] });
    expect(a).toBe(b);
  });

  it("skips malformed technique ids and uses the first well-formed one", () => {
    expect(deriveSemanticKey({ title: "Credential dumping", mitreTechniques: ["bogus", "T1003.001"] }))
      .toBe("T1003.001:credential_dumping");
  });

  it("omits the technique prefix when the finding maps none", () => {
    expect(deriveSemanticKey({ title: "Cobalt Strike beacon", mitreTechniques: [] }))
      .toBe("beacon_cobalt_strike");
  });

  it("is deterministic / idempotent", () => {
    const f = { title: "Mimikatz credential dumping", mitreTechniques: ["T1003.001"] };
    expect(deriveSemanticKey(f)).toBe(deriveSemanticKey(f));
  });
});
