import { describe, it, expect } from "vitest";
import { attackTechniqueUrl, attackTacticUrl, attackTechniqueMd } from "../../src/analysis/attack.js";

describe("attack (MITRE ATT&CK links)", () => {
  it("builds technique and sub-technique URLs", () => {
    expect(attackTechniqueUrl("T1059")).toBe("https://attack.mitre.org/techniques/T1059/");
    expect(attackTechniqueUrl("T1059.001")).toBe("https://attack.mitre.org/techniques/T1059/001/");
    expect(attackTechniqueUrl(" t1003.001 ")).toBe("https://attack.mitre.org/techniques/T1003/001/");
  });

  it("returns null for non-technique strings (incl. tactic ids and garbage)", () => {
    expect(attackTechniqueUrl("TA0001")).toBeNull();
    expect(attackTechniqueUrl("T123")).toBeNull();
    expect(attackTechniqueUrl("nope")).toBeNull();
  });

  it("builds tactic URLs from the tactic name", () => {
    expect(attackTacticUrl("Credential Access")).toBe("https://attack.mitre.org/tactics/TA0006/");
    expect(attackTacticUrl("command and control")).toBe("https://attack.mitre.org/tactics/TA0011/");
    expect(attackTacticUrl("Impact")).toBe("https://attack.mitre.org/tactics/TA0040/");
    expect(attackTacticUrl("not a tactic")).toBeNull();
  });

  it("renders a Markdown link, falling back to plain text", () => {
    expect(attackTechniqueMd("T1486")).toBe("[T1486](https://attack.mitre.org/techniques/T1486/)");
    expect(attackTechniqueMd("freeform")).toBe("freeform");
  });
});
