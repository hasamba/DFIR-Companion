// The principal-name ledger (#2490): id → name facts learned at import, unioned on merge, with the
// exactly-one-name rule compared on the full stored name, never on the shortened shown text.
import { describe, it, expect } from "vitest";
import {
  mergePrincipalNames,
  principalLedgerChanged,
  principalNameLookup,
  principalPair,
  PRINCIPAL_NAMES_MAX,
} from "../../src/analysis/principalNames.js";
import { displayPrincipalName, PRINCIPAL_NAME_SHOWN_MAX } from "../../src/analysis/principalNameCarry.js";

const SP = "3f2a1b4c-1111-2222-3333-444455556666";
const APP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

describe("principalPair", () => {
  it("keys on the lower-cased GUID and keeps the name", () => {
    expect(principalPair(SP.toUpperCase(), "backup-automation")).toEqual({
      id: SP,
      names: ["backup-automation"],
    });
  });
  it("refuses a non-GUID id, an empty name and a name that is itself a GUID", () => {
    expect(principalPair("not-a-guid", "x")).toBeNull();
    expect(principalPair(SP, "  ​ ")).toBeNull();
    expect(principalPair(SP, APP)).toBeNull();
  });
  it("stores one line without controls or format characters", () => {
    expect(principalPair(SP, "evil\r\nname‮")?.names).toEqual(["evil name"]);
  });
});

describe("mergePrincipalNames", () => {
  it("unions by id, case-insensitive on names, first spelling kept", () => {
    const a = [{ id: SP, names: ["Backup-Automation"] }];
    const b = [
      { id: SP, names: ["backup-automation"] },
      { id: APP, names: ["deployer"] },
    ];
    expect(mergePrincipalNames(a, b)).toEqual([
      { id: SP, names: ["Backup-Automation"] },
      { id: APP, names: ["deployer"] },
    ]);
  });
  it("a second distinct name makes a conflict, and the lookup then names nothing", () => {
    const merged = mergePrincipalNames([{ id: SP, names: ["one"] }], [{ id: SP, names: ["two"] }]);
    expect(merged).toEqual([{ id: SP, names: ["one", "two"] }]);
    expect(principalNameLookup(merged)(SP)).toBeUndefined();
  });
  it("two long names that share the shown prefix still conflict (compared on the stored form)", () => {
    const prefix = "x".repeat(PRINCIPAL_NAME_SHOWN_MAX + 10); // longer than any row shows
    const merged = mergePrincipalNames(
      [{ id: SP, names: [`${prefix}-prod`] }],
      [{ id: SP, names: [`${prefix}-dev`] }],
    );
    expect(merged[0].names).toHaveLength(2);
    expect(principalNameLookup(merged)(SP)).toBeUndefined();
  });
  it("keeps at most two names per id and drops malformed records", () => {
    const merged = mergePrincipalNames([{ id: SP, names: ["a", "b", "c"] }], [
      { id: "nope", names: ["x"] },
      { id: APP, names: [] },
    ] as never);
    expect(merged).toEqual([{ id: SP, names: ["a", "b"] }]);
  });
  it("stops adding ids at the cap but still records a conflict on a known id", () => {
    const many = Array.from({ length: PRINCIPAL_NAMES_MAX }, (_, i) => ({
      id: `00000000-0000-0000-0000-${String(i).padStart(12, "0")}`,
      names: ["n"],
    }));
    const merged = mergePrincipalNames(many, [
      { id: SP, names: ["late"] },
      { id: many[0].id, names: ["other"] },
    ]);
    expect(merged).toHaveLength(PRINCIPAL_NAMES_MAX);
    expect(merged[0].names).toEqual(["n", "other"]);
  });
});

describe("displayPrincipalName", () => {
  it("removes brackets and parentheses, breaks long hex runs, and bounds the text", () => {
    expect(displayPrincipalName("x) from 10.0.0.1 [High] (")).toBe("x from 10.0.0.1 High");
    expect(displayPrincipalName("z".repeat(200))).toHaveLength(PRINCIPAL_NAME_SHOWN_MAX);
    expect(displayPrincipalName("f".repeat(40))).not.toMatch(/[0-9a-f]{32}/);
  });
});

describe("principalLedgerChanged", () => {
  it("compares content", () => {
    expect(principalLedgerChanged({}, { principalNames: [] })).toBe(false);
    expect(principalLedgerChanged({}, { principalNames: [{ id: SP, names: ["a"] }] })).toBe(true);
  });
});
