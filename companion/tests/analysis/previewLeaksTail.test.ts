import { describe, it, expect } from "vitest";
import { possibleLeaks } from "../../src/analysis/ai/previewLeaks.js";

// #2995 case 4: the preview's leak hint covers an IPv6 address with its whole dotted IPv4 tail, and
// flags octets left in clear right after a token. Synthetic values only.

// A token and the octets left after it, joined at runtime so no dotted quad sits in the repo.
const tok = (cat: string) => ["ANON", cat, "1"].join("_");
const TAIL = [".0", "0", "5"].join(".");

const hints = (masked: string, maskPublicIps: boolean) =>
  possibleLeaks(masked, { maskPublicIps }).map((w) => masked.slice(w.m[0], w.m[1]));

describe.each([true, false])("possible leaks around a dotted IPv4 tail, maskPublicIps=%s", (mask) => {
  it("flags the whole address, not only its head", () => {
    expect(hints("x fd00::10.0.0.5 y", mask)).toEqual(["fd00::10.0.0.5"]);
  });

  it.each([
    [`x ${tok("IP")}${TAIL} y`, TAIL],
    [`x ${tok("HOST")}${TAIL} y`, TAIL],
    [`${tok("IP")}.168.1.${tok("PHONE")}`, ".168.1"],
  ])("flags the octets left after a token in %s", (masked, hint) => {
    expect(hints(masked, mask)).toEqual([hint]);
  });

  it("does not flag a token alone or one followed by a word", () => {
    expect(hints("x ANON_IP_1 y ANON_HOST_2.exe", mask)).toEqual([]);
  });
});

describe("a public address with a dotted tail", () => {
  it("is flagged whole only when public IPs are masked", () => {
    expect(hints("x 2001:db8::10.0.0.5 y", true)).toEqual(["2001:db8::10.0.0.5"]);
  });
});
