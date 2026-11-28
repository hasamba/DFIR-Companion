import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";
import { TOKEN_DELIMITER as DL } from "../../src/analysis/anonTokenLiterals.js";

// #3069: a DOMAIN\user account saves its qualifier (#3049), so on a later call the custom pass mints
// the saved `CORP` before the account pass runs. An address on the internal domain with digits glued
// after its TLD then reached the account pass as `<user>@ANON_DOMAIN_1.local1`, which no reader took:
// the user and the rest of the domain went out in clear. Values are synthetic and built at runtime.
const BS = "\\";
const AT = "@";
const DOM = ["corp", "local"].join(".");
const EXT = ["acme", "example"].join(".");

function policy(maskPublicIps: boolean): AnonPolicy {
  const categories = { IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true };
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: { ...categories, CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
  };
}
const KNOWN: KnownEntities = { hosts: [], accounts: ["jdoe"], internalDomains: [DOM] };

/** A call seeded with what a call on `first` discovered, applied to `text`. */
function seeded(first: string, text: string, pm = true) {
  const a = createAnonymizer(policy(pm), KNOWN);
  a.apply(first);
  const custom = a.discoveries();
  const b = createAnonymizer(policy(pm), { ...KNOWN, custom });
  const out = b.apply(text);
  return { custom, out, back: b.restore(out) };
}

describe("a saved DOMAIN\\user qualifier before an address with glued digits (#3069)", () => {
  for (const pm of [true, false]) {
    it(`hides the user and the whole internal domain (maskPublicIps=${pm})`, () => {
      for (const q of ["CORP", "corp", "Corp"]) {
        for (const [user, glue] of [
          ["jdoe", "1"],
          ["bob", "12"],
          ["bob", "0::2"],
        ]) {
          const text = `x ${user}${AT}${DOM}${glue} y`;
          const { custom, out, back } = seeded(`a ${q}${BS}zed`, text, pm);
          expect(custom.map((d) => d.value)).toContain(q); // the qualifier is still saved
          expect(out).toMatch(new RegExp(`^x ANON_USER_\\d+${AT}ANON_DOMAIN_\\d+${DL}${glue} y$`));
          expect(back).toBe(text);
        }
      }
    });
  }
  it("restores the domain as written when the account is in the same text", () => {
    const text = `a CORP${BS}zed ok x jdoe${AT}${DOM}1`;
    const { out, back } = seeded(text, text);
    expect(out).not.toMatch(/jdoe|local/);
    expect(back).toBe(text);
  });
  it("hides an external address whole, as a call without saved values does", () => {
    const text = `x bob${AT}${EXT}1 y`;
    const { out, back } = seeded(`a ACME${BS}zed`, text);
    expect(out).toMatch(new RegExp(`^x ANON_EMAIL_\\d+${DL}1 y$`));
    expect(back).toBe(text);
  });
  it("still masks the saved qualifier on its own", () => {
    const { out, back } = seeded(`a CORP${BS}zed`, "domain CORP y");
    expect(out).toMatch(/^domain ANON_DOMAIN_\d+ y$/);
    expect(back).toBe("domain CORP y");
  });
});
