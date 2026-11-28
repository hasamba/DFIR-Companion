import { describe, it, expect } from "vitest";
import {
  createAnonymizer,
  type AnonPolicy,
  type AnonTokenCategory,
  type CustomEntity,
} from "../../src/analysis/anonymize.js";

// #3019: a call that re-injects saved values (a seeded call) never masks less than the same call
// without them. Synthetic values only: 10/8, 192.168/16, fd00::/8, 2001:db8::/32, 555-01xx and a
// .invalid mail domain, built at runtime.

type Cats = Partial<Record<AnonTokenCategory, boolean>>;
function policy(mask: boolean, cats: Cats): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: false,
    maskPublicIps: mask,
    categories: {
      IP: true,
      EMAIL: true,
      USER: false,
      HOST: false,
      DOMAIN: false,
      PATH: false,
      CMD: false,
      REG: false,
      CARD: false,
      PHONE: true,
      NATID: false,
      ...cats,
    },
  };
}
function anon(mask: boolean, cats: Cats, custom: CustomEntity[] = []) {
  return createAnonymizer(policy(mask, cats), {
    hosts: [],
    accounts: [],
    internalDomains: [],
    custom,
    suppressed: [],
  });
}
// Call 1 saves its discoveries; call 2 re-injects them as custom values.
function seeded(first: string, second: string, mask: boolean, cats: Cats = {}) {
  const a = anon(mask, {});
  a.apply(first);
  const s = anon(mask, cats, a.discoveries());
  const out = s.apply(second);
  return { out, back: s.restore(out), saved: s.discoveries().map((d) => d.value) };
}
function fresh(text: string, mask: boolean, cats: Cats = {}) {
  const a = anon(mask, cats);
  const out = a.apply(text);
  return { out, back: a.restore(out) };
}

const NUM = ["555", "0100"].join("-");
const MAIL = ["mail", "invalid"].join(".");
const DOC = ["2001", "db8::"].join(":");
const FIVE = /\d+\.\d+\.\d+\.\d+\.\d+/;
// The digits left in clear once every token is taken out.
const clear = (out: string) => out.replace(/ANON_[A-Z]+_\d+/g, "").replace(/\D/g, "");

describe.each([false, true])("a seeded call masks no less than a fresh one (#3019), mask=%s", (mask) => {
  it("shape 1: a saved email inside a longer dotted local part takes the numbers in front", () => {
    const input = `x ${DOC}10.10.0.0.5@${MAIL} y`;
    const cats = { IP: false };
    const r = seeded(input, input, mask, cats);
    expect(r.out).toMatch(/[:.]ANON_EMAIL_\d+ y$/);
    expect(r.out).not.toContain("10.");
    expect(clear(r.out).length).toBeLessThanOrEqual(clear(fresh(input, mask, cats).out).length);
    expect(r.back).toBe(input);
  });

  it("shape 3: a saved phone value that starts with an address's last number is split", () => {
    const first = `x fd00::10.0.0.100 ${NUM} y`;
    const input = `x 192.168.1.100 ${NUM} y`;
    const r = seeded(first, input, mask);
    expect(r.out).toMatch(/^x ANON_IP_\d+ ANON_PHONE_\d+ y$/);
    expect(r.back).toBe(input);
    expect(clear(r.out)).toBe("");
  });

  it("shape 3: the split also holds with the phone category off on the seeded call", () => {
    const first = `x fd00::10.0.0.100 ${NUM} y`;
    const input = `x 192.168.1.100 ${NUM} y`;
    const r = seeded(first, input, mask, { PHONE: false });
    expect(r.back).toBe(input);
    expect(clear(r.out)).toBe("");
  });

  it("shape 3: with the IP category off the seeded call is unchanged", () => {
    const first = `x fd00::10.0.0.100 ${NUM} y`;
    const input = `x 192.168.1.100 ${NUM} y`;
    const r = seeded(first, input, mask, { IP: false });
    expect(r.out).toMatch(/^x 192\.168\.1\.ANON_PHONE_\d+ y$/);
    expect(r.back).toBe(input);
  });

  it("shape 4: a saved IPv4 at the end of a longer dotted run takes the numbers in front", () => {
    const input = "x 10.10.0.0.5 y";
    const r = seeded("x 10.0.0.5 y", input, mask);
    expect(r.out).toMatch(/^x ANON_IP_\d+ y$/);
    expect(r.back).toBe(input);
    expect(r.saved.some((v) => FIVE.test(v))).toBe(false);
  });

  it("shape 4: the run after a host label is masked whole", () => {
    const input = "x srv.10.10.0.0.5 y";
    const r = seeded("x 10.0.0.5 y", input, mask);
    expect(r.out).toMatch(/^x srv\.ANON_IP_\d+ y$/);
    expect(r.back).toBe(input);
  });

  it("shape 5: a saved value ending in an address with a dotted tail takes the extra number", () => {
    const input = "abc::ffff:10.0.0.5.5";
    const r = seeded("v_::ffff:10.0.0.5.5", input, mask);
    expect(clear(r.out.replace("ffff", ""))).toBe("");
    expect(r.out).toMatch(/^abc::ANON_IP_\d+$/);
    expect(r.back).toBe(input);
    expect(r.saved.some((v) => FIVE.test(v))).toBe(false);
  });

  it("shape 5: a saved address glued after a label takes the extra number", () => {
    for (const label of ["abc", "v_"]) {
      const input = `${label}${DOC}10.10.0.0.5`;
      const r = seeded(`x ${DOC}10.10.0.0 y`, input, mask);
      expect(r.out.startsWith(label)).toBe(true);
      expect(clear(r.out)).toBe("");
      expect(r.back).toBe(input);
    }
  });

  it("shape 2: a fifth number after a label-prefixed :: address is masked with it", () => {
    for (const input of ["Evtx::10.0.0.5.6", "a.::10.0.0.5.6"]) {
      const r = fresh(input, mask);
      expect(r.out).toMatch(/::ANON_IP_\d+$/);
      expect(r.back).toBe(input);
    }
  });

  it("leaves the cut tail of an address set aside to that address", () => {
    const input = `x ${DOC}10.10.0.0.10.0.0.6 y`;
    const r = seeded("x 10.0.0.100.10.0.0.6 y", input, mask);
    expect(r.out).not.toContain("::10.");
    expect(r.back).toBe(input);
  });

  it("takes one or two numbers between an address set aside and a saved IPv4", () => {
    const input = "x fd00::10.10.10.0.0.5 y";
    const r = seeded("x 10.0.0.5 y", input, mask);
    expect(clear(r.out)).toBe("");
    expect(r.back).toBe(input);
  });

  it("masks the last group of an address left in clear with the saved IPv4 it opens", () => {
    for (const tail of ["", ".6"]) {
      const input = `x ${DOC}10.10.0.0.5${tail} y`;
      const r = seeded("x 10.0.0.5 y", input, mask);
      expect(r.out).not.toMatch(/::10\./);
      expect(r.back).toBe(input);
    }
  });

  it("shape 3: a saved phone value behind an IPv6 address with a dotted tail is split", () => {
    for (const head of ["fd00::", DOC]) {
      const input = `x ${head}10.0.0.100 ${NUM} y`;
      const r = seeded(`x 10.0.0.5.100 ${NUM} y`, input, mask);
      expect(r.out).toMatch(/ANON_[A-Z]+_\d+ ANON_PHONE_\d+ y$/);
      expect(r.out).not.toContain("10.0.0.");
      expect(r.back).toBe(input);
    }
  });

  it("shape 3: a longer dotted run in front of a saved phone value is masked whole", () => {
    const input = `x 10.10.0.0.100 ${NUM} y`;
    const r = seeded(`x 10.0.0.100.100 ${NUM} y`, input, mask);
    expect(r.out).toMatch(/^x ANON_IP_\d+ ANON_PHONE_\d+ y$/);
    expect(r.back).toBe(input);
  });

  it("keeps a run the IPv4 pass leaves in clear as before", () => {
    const lead = [198, 51].join(".");
    const input = `x ${lead}.10.0.0.5 y`;
    const r = seeded("x 10.0.0.5 y", input, mask);
    expect(r.back).toBe(input);
    if (!mask) expect(r.out).toMatch(new RegExp(`^x ${lead.replace(".", "\\.")}\\.ANON_IP_\\d+ y$`));
  });

  it("never eats the index of a token in front of the run", () => {
    const input = "x ANON_HOST_1.10.10.0.0.5 y";
    const r = seeded("x 10.0.0.5 y", input, mask);
    expect(r.out).toMatch(/^x ANON_HOST_1\.ANON_IP_\d+ y$/);
    expect(r.back).toBe(input);
  });
});
