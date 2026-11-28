import { describe, expect, it } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3062 — values glued to each other (card + IPv4, IPv4 + card, IPv4 + IPv4) each get their own
// token, Amex and 19-digit groupings with a glued digit are masked, and a public head with a
// three- or four-digit last part is masked under public masking. Addresses and cards are built
// at runtime.

function policy(maskPublicIps = true, over: Partial<AnonPolicy["categories"]> = {}): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps,
    categories: {
      ...{ IP: true, EMAIL: true, USER: true, HOST: true, DOMAIN: true, PATH: true },
      ...{ CMD: true, REG: true, CARD: true, PHONE: true, NATID: true },
      ...over,
    },
  };
}
const known: KnownEntities = { hosts: [], accounts: [], internalDomains: [], usernames: [], suppressed: [] };
const ip = (...parts: Array<number | string>) => parts.join(".");

function luhnOk(digits: string): boolean {
  let sum = 0;
  for (let i = digits.length - 1, alt = false; i >= 0; i--, alt = !alt) {
    let d = Number(digits[i]);
    if (alt && (d *= 2) > 9) d -= 9;
    sum += d;
  }
  return sum % 10 === 0;
}
/** `body` plus the one check digit that makes it pass Luhn. */
function withCheck(body: string): string {
  for (let d = 0; d < 10; d++) if (luhnOk(body + d)) return body + d;
  throw new Error("unreachable");
}
const group = (digits: string, widths: number[]) => {
  let at = 0;
  return widths.map((w) => digits.slice(at, (at += w))).join(" ");
};
const CARD16 = withCheck("4" + "1".repeat(14));
const CARD = group(CARD16, [4, 4, 4, 4]);
const AMEX = group(withCheck("37" + "8".repeat(12)), [4, 6, 5]);
const CARD19 = group(withCheck("4" + "1".repeat(17)), [4, 4, 4, 4, 3]);

function masks(text: string, shape: RegExp, mask = true, over = {}) {
  const a = createAnonymizer(policy(mask, over), known);
  const out = a.apply(text);
  expect(out).toMatch(shape);
  expect(a.restore(out)).toBe(text);
  return a;
}

describe("values glued to each other (#3062)", () => {
  it("a card glued before an internal address: one token each", () => {
    const a = masks(`a ${CARD}${ip(10, 0, 0, 5)} b`, /^a ANON_CARD_\d+ANON_IP_\d+ b$/);
    expect(a.discoveries().map((d) => d.value)).toEqual(expect.arrayContaining([CARD, ip(10, 0, 0, 5)]));
    masks(`a ${CARD16}${ip(10, 0, 0, 5)} b`, /^a ANON_CARD_\d+ANON_IP_\d+ b$/);
    masks(`a ${CARD19}${ip(10, 0, 0, 5)} b`, /^a ANON_CARD_\d+ANON_IP_\d+ b$/);
  });

  it("an internal address glued before a card: one token each", () => {
    const a = masks(`a ${ip(10, 0, 0, 5)}${CARD} b`, /^a ANON_IP_\d+ANON_CARD_\d+ b$/);
    expect(a.discoveries().map((d) => d.value)).toEqual(expect.arrayContaining([CARD, ip(10, 0, 0, 5)]));
    masks(`a ${ip(10, 0, 0, 5)}${CARD16} b`, /^a ANON_IP_\d+ANON_CARD_\d+ b$/);
    masks(`a ${ip(192, 168, 1, 77)}${AMEX} b`, /^a ANON_IP_\d+ANON_CARD_\d+ b$/);
  });

  it("two addresses glued together: one token each", () => {
    const a = masks(`a ${ip(10, 0, 0, 5)}${ip(10, 0, 0, 6)} b`, /^a ANON_IP_\d+ANON_IP_\d+ b$/);
    expect(a.discoveries().map((d) => d.value)).toEqual(
      expect.arrayContaining([ip(10, 0, 0, 5), ip(10, 0, 0, 6)]),
    );
    masks(`a ${ip(10, 0, 0, 51)}${ip(192, 168, 1, 7)} b`, /^a ANON_IP_\d+ANON_IP_\d+ b$/);
  });

  it("a later call with public masking off still hides a public second address seen before", () => {
    const text = `a ${ip(10, 0, 0, 5)}${ip(93, 1, 2, 3)} b`;
    const first = createAnonymizer(policy(true), known);
    expect(first.apply(text)).toMatch(/^a ANON_IP_\d+ANON_EXTIP_\d+ b$/);
    const later = createAnonymizer(policy(false), { ...known, custom: first.discoveries() });
    expect(later.apply(text)).toMatch(/^a ANON_IP_\d+ b$/);
  });

  it("a public address before an internal one stays visible with public masking off", () => {
    const pub = ip(8, 8, 8, 8);
    masks(
      `a ${pub}${ip(10, 0, 0, 6)} b`,
      new RegExp(`^a ${pub.replace(/\./g, "\\.")}ANON_IP_\\d+ b$`),
      false,
    );
    masks(`a ${pub}${ip(10, 0, 0, 6)} b`, /^a ANON_EXTIP_\d+ANON_IP_\d+ b$/, true);
  });

  it("with the card category off, no card group goes out that is hidden today", () => {
    const a = createAnonymizer(policy(true, { CARD: false }), known);
    const out = a.apply(`a ${ip(10, 0, 0, 5)}${CARD} b`);
    expect(out).toMatch(/^a ANON_IP_\d+ /);
    expect(a.restore(out)).toBe(`a ${ip(10, 0, 0, 5)}${CARD} b`);
  });

  it("an Amex or 19-digit card glued before a public address left in clear gets its own token", () => {
    const pub = ip(1, 3, 0, 255);
    for (const c of [AMEX, CARD19]) {
      const a = masks(
        `a ${c}${pub} b`,
        new RegExp(`^a ANON_CARD_\\d+\\S?${pub.replace(/\./g, "\\.")} b$`),
        false,
      );
      expect(a.discoveries().map((d) => d.value)).toContain(c);
    }
  });

  it("a card glued after a public address is masked with public masking off", () => {
    const pub = ip(8, 8, 8, 8);
    const a = createAnonymizer(policy(false), known);
    for (const c of [CARD, CARD16]) {
      const out = a.apply(`a ${pub}${c} b`);
      expect(out).not.toContain(CARD16.slice(-8));
      expect(out).not.toContain(CARD.slice(-9));
      expect(a.restore(out)).toBe(`a ${pub}${c} b`);
    }
  });
});

describe("Amex and 19-digit groupings with a glued digit (#3062)", () => {
  it("is masked whole on either end", () => {
    for (const v of [`${AMEX}5`, `5${AMEX}`, `${CARD19}5`, `5${CARD19}`, `12${CARD19}`])
      masks(`a ${v} b`, /^a ANON_CARD_\d+ b$/);
  });

  it("a long bare number is never cut into a card window", () => {
    const a = createAnonymizer(policy(), known);
    for (const n of ["133" + "7".repeat(15), withCheck("4" + "1".repeat(17)) + "7"]) {
      expect(a.apply(`t ${n} x`)).toBe(`t ${n} x`);
      expect(a.apply(`t ${n}${ip(".", 1, 2, 3).slice(1)} x`)).toBe(`t ${n}${ip(".", 1, 2, 3).slice(1)} x`);
    }
  });

  it("a 17-19 digit run next to a dotted triple is read as a card only when its 16 digits pass", () => {
    const off = createAnonymizer(policy(false), known);
    const bad = CARD16.slice(0, 15) + ((Number(CARD16[15]) + 1) % 10); // fails Luhn
    for (const n of [`${bad}12`, `${bad}5`]) {
      const before = `t ${n}${ip(".", 1, 2, 3).slice(1)} x`;
      expect(off.apply(before)).toBe(before);
      const after = `t ${ip(1, 2, 3, "")}${n.slice(-2, -1)}${bad} x`;
      expect(off.apply(after)).toBe(after);
    }
  });
});

describe("a public head with a three- or four-digit last part (#3062)", () => {
  it("is masked with public masking on and stays clear with it off", () => {
    for (const v of [ip(8, 8, 8, 8123), ip(8, 8, 8, 812)]) {
      masks(`ran ${v} y`, /^ran ANON_EXTIP_\d+ y$/, true);
      const off = createAnonymizer(policy(false), known);
      expect(off.apply(`ran ${v} y`)).toBe(`ran ${v} y`);
    }
  });
});

describe("glued readings a later call must keep hidden (#3068)", () => {
  it("a public head glued to a card-shaped digit run stays hidden with public masking and CARD off later", () => {
    const run = withCheck("36011" + "3".repeat(13)); // 19 digits: CARD_RE reads it after the dot
    const text = `a ${ip(93, 1, 2, run)}`;
    const first = createAnonymizer(policy(true), known);
    const out = first.apply(text);
    expect(out).toMatch(/^a ANON_EXTIP_\d+$/);
    expect(first.restore(out)).toBe(text);
    const later = createAnonymizer(policy(false, { CARD: false }), { ...known, custom: first.discoveries() });
    const out2 = later.apply(text);
    expect(out2).not.toContain(run.slice(1));
    expect(later.restore(out2)).toBe(text);
  });

  it("a card with digits glued in front, before an internal address: one token each", () => {
    for (const pre of ["5", "12", "123"]) {
      const a = masks(`a ${pre}${CARD}${ip(10, 0, 0, 5)} b`, /^a ANON_CARD_\d+ANON_IP_\d+ b$/);
      expect(a.discoveries().map((d) => d.value)).toEqual(
        expect.arrayContaining([pre + CARD, ip(10, 0, 0, 5)]),
      );
    }
    masks(`a 5${CARD19}${ip(10, 0, 0, 5)} b`, /^a ANON_CARD_\d+ANON_IP_\d+ b$/);
    masks(`a 5${AMEX}${ip(10, 0, 0, 5)} b`, /^a ANON_CARD_\d+ANON_IP_\d+ b$/);
  });

  it("an internal address glued to a public one with public masking off never shows the internal one", () => {
    const off = createAnonymizer(policy(false), known);
    for (const [head, tail] of [
      [ip(10, 0, 0, 5), ip(93, 1, 2, 3)],
      [ip(10, 0, 0, 51), ip(8, 8, 8, 8)],
    ]) {
      const text = `a ${head}${tail} b`;
      const out = off.apply(text);
      expect(out).toMatch(/^a ANON_IP_\d+/);
      expect(out).not.toContain(head.slice(0, -1));
      expect(off.restore(out)).toBe(text);
    }
  });
});
