import { describe, it, expect, afterEach } from "vitest";
import {
  detectLookalike,
  registrable,
  skeleton,
  lookalikeBrands,
  lookalikeAllowedHosts,
} from "../../src/analysis/lookalikeDomains.js";

describe("registrable", () => {
  it("takes eTLD+1 and strips www / subdomains", () => {
    expect(registrable("www.accounts.google.com")).toBe("google.com");
    expect(registrable("Microsoft.COM")).toBe("microsoft.com");
    expect(registrable("foo.bar.barclays.co.uk")).toBe("barclays.co.uk"); // multipart suffix
  });
});

describe("skeleton", () => {
  it("folds ASCII homoglyphs and separators", () => {
    expect(skeleton("paypa1.com")).toBe(skeleton("paypal.com"));
    expect(skeleton("g00gle.com")).toBe(skeleton("google.com"));
    expect(skeleton("micro-soft.com")).toBe(skeleton("microsoft.com"));
  });
  it("folds confusable Unicode (Latin diacritic / Cyrillic)", () => {
    expect(skeleton("microsöft.com")).toBe(skeleton("microsoft.com"));
    expect(skeleton("pаypal.com")).toBe(skeleton("paypal.com")); // Cyrillic 'а'
  });
});

describe("detectLookalike — homoglyph (strongest)", () => {
  it("flags an ASCII digit homoglyph of a brand", () => {
    const v = detectLookalike("paypa1.com");
    expect(v?.kind).toBe("homoglyph");
    expect(v?.brand).toBe("paypal.com");
    expect(v?.note).toMatch(/homoglyph/i);
  });
  it("flags a Cyrillic-lookalike domain", () => {
    const v = detectLookalike("microsоft.com"); // Cyrillic 'о'
    expect(v?.kind).toBe("homoglyph");
    expect(v?.brand).toBe("microsoft.com");
  });
  it("decodes IDN punycode before comparing", () => {
    // xn--microsft-s4a.com decodes to "microsöft.com" → homoglyph of microsoft.com
    const v = detectLookalike("xn--microsft-s4a.com");
    expect(v?.brand).toBe("microsoft.com");
  });
});

describe("detectLookalike — typosquat", () => {
  it("flags a one-edit typo of a brand", () => {
    const v = detectLookalike("gooogle.com");
    expect(v?.kind).toBe("typosquat");
    expect(v?.brand).toBe("google.com");
    expect(v?.distance).toBe(1);
  });
  it("allows up to 2 edits for long brand labels", () => {
    const v = detectLookalike("micrsoft.com"); // 1 deletion from microsoft
    expect(v?.brand).toBe("microsoft.com");
    expect(v?.kind).toBe("typosquat");
  });
});

describe("detectLookalike — impersonation (brand token in another domain)", () => {
  it("flags a brand token embedded in a different registrable domain", () => {
    const v = detectLookalike("microsoft-login.com");
    expect(v?.kind).toBe("impersonation");
    expect(v?.brand).toBe("microsoft.com");
  });
  it("flags the brand as a deceptive subdomain of an evil domain", () => {
    const v = detectLookalike("paypal.com.secure-verify.io");
    expect(v?.brand).toBe("paypal.com");
    expect(v?.kind).toBe("impersonation");
  });
  it("flags a brand as the leading label of a phishing host", () => {
    const v = detectLookalike("google.verify-account.com");
    expect(v?.kind).toBe("impersonation");
    expect(v?.brand).toBe("google.com");
  });
});

describe("detectLookalike — no false positives on legitimate domains", () => {
  it("never flags an exact brand or its subdomains", () => {
    expect(detectLookalike("microsoft.com")).toBeNull();
    expect(detectLookalike("login.microsoftonline.com")).toBeNull();
    expect(detectLookalike("accounts.google.com")).toBeNull();
    expect(detectLookalike("www.paypal.com")).toBeNull();
  });
  it("does not flag unrelated domains", () => {
    expect(detectLookalike("example.com")).toBeNull();
    expect(detectLookalike("some-random-blog.net")).toBeNull();
    expect(detectLookalike("weather-widget.net")).toBeNull();
  });
  it("does not match a brand label inside a longer unrelated word", () => {
    // "amazon" is a substring of "amazonia" but there's no token boundary → not impersonation.
    expect(detectLookalike("amazonia-travel.com")).toBeNull();
  });
  it("returns null for non-domain / empty input", () => {
    expect(detectLookalike("")).toBeNull();
    expect(detectLookalike("notadomain")).toBeNull();
  });
});

describe("detectLookalike — known security-reference hosts are never flagged", () => {
  it("does not flag lolbas-project.github.io as impersonating github.com", () => {
    // Regression for INC-2026-018: registrable("lolbas-project.github.io") falls back to the
    // 2-label "github.io" (not a recognised multipart suffix), so without an explicit allowlist
    // the "github" brand token still matches with a boundary and this reads as impersonation.
    expect(detectLookalike("lolbas-project.github.io")).toBeNull();
  });
  it("does not flag other bundled reference hosts", () => {
    expect(detectLookalike("gtfobins.github.io")).toBeNull();
    expect(detectLookalike("attack.mitre.org")).toBeNull();
  });
  it("still flags an unrelated site that embeds a brand token", () => {
    const v = detectLookalike("paypal-support-verify.info");
    expect(v?.kind).toBe("impersonation");
    expect(v?.brand).toBe("paypal.com");
  });
  it("does not exempt a github.io host outside the allowlist", () => {
    // Confirms the fix is a narrow, exact-hostname allowlist, not a blanket "*.github.io" carve-out.
    const v = detectLookalike("not-a-real-lolbas-project.github.io");
    expect(v?.kind).toBe("impersonation");
    expect(v?.brand).toBe("github.com");
  });
});

describe("lookalikeAllowedHosts — env extension", () => {
  afterEach(() => {
    delete process.env.DFIR_LOOKALIKE_ALLOW_DOMAINS;
  });

  it("includes the bundled reference hosts by default", () => {
    expect(lookalikeAllowedHosts().has("lolbas-project.github.io")).toBe(true);
  });

  it("adds the analyst's own hosts from DFIR_LOOKALIKE_ALLOW_DOMAINS", () => {
    process.env.DFIR_LOOKALIKE_ALLOW_DOMAINS = "internal-wiki.github.io, Docs.Acme.Com";
    expect(lookalikeAllowedHosts().has("internal-wiki.github.io")).toBe(true);
    expect(lookalikeAllowedHosts().has("docs.acme.com")).toBe(true);
  });
});

describe("lookalikeBrands — env extension", () => {
  afterEach(() => {
    delete process.env.DFIR_LOOKALIKE_EXTRA_DOMAINS;
  });

  it("includes the bundled brands by default", () => {
    expect(lookalikeBrands()).toContain("microsoft.com");
    expect(lookalikeBrands()).toContain("okta.com");
  });

  it("adds the analyst's own domains from DFIR_LOOKALIKE_EXTRA_DOMAINS", () => {
    process.env.DFIR_LOOKALIKE_EXTRA_DOMAINS = "acmecorp.com, www.acmecorp.co.uk";
    expect(lookalikeBrands()).toContain("acmecorp.com");
    expect(lookalikeBrands()).toContain("acmecorp.co.uk");
    // And a typosquat of the org's own domain is then detected.
    const v = detectLookalike("acmecorp-hr.com");
    expect(v?.brand).toBe("acmecorp.com");
  });
});
