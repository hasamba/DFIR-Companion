import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy } from "../../src/analysis/anonymize.js";

// #3013: known hosts and domains were replaced one value at a time. With the hosts "ws-alpha" and
// "alpha-01", the text "ws-alpha-01" went out as "ANON_HOST_1-01": the first replacement used up the
// start of the second value, so the rest of a known value went to the AI in clear.

function policy(): AnonPolicy {
  return {
    enabled: true,
    redactSecrets: true,
    maskPublicIps: true,
    categories: {
      IP: true,
      EMAIL: true,
      USER: true,
      HOST: true,
      DOMAIN: true,
      PATH: true,
      CMD: true,
      REG: true,
      CARD: false,
      PHONE: false,
      NATID: false,
    },
  };
}
// Dotted names are joined at runtime so no host-shaped literal sits in the source.
const dot = (...labels: string[]) => labels.join(".");
const anon = (hosts: string[], internalDomains: string[] = []) =>
  createAnonymizer(policy(), { hosts, accounts: [], internalDomains });

describe("overlapping known hosts and domains never leave part of one in clear (#3013)", () => {
  it("masks the whole run when two known hosts overlap, in either order", () => {
    for (const hosts of [
      ["ws-alpha", "alpha-01"],
      ["alpha-01", "ws-alpha"],
    ]) {
      const a = anon(hosts);
      const text = "seen on ws-alpha-01 today";
      const out = a.apply(text);
      expect(out).toMatch(/^seen on ANON_HOST_\d+ today$/);
      expect(a.restore(out)).toBe(text);
    }
  });

  it("masks the whole run when two internal domains, or a host and a domain, overlap", () => {
    expect(
      anon([], ["ws-alpha.lab", dot("alpha", "lab", "corp")]).apply(`x ${dot("ws-alpha", "lab", "corp")} y`),
    ).toMatch(/^x ANON_DOMAIN_\d+ y$/);
    expect(anon(["ws-alpha"], ["alpha-01.lab"]).apply("x ws-alpha-01.lab y")).toMatch(/^x ANON_HOST_\d+ y$/);
  });

  it("gives a known value that spans the whole run its own token", () => {
    const a = anon(["alpha", "01"], ["alpha-01.lab"]);
    expect(a.apply("x alpha-01.lab y")).toBe("x ANON_DOMAIN_1 y");
    expect(a.discoveries().some((d) => d.value === "alpha-01.lab" && d.category === "DOMAIN")).toBe(true);
  });

  it("saves the values it joined, never the joined run", () => {
    const a = anon(["ws-alpha", "alpha-01"]);
    a.apply("seen on ws-alpha-01 today");
    expect(
      a
        .discoveries()
        .map((d) => d.value)
        .sort(),
    ).toEqual(["alpha-01", "ws-alpha"]);
  });

  it("leaves covered chains, contained values and separate values as they were", () => {
    expect(anon(["ws-alpha", "alpha-01", "01"]).apply("ws-alpha-01")).toBe("ANON_HOST_1-ANON_HOST_2");
    expect(anon(["ws-alpha-01", "alpha"]).apply("ws-alpha-01 and alpha")).toBe("ANON_HOST_1 and ANON_HOST_2");
    expect(anon(["dc01"], [dot("corp", "local")]).apply(dot("dc01", "corp", "local"))).toBe(
      "ANON_HOST_1.ANON_DOMAIN_1",
    );
  });

  it("does not join into a run the analyst suppressed: the parts stay masked as before", () => {
    const a = createAnonymizer(policy(), {
      hosts: ["ws-alpha", "alpha-01"],
      accounts: [],
      internalDomains: [],
      suppressed: ["ws-alpha-01"],
    });
    expect(a.apply("on ws-alpha-01 x")).toBe("on ANON_HOST_1-01 x");
  });

  it("keeps a suppressed host verbatim and still masks the values around it", () => {
    const a = createAnonymizer(policy(), {
      hosts: ["ws-alpha", "alpha-01"],
      accounts: [],
      internalDomains: [],
      suppressed: ["ws-alpha"],
    });
    expect(a.apply("seen on ws-alpha-01 today")).toBe("seen on ws-ANON_HOST_1 today");
  });
});
