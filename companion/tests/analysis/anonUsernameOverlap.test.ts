import { describe, it, expect } from "vitest";
import { createAnonymizer, type AnonPolicy, type KnownEntities } from "../../src/analysis/anonymize.js";

// #3010: with learned names "ann bob" and "bob carol dave", the line "ann bob carol dave" went out as
// "ANON_USER_1 carol dave": the bare-name pass resumed after "ann bob" and never tried the name that
// started inside it, so the rest of a masked name went to the AI in clear.

const NONE: KnownEntities = { hosts: [], accounts: [], internalDomains: [] };
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
const PROFILE = ["C:", "Users", ""].join("\\"); // built from parts: no literal profile path in source
const anon = (usernames: string[]) => createAnonymizer(policy(), { ...NONE, usernames });

describe("overlapping learned usernames never leave a tail in clear (#3010)", () => {
  it("masks the whole run when a learned name starts inside the previous match", () => {
    const a = anon(["ann bob", "bob carol dave"]);
    const text = "line: ann bob carol dave end";
    const out = a.apply(text);
    expect(out).toMatch(/^line: ANON_USER_\d+ end$/);
    expect(a.restore(out)).toBe(text);
  });

  it("saves the names it joined, never the joined run", () => {
    const a = anon(["ann bob", "bob carol dave"]);
    a.apply("line: ann bob carol dave end");
    const saved = a.discoveries().map((d) => d.value.toLowerCase());
    expect(saved.sort()).toEqual(["ann bob", "bob carol dave"]);
  });

  it("masks the whole run in upper case and in the reverse order of learning", () => {
    expect(anon(["bob carol dave", "ann bob"]).apply("ANN BOB CAROL DAVE")).toMatch(/^ANON_USER_\d+$/);
  });

  it("masks the whole run when both names were learned from profile paths", () => {
    const a = createAnonymizer(policy(), NONE);
    const text = `${PROFILE}ann bob\\x and ${PROFILE}bob carol dave\\y then ann bob carol dave said hi`;
    const out = a.apply(text);
    expect(out).toMatch(/then ANON_USER_\d+ said hi$/);
    expect(out.toLowerCase()).not.toContain("carol");
    expect(a.restore(out)).toBe(text);
  });

  it("does not join into a run the analyst suppressed: the first name is masked as before", () => {
    const a = createAnonymizer(policy(), {
      ...NONE,
      usernames: ["ann bob", "bob carol dave"],
      suppressed: ["ann bob carol dave"],
    });
    expect(a.apply("x ann bob carol dave y")).toBe("x ANON_USER_1 carol dave y");
  });

  it("leaves a three-way chain, a contained name and a covered tail as they were", () => {
    expect(anon(["ann bob", "bob carol", "carol dave"]).apply("ann bob carol dave")).toBe(
      "ANON_USER_1 ANON_USER_2",
    );
    expect(anon(["ann bob carol", "bob"]).apply("ann bob carol")).toBe("ANON_USER_1");
    expect(anon(["ann bob", "bob carol", "carol"]).apply("carol said: ann bob carol")).toBe(
      "ANON_USER_1 said: ANON_USER_2 ANON_USER_1",
    );
  });
});
