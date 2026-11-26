import type { Request } from "express";
import { describe, expect, it } from "vitest";
import { setRequestAuthentication, type RequestAuthentication } from "../../src/auth/types.js";
import type { RouteContext } from "../../src/routes/context.js";
import { isInstanceAdministrator } from "../../src/routes/instanceAdmin.js";

// #2945: one shared "is this the instance administrator?" check for every route that asks.

const session = (globalRole: "administrator" | "member") =>
  ({ kind: "session", identity: { id: "u1", globalRole } }) as unknown as RequestAuthentication;

function ctxWith(fresh: RequestAuthentication | null): RouteContext {
  const teamAuth = {
    requireSession: () => fresh,
    isGlobalAdministrator: (a: RequestAuthentication) =>
      a.kind === "session" && a.identity.globalRole === "administrator",
  };
  return { options: { teamAuth } } as unknown as RouteContext;
}

describe("isInstanceAdministrator (#2945)", () => {
  it("is true for the one operator in single-user mode", () => {
    expect(isInstanceAdministrator({ options: {} } as unknown as RouteContext, {} as Request)).toBe(true);
  });

  it("answers from a fresh session lookup: administrator yes, member no, none no", () => {
    expect(isInstanceAdministrator(ctxWith(session("administrator")), {} as Request)).toBe(true);
    expect(isInstanceAdministrator(ctxWith(session("member")), {} as Request)).toBe(false);
    expect(isInstanceAdministrator(ctxWith(null), {} as Request)).toBe(false);
  });

  it("does not trust the request's cached authentication once the session is gone", () => {
    const req = {} as Request;
    setRequestAuthentication(req, session("administrator")); // authenticated before an await
    expect(isInstanceAdministrator(ctxWith(null), req)).toBe(false); // signed out / disabled since
    expect(isInstanceAdministrator(ctxWith(session("member")), req)).toBe(false); // demoted since
  });
});
