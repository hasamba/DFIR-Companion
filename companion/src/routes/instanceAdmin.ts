import type { Request } from "express";
import type { RouteContext } from "./context.js";

/**
 * True for the instance administrator, and for the one operator in single-user mode (#2945: the one
 * copy of a check five route files used to repeat).
 *
 * The session is looked up afresh rather than taken from the request's cached authentication: a route
 * may await before it asks (jobs waits for the job manager), and an administrator signed out,
 * disabled or demoted meanwhile must not still pass. A service token is never the administrator.
 */
export function isInstanceAdministrator(ctx: RouteContext, req: Request): boolean {
  const teamAuth = ctx.options.teamAuth;
  if (!teamAuth) return true;
  const auth = teamAuth.requireSession(req);
  return auth !== null && teamAuth.isGlobalAdministrator(auth);
}
