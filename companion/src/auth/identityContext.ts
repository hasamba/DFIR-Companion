import { AsyncLocalStorage } from "node:async_hooks";
import type { AuthIdentity } from "./types.js";

const identityContext = new AsyncLocalStorage<AuthIdentity>();

export function runWithIdentity<T>(identity: AuthIdentity, fn: () => T): T {
  return identityContext.run(identity, fn);
}

/**
 * Run `fn` with no request identity, so what it audits names its own `actor` instead of the analyst
 * whose request (or timer) started it. Watson's Auto actions use it: they are Watson's, not the
 * analyst's.
 */
export function runWithoutIdentity<T>(fn: () => T): T {
  return identityContext.exit(fn);
}

export function currentIdentity(): AuthIdentity | undefined {
  return identityContext.getStore();
}

export interface AuthenticatedActorFields {
  actorId: string;
  actorDisplayName: string;
  actorKind: AuthIdentity["kind"];
}

export function authenticatedActorFields(): AuthenticatedActorFields | undefined {
  const identity = currentIdentity();
  if (!identity) return undefined;
  return {
    actorId: identity.id,
    actorDisplayName: identity.displayName,
    actorKind: identity.kind,
  };
}
