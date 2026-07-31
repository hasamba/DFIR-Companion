import { AsyncLocalStorage } from "node:async_hooks";
import type { AuthIdentity } from "./types.js";

const identityContext = new AsyncLocalStorage<AuthIdentity>();

export function runWithIdentity<T>(identity: AuthIdentity, fn: () => T): T {
  return identityContext.run(identity, fn);
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
