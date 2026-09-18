import type { AuthStore } from "../../src/auth/authStore.js";
import type { ServicePermission } from "../../src/auth/types.js";

/**
 * Provisions a real, storage-backed service token for HTTP tests that need to prove a route's own
 * authenticated-but-non-human rejection path — every existing "team-auth on" route test only ever
 * sends a request with no session at all, which the upstream session gate rejects with 401 before
 * the route's own humanIdentityFor() check (and its 403 branch) ever runs (#1169). Bootstraps a
 * throwaway administrator identity purely as the audit-log actor createServiceToken requires; the
 * returned token is what a real caller would send as `Authorization: Bearer <token>`.
 */
export async function provisionServiceToken(
  store: AuthStore,
  caseId: string,
  permissions: ServicePermission[] = ["write"],
): Promise<string> {
  const admin = await store.bootstrapLocalAdministrator({
    username: "svc-bootstrap",
    displayName: "svc-bootstrap",
    password: "provision-only-not-a-real-credential-1",
  });
  const { token } = store.createServiceToken({ name: "test-service-token", caseId, permissions }, admin);
  return token;
}
