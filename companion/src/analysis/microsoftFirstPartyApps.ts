import type { Severity } from "./stateTypes.js";
import { KNOWN_APIS } from "./entraCapabilities.js";

// Microsoft first-party BACKEND services, by immutable application id (#2549). When one of these
// acts app-only (no signed-in user) to add or update a service principal, it is Microsoft's own
// provisioning — the Service Management API creating a managed identity, Intune or Device
// Registration refreshing its principal — not a tenant admin's change. The importer grades those
// rows Low instead of the High the operation table gives a service-principal change.
//
// Keyed on the app id only: an application's display name is chosen freely by whoever registers it,
// and an app id is assigned by Entra and global. PUBLIC CLIENTS ARE NEVER LISTED — Azure CLI, Azure
// PowerShell, Microsoft Office, Graph Explorer, Graph Command Line Tools — because they are what an
// attacker drives with a stolen token. Add an id here only for a backend service whose app-only
// activity has been seen in a real export or is in Microsoft's published first-party list.
export const MICROSOFT_FIRST_PARTY_SERVICES: ReadonlySet<string> = new Set([
  ...Object.keys(KNOWN_APIS),
  "797f4846-ba00-4fd7-ba43-dac1f8f63013", // Windows Azure Service Management API
  "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9", // Device Registration Service
  "0000000a-0000-0000-c000-000000000000", // Microsoft Intune
  "f0ae4899-d877-4d3c-ae25-679e38eea492", // AAD App Management
]);

/** True for an app id in the curated first-party backend-service list (case-insensitive). */
export const isMicrosoftFirstPartyService = (appId: string): boolean =>
  MICROSOFT_FIRST_PARTY_SERVICES.has(appId.trim().toLowerCase());

// Only adding or updating the principal itself — never its credentials, owners or app-role grants.
const SP_PROVISIONING = /^(?:add|update) service principal\.?$/i;
export const isSpProvisioningOperation = (operation: string): boolean =>
  SP_PROVISIONING.test(operation.trim());

/**
 * `Certificate` is the UserId the unified audit log gives Microsoft's internal certificate-
 * authenticated service actors (Entra JIT provisioning, Microsoft Online Services). A row that has
 * only that column to go on — its AuditData empty — is still graded Low for an SP add/update.
 */
export const INTERNAL_CERTIFICATE_ACTOR = "Certificate";
/** The grade for Microsoft's own provisioning: Low (kept in the forensic timeline), no technique. */
export const FIRST_PARTY_UPKEEP: Readonly<{ severity: Severity; mitre: string[] }> = Object.freeze({
  severity: "Low",
  mitre: [],
});
export const isInternalCertificateSpChange = (operation: string, user: string): boolean =>
  user.trim() === INTERNAL_CERTIFICATE_ACTOR && isSpProvisioningOperation(operation);
