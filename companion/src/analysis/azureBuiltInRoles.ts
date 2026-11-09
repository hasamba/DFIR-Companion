// Azure built-in role definition guid → display name. Every guid was checked against Microsoft
// Learn, "Azure built-in roles" (learn.microsoft.com/azure/role-based-access-control/built-in-roles),
// on 2026-11-09. Built-in role guids are the same in every tenant, so a role assignment record that
// carries only `roleDefinitions/<guid>` can be named without a call to the tenant. The list holds
// the privileged roles and the roles an intruder commonly grants; anything else is shown as
// "custom or unlisted role <guid>" by the caller — never guessed.

export const AZURE_BUILT_IN_ROLES: Readonly<Record<string, string>> = Object.freeze({
  // Privileged
  "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
  "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
  "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
  "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
  // General
  "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
  // Key Vault
  "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
  "b86a8fe4-44ce-4948-aee5-eccb2c155cd7": "Key Vault Secrets Officer",
  "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
  "14b46e9e-c2b7-41b4-b07b-48a6ebf60603": "Key Vault Crypto Officer",
  // Storage
  "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "Storage Blob Data Owner",
  "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
  "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": "Storage Blob Data Reader",
  "17d1049b-9a84-46fb-8f53-869881c3d3ab": "Storage Account Contributor",
  // Compute
  "9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "Virtual Machine Contributor",
  "1c0163c0-47e6-4577-8991-ea5c82e286e4": "Virtual Machine Administrator Login",
  "fb879df8-f326-4884-b1cf-06f3ad86be52": "Virtual Machine User Login",
  // Identity
  "f1a07417-d97a-45cb-824c-7a7467783830": "Managed Identity Operator",
  "e40ec5ca-96e0-45a2-b4ff-59039f2c2b59": "Managed Identity Contributor",
  // Management, monitoring, security
  "f353d9bd-d4a6-484e-a77a-8050b599b867": "Automation Contributor",
  "92aaf0da-9dab-42b6-94a3-d43ce8d16293": "Log Analytics Contributor",
  "749f88d5-cbae-40b8-bcfc-e573ddc772fa": "Monitoring Contributor",
  "fb1c8493-542b-48eb-b624-b4c8fea62acd": "Security Admin",
});

/** The built-in role's name for a definition guid (any case), or undefined when not listed. */
export function azureRoleName(guid: string): string | undefined {
  const k = guid.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(AZURE_BUILT_IN_ROLES, k) ? AZURE_BUILT_IN_ROLES[k] : undefined;
}
