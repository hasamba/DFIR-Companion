// The GCP audit method -> severity/MITRE table (#931 item 12), shared by the per-record importer
// (cloudActivityImport.ts) and the per-service-account join (gcpServiceAccountJoin.ts, #1065) so a
// call's grade is read once from one table, never recomputed with a second copy that could drift.

import type { Severity } from "./stateTypes.js";

export type GcpRule = [RegExp, Severity, string[]];

// GCP audit methodName patterns (prefixes vary — v1./beta./google.iam.admin.v1. — so match
// on the distinctive verb/resource fragment).
export const GCP_RULES: GcpRule[] = [
  [/createserviceaccountkey/, "High", ["T1098.001"]],
  [/createserviceaccount\b/, "Medium", ["T1136"]],
  [/(create|update).*\brole\b/, "Medium", ["T1098.003"]],
  [/firewalls?\.(insert|patch|update)/, "Medium", ["T1562.007"]],
  [/sinks?\.(delete|update)|logentries.*delete/, "High", ["T1562.008"]],
  [/accesssecretversion/, "Medium", ["T1552.001"]],
  [/(snapshots|images|disks)\.(insert|setiampolicy)/, "High", ["T1537"]],
  [/instances\.insert/, "Low", ["T1578.002"]],
  [/storage\.objects\.(get|list)/, "Info", []],
  [/\.delete$/, "Medium", []],
];

export function matchGcpRule(method: string): { severity: Severity; mitre: string[] } | null {
  const k = method.toLowerCase();
  for (const [re, severity, mitre] of GCP_RULES) if (re.test(k)) return { severity, mitre };
  return null;
}
