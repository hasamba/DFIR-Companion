// Cloud-provider JSON signatures, moved out of importDetect.ts (#1294) when that file reached the
// 800-line cap. Order is load-bearing only in the sense that a flow-log record must be claimed
// BEFORE the activity/audit catch-alls: an Azure flow record carries `operationName` (but never
// `caller`/`resourceId`/`correlationId`), and a GCP flow entry carries `logName` (but never
// `protoPayload` or a `cloudaudit` log name) — so today neither catch-all would claim them, and
// tests pin that the reverse never happens either (a flow predicate never claims an activity,
// audit or storage fixture).

import { getCI, str } from "./siemImport.js";
import { isAzureStorageLog } from "./azureStorageLogImport.js";
import { isAzureFlowLogUpload } from "./azureFlowLogImport.js";
import { isGcpFlowLogEntry } from "./gcpFlowLogImport.js";

type Row = Record<string, unknown>;

export type CloudJsonKind = "azureflowlog" | "gcpflowlog" | "aws" | "cloud" | "azurestoragelog";

export function isAws(s: Row): boolean {
  return !!getCI(s, "eventName") && !!getCI(s, "eventSource");
}
export function isGcp(s: Row): boolean {
  return !!getCI(s, "protoPayload") || /cloudaudit/i.test(str(getCI(s, "logName")));
}
export function isAzure(s: Row): boolean {
  return (
    (!!getCI(s, "operationName") || !!getCI(s, "OperationNameValue") || !!getCI(s, "OperationName")) &&
    (!!getCI(s, "caller") ||
      !!getCI(s, "Caller") ||
      !!getCI(s, "resourceId") ||
      !!getCI(s, "ResourceId") ||
      !!getCI(s, "correlationId"))
  );
}

export function detectCloudJson(root: unknown, sample: Row): CloudJsonKind | null {
  if (isAzureFlowLogUpload(root, sample)) return "azureflowlog";
  if (isGcpFlowLogEntry(sample)) return "gcpflowlog";
  if (isAws(sample)) return "aws";
  if (isGcp(sample)) return "cloud";
  if (isAzureStorageLog(sample)) return "azurestoragelog";
  if (isAzure(sample)) return "cloud";
  return null;
}
