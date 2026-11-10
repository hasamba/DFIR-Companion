// A long-term access key issued by IAM `CreateAccessKey`, read for the credential lineage only
// (#2542). The STS issuance reader (awsIdentity.ts) also grades rows inside the importer, so a new
// action there would change every CreateAccessKey row's words and key; this reader feeds the
// lineage builder and nothing else.
//
// The record establishes the issuance only on a success whose response carries the new key id
// (`responseElements.accessKey.accessKeyId`). A failed call, or a response without the key (a
// redacted or truncated export), issues nothing here. The key is owned by the caller's account.

import { getCI, getPath, str } from "./siemImport.js";

type Row = Record<string, unknown>;

export const ACCESS_KEY_ISSUANCE_ACTION = "CreateAccessKey";

export interface AccessKeyIssuance {
  action: typeof ACCESS_KEY_ISSUANCE_ACTION;
  /** The new key's id, from the response. */
  issuedKey: string;
  /** The IAM user the key was created for, from the response (or the request). */
  userName: string;
}

/** The access key a successful IAM CreateAccessKey record issued, or null. */
export function readAccessKeyIssuance(rec: Row): AccessKeyIssuance | null {
  if (!/^iam\.amazonaws\.com$/i.test(str(getCI(rec, "eventSource")).trim())) return null;
  if (str(getCI(rec, "eventName")).trim() !== ACCESS_KEY_ISSUANCE_ACTION) return null;
  if (str(getCI(rec, "errorCode")).trim()) return null;
  const issuedKey = str(getPath(rec, "responseElements.accessKey.accessKeyId")).trim();
  if (!issuedKey) return null;
  const userName =
    str(getPath(rec, "responseElements.accessKey.userName")).trim() ||
    str(getPath(rec, "requestParameters.userName")).trim();
  return { action: ACCESS_KEY_ISSUANCE_ACTION, issuedKey, userName };
}
