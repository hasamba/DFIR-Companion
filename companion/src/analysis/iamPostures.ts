import type { Severity } from "./stateTypes.js";

// The IAM posture table (#931 item 6): one entry per IAM call the decoder narrates — the verb
// (present tense for a success, the infinitive after "attempted to" for a failure), the request
// fields that identify the object, the document field, the qualifier and note the record needs,
// and the floor a SUCCESS supplies. Every IAM entry of the importer's action table has an entry
// here; a test enforces it. A verb is what the call DOES — never which way access moved.

export interface Posture {
  id: string;
  verb: string;
  infinitive: string;
  fields: string[];
  docField?: string;
  qualifier?: string;
  note?: string;
  floor?: Severity;
  mitre?: string[];
}

const PREVIOUS_NOTE = "previous document not in this record";
const MANAGED_NOTE = "— its document and version are not in this record";
const GROUP_NOTE = "— the group's policies are not in this record";

// The object tuple: request field → label. Lowercased ARNs and names in the key; the display shows
// a policy ARN by its name.
export const FIELD_LABELS: Record<string, string> = {
  userName: "user",
  roleName: "role",
  groupName: "group",
  policyArn: "policy",
  policyName: "policyName",
  versionId: "version",
  instanceProfileName: "profile",
  accessKeyId: "accessKeyId",
  serialNumber: "serial",
  permissionsBoundary: "boundary",
  setAsDefault: "setAsDefault",
  status: "status",
};
const P = (
  id: string,
  verb: string,
  infinitive: string,
  fields: string[],
  extra: Partial<Posture> = {},
): Posture => ({ id, verb, infinitive, fields, ...extra });
const PROFILE_BIND: Posture = P(
  "bind-role-to-profile",
  "binds role to instance profile",
  "bind role to instance profile",
  ["roleName", "instanceProfileName"],
  { floor: "Medium", mitre: ["T1098"] },
);

export const POSTURES: Record<string, Posture> = {
  attachuserpolicy: P(
    "attach-policy",
    "attaches managed policy",
    "attach managed policy",
    ["userName", "policyArn"],
    { note: MANAGED_NOTE },
  ),
  attachrolepolicy: P(
    "attach-policy",
    "attaches managed policy",
    "attach managed policy",
    ["roleName", "policyArn"],
    { note: MANAGED_NOTE },
  ),
  attachgrouppolicy: P(
    "attach-policy",
    "attaches managed policy",
    "attach managed policy",
    ["groupName", "policyArn"],
    { note: MANAGED_NOTE },
  ),
  detachuserpolicy: P(
    "detach-policy",
    "detaches managed policy",
    "detach managed policy",
    ["userName", "policyArn"],
    { note: MANAGED_NOTE },
  ),
  detachrolepolicy: P(
    "detach-policy",
    "detaches managed policy",
    "detach managed policy",
    ["roleName", "policyArn"],
    { note: MANAGED_NOTE },
  ),
  detachgrouppolicy: P(
    "detach-policy",
    "detaches managed policy",
    "detach managed policy",
    ["groupName", "policyArn"],
    { note: MANAGED_NOTE },
  ),
  putuserpolicy: P(
    "put-inline-policy",
    "replaces inline policy",
    "replace inline policy",
    ["userName", "policyName"],
    { docField: "policyDocument", qualifier: PREVIOUS_NOTE },
  ),
  putrolepolicy: P(
    "put-inline-policy",
    "replaces inline policy",
    "replace inline policy",
    ["roleName", "policyName"],
    { docField: "policyDocument", qualifier: PREVIOUS_NOTE },
  ),
  putgrouppolicy: P(
    "put-inline-policy",
    "replaces inline policy",
    "replace inline policy",
    ["groupName", "policyName"],
    { docField: "policyDocument", qualifier: PREVIOUS_NOTE },
  ),
  deleteuserpolicy: P("delete-inline-policy", "deletes inline policy", "delete inline policy", [
    "userName",
    "policyName",
  ]),
  deleterolepolicy: P("delete-inline-policy", "deletes inline policy", "delete inline policy", [
    "roleName",
    "policyName",
  ]),
  deletegrouppolicy: P("delete-inline-policy", "deletes inline policy", "delete inline policy", [
    "groupName",
    "policyName",
  ]),
  createpolicy: P("create-policy", "creates policy", "create policy", ["policyName"], {
    docField: "policyDocument",
    floor: "Medium",
    mitre: ["T1098.003"],
  }),
  deletepolicy: P("delete-policy", "deletes policy", "delete policy", ["policyArn"]),
  createpolicyversion: P(
    "add-policy-version",
    "adds policy version",
    "add policy version",
    ["policyArn", "setAsDefault"],
    { docField: "policyDocument" },
  ),
  setdefaultpolicyversion: P(
    "activate-policy-version",
    "activates policy version",
    "activate policy version",
    ["policyArn", "versionId"],
    { note: "— its document is not in this record" },
  ),
  deletepolicyversion: P(
    "delete-policy-version",
    "deletes non-default policy version",
    "delete policy version",
    ["policyArn", "versionId"],
    { note: "— current access unchanged" },
  ),
  addusertogroup: P("add-to-group", "adds user to group", "add user to group", ["userName", "groupName"], {
    note: GROUP_NOTE,
  }),
  removeuserfromgroup: P("remove-from-group", "removes user from group", "remove user from group", [
    "userName",
    "groupName",
  ]),
  createaccesskey: P("create-access-key", "creates access key", "create access key", ["userName"]),
  deleteaccesskey: P("delete-access-key", "deletes access key", "delete access key", [
    "userName",
    "accessKeyId",
  ]),
  updateaccesskey: P("update-access-key", "updates access key", "update access key", [
    "userName",
    "accessKeyId",
    "status",
  ]),
  createloginprofile: P("create-login", "creates console password", "create console password", ["userName"]),
  deleteloginprofile: P("delete-login", "deletes console password", "delete console password", ["userName"]),
  updateloginprofile: P("reset-login", "resets console password", "reset console password", ["userName"]),
  putuserpermissionsboundary: P("set-boundary", "sets permissions boundary", "set permissions boundary", [
    "userName",
    "permissionsBoundary",
  ]),
  putrolepermissionsboundary: P("set-boundary", "sets permissions boundary", "set permissions boundary", [
    "roleName",
    "permissionsBoundary",
  ]),
  deleteuserpermissionsboundary: P(
    "remove-boundary",
    "removes permissions boundary",
    "remove permissions boundary",
    ["userName"],
    { note: "— may increase permissions", floor: "High", mitre: ["T1098.003"] },
  ),
  deleterolepermissionsboundary: P(
    "remove-boundary",
    "removes permissions boundary",
    "remove permissions boundary",
    ["roleName"],
    { note: "— may increase permissions", floor: "High", mitre: ["T1098.003"] },
  ),
  updateassumerolepolicy: P("replace-trust", "replaces trust policy", "replace trust policy", ["roleName"], {
    docField: "policyDocument",
    qualifier: PREVIOUS_NOTE,
  }),
  createrole: P(
    "create-role",
    "creates role with trust policy",
    "create role with trust policy",
    ["roleName"],
    { docField: "assumeRolePolicyDocument" },
  ),
  createuser: P("create-user", "creates user", "create user", ["userName"]),
  deleterole: P("delete-role", "deletes role", "delete role", ["roleName"]),
  deleteuser: P("delete-user", "deletes user", "delete user", ["userName"]),
  deactivatemfadevice: P("deactivate-mfa", "deactivates MFA device", "deactivate MFA device", [
    "userName",
    "serialNumber",
  ]),
  deletevirtualmfadevice: P("delete-mfa", "deletes virtual MFA device", "delete virtual MFA device", [
    "serialNumber",
  ]),
  addroletoinstanceprofile: PROFILE_BIND,
};

// Identities the RESPONSE creates — the request cannot hold them.
export const RESPONSE_FIELDS: Record<string, Array<[string, string[]]>> = {
  createaccesskey: [["accessKeyId", ["accessKey", "accessKeyId"]]],
  createpolicyversion: [["version", ["policyVersion", "versionId"]]],
  createrole: [["roleId", ["role", "roleId"]]],
  createuser: [["userId", ["user", "userId"]]],
  createpolicy: [["policy", ["policy", "arn"]]],
};
