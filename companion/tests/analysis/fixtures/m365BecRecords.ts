// Synthetic M365 records for the BEC pairings (#2550, #2570): an Exchange inbox-rule cmdlet record
// (RecordType 1) and an Entra directory change exported through the UAL (RecordType 8), in the
// shapes the Invictus dataset uses. Reserved domains only.

type Rec = Record<string, unknown>;

export const T0 = Date.parse("2024-05-01T10:00:00Z");
export const at = (minutes: number): string =>
  new Date(T0 + minutes * 60_000).toISOString().replace(".000Z", "");

let seq = 0;

export const ex = (op: string, params: Record<string, string>, minutes: number, over: Rec = {}): Rec => ({
  Id: `ex-${++seq}`,
  CreationTime: at(minutes),
  Workload: "Exchange",
  RecordType: 1,
  Operation: op,
  OrganizationId: "tenant-1",
  UserType: 2,
  UserId: "alice@tenant.invalid",
  ObjectId: `alice\\${params.Name ?? ""}`,
  ResultStatus: "True",
  ClientIP: "203.0.113.9",
  Parameters: Object.entries(params).map(([Name, Value]) => ({ Name, Value })),
  ...over,
});

export const forwardOut = (minutes: number, over: Rec = {}): Rec =>
  ex(
    "New-InboxRule",
    { Name: "Fin", BodyContainsWords: "Invoice", ForwardTo: "drop@outside.invalid" },
    minutes,
    over,
  );

export const deleter = (minutes: number, over: Rec = {}): Rec =>
  ex("New-InboxRule", { Name: "", BodyContainsWords: "drop", DeleteMessage: "True" }, minutes, over);

export const aad = (
  op: string,
  minutes: number,
  target: { id: string; upn: string },
  props: Rec[] = [],
  over: Rec = {},
): Rec => ({
  Id: `aad-${++seq}`,
  CreationTime: at(minutes),
  Workload: "AzureActiveDirectory",
  RecordType: 8,
  Operation: op,
  ResultStatus: "Success",
  OrganizationId: "tenant-1",
  UserType: 0,
  UserId: "admin@tenant.invalid",
  ObjectId: target.upn,
  Actor: [
    { ID: "admin@tenant.invalid", Type: 5 },
    { ID: "User", Type: 2 },
  ],
  Target: [
    { ID: `User_${target.id}`, Type: 2 },
    { ID: target.id, Type: 2 },
    { ID: "User", Type: 2 },
    { ID: target.upn, Type: 5 },
  ],
  ModifiedProperties: props,
  ...over,
});

export const NEW_USER = { id: "11111111-2222-4333-8444-555555555555", upn: "newbie@tenant.invalid" };

const role = (name: string, templateId: string): Rec[] => [
  { Name: "Role.DisplayName", NewValue: name, OldValue: "" },
  { Name: "Role.TemplateId", NewValue: templateId, OldValue: "" },
];
export const EXCHANGE_ADMIN = role("Exchange Administrator", "29232cdf-9323-42fd-ade2-1d097af3e4de");

export const addUser = (minutes: number, over: Rec = {}): Rec =>
  aad("Add user.", minutes, NEW_USER, [], over);
export const grantAdmin = (minutes: number, over: Rec = {}): Rec =>
  aad("Add member to role.", minutes, NEW_USER, EXCHANGE_ADMIN, over);

/** A record no pairing reads: a sign-in by another user. */
export const filler = (minutes: number): Rec => ({
  Id: `fill-${++seq}`,
  CreationTime: at(minutes),
  Workload: "AzureActiveDirectory",
  RecordType: 15,
  Operation: "UserLoggedIn",
  OrganizationId: "tenant-1",
  UserType: 0,
  UserId: `filler${seq}@tenant.invalid`,
  ClientIP: "192.0.2.10",
  ResultStatus: "Success",
});

/** Which pairing row a forensic row is, by its stable description head, or "". */
export function pairRole(description: string): "hide" | "forward" | "grant" | "created" | "" {
  if (description.includes('creates inbox rule ""')) return "hide";
  if (description.includes('creates inbox rule "Fin"')) return "forward";
  if (/assigns directory role/.test(description)) return "grant";
  if (/Add user/.test(description)) return "created";
  return "";
}
