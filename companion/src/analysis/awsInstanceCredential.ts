// EC2 instance-role credentials, recognised from structured CloudTrail fields only (#2545).
//
// An instance-role session is named after the instance id AND carries `ec2RoleDelivery`, which the
// service sets when it hands the credential to the instance (the importer reads it as the IMDSv1 /
// IMDSv2 protocol). Both are required: `RoleSessionName` is caller-chosen on AssumeRole, so a
// session named `i-…` alone is an attacker-chosen string. Descriptions are never re-parsed.
//
// One instance presents one egress address. The same instance credential used from TWO OR MORE
// different public addresses therefore means a second user holds it — that is the High. A single
// public address is the instance's NAT gateway or its own public IP far more often than a thief.

// Plain strings in, so the timeline pass (lowest tier) and the ingest-side lineage can both use it.
import { addressReach } from "./publicAddress.js";

/** An EC2 instance id, as the session name of an instance-role credential carries it. */
const INSTANCE_SESSION_RE = /^i-[0-9a-f]{8,17}$/i;
const INSTANCE_PROTOCOLS = new Set(["IMDSv1", "IMDSv2"]);
/** Distinct public addresses that make the spread a finding. */
export const INSTANCE_SPREAD_MIN = 2;
/** Distinct public addresses tracked per credential — the words name the count, never every one. */
const INSTANCE_ADDRESSES_MAX = 16;
export const INSTANCE_SPREAD_MITRE = ["T1552.005", "T1078.004"] as const;

/** The session part of an AWS principal id (`AROA…:session`) — the same rule `readAwsIdentity` uses. */
export function sessionOfPrincipalId(principalId: string): string {
  const id = (principalId ?? "").trim();
  return id.includes(":") ? id.slice(id.lastIndexOf(":") + 1) : "";
}

/** Both structured markers of an instance-role credential: the IMDS protocol and an instance-id session. */
export function isInstanceCredentialMarkers(
  principalType: string,
  protocol: string,
  session: string,
): boolean {
  return (
    principalType === "AssumedRole" && INSTANCE_PROTOCOLS.has(protocol) && INSTANCE_SESSION_RE.test(session)
  );
}

/** Record a public source address of an instance-role use into a bounded set; anything else is ignored. */
export function trackInstanceAddress(set: Set<string>, isInstance: boolean, address: string): void {
  if (set.size >= INSTANCE_ADDRESSES_MAX || !isInstance) return;
  const a = address.trim().toLowerCase();
  if (a && addressReach(a) === "public") set.add(a);
}

/** The clause a lineage row states when the spread is what graded it High. */
export function instanceSpreadWords(addresses: ReadonlySet<string>): string {
  const n = addresses.size >= INSTANCE_ADDRESSES_MAX ? `${INSTANCE_ADDRESSES_MAX}+` : String(addresses.size);
  return (
    `this EC2 instance credential was used from ${n} different public addresses; one instance presents one ` +
    "egress address, so a second holder has the credential (confirm against the instance's NAT or public address)"
  );
}
