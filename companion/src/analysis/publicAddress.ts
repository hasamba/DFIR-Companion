// Is a source address outside the network, or inside it — and can that be answered at all?
//
// Both cloud passes (#908 items 7 and 8) raise a finding when activity came from an address the
// workload should not have. Each grew its own private-range table, and both had the same defect:
// a two-state answer. An address they could not parse — every IPv6 address, and the
// `::ffff:203.0.113.9` form a dual-stack proxy logs — came back as "not public", which the caller
// then reported as "the source was inside the network". That is an absence presented as a result,
// which is the one thing these findings are written to avoid.
//
// So the answer is three-state, the ranges come from the repository's existing table rather than a
// third copy, and "unreadable" is a value the caller has to handle.

import { isInternalTarget } from "./iocValue.js";

export type AddressReach = "public" | "private" | "unreadable";

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6_HINT_RE = /^[0-9a-f:]+$|^\[[0-9a-f:.]+\]$/i;

/** Where an address sits, or that it could not be read. */
export function addressReach(address: string): AddressReach {
  const raw = (address ?? "").trim().replace(/^\[|\]$/g, "");
  if (!raw) return "unreadable";

  const v4 = IPV4_RE.exec(raw);
  if (v4) {
    // Every octet must be a real octet. "999.1.1.1" is not an address, and calling it public would
    // put a fabricated "from outside the network" claim on a finding.
    if (v4.slice(1).some((o) => Number(o) > 255)) return "unreadable";
    return isInternalTarget(raw) ? "private" : "public";
  }

  if (raw.includes(":") && IPV6_HINT_RE.test(raw)) {
    // isInternalTarget handles ::1, fc00::/7, fe80::/10 and the IPv4-mapped forms. Anything it does
    // not recognise as internal but that IS a well-formed address is public.
    if (isInternalTarget(raw)) return "private";
    return /^(?:[0-9a-f]{0,4}:){2,7}[0-9a-f.]{0,39}$/i.test(raw) ? "public" : "unreadable";
  }

  return "unreadable";
}

/** Words for a finding, so "we could not read it" never reads as "it was internal". */
export function reachPhrase(address: string, reach: AddressReach): string {
  if (reach === "public") return `${address}, an address outside the network`;
  if (reach === "private") return `${address}, an internal address`;
  return address
    ? `${address}, which could not be read as an address`
    : "an address the evidence did not record";
}
