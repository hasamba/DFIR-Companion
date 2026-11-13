// Security-group ingress rules as one CloudTrail request states them (#2605). Shared by the import
// row (awsExposure.ts — the rule on its own row) and the compute lifecycle (awsCompute.ts — the rule
// joined to an instance that holds the group), so both read the same thing.
//
// CloudTrail records two request forms: the `ipPermissions.items` form, and the legacy top-level
// form (`ipProtocol` / `fromPort` / `toPort` / `cidrIp` / `cidrIpv6` / `sourceSecurityGroupName`,
// recorded with an empty `ipPermissions: {}`). Both are read. "Any address" is a prefix length of 0
// for IPv4 or IPv6 — `x.x.x.x/0` covers every address whatever the host bits say. What the reading
// never says: whether the rule was already present, or what the group allowed before. Pure.

import { isIP } from "node:net";
import { getCI, isObject, str } from "./siemImport.js";
import { show } from "./loggingChange.js";

type Row = Record<string, unknown>;
const LIST_MAX = 3;

export interface Permission {
  protocol: string;
  ports: string;
  source: string;
  anySource: boolean;
}

const field = (o: unknown, key: string): string => (isObject(o) ? str(getCI(o, key)).trim() : "");
/** A CloudTrail set: `{ items: [...] }` or a bare array — its object items. */
const items = (v: unknown): Row[] => {
  const list = Array.isArray(v) ? v : isObject(v) ? getCI(v, "items") : undefined;
  return Array.isArray(list) ? list.filter(isObject) : [];
};

/**
 * True for a CIDR whose prefix length is 0 (IPv4 or IPv6): it covers every address. The address side
 * must be a real IP (#2625) — a malformed, truncated or tampered source with a `/0` suffix is read as
 * its literal text, never as "any address". Whether the family matches its field (an IPv6 address in
 * `cidrIp`) is not checked: this proves the source is an address, not that the request was valid.
 */
export function isAnyAddress(cidr: string): boolean {
  const m = /^([0-9a-f:.]+)\/(\d+)$/i.exec(cidr.trim());
  return m !== null && Number(m[2]) === 0 && isIP(m[1]) !== 0;
}

function protocolOf(p: Row): { protocol: string; ports: string } {
  const proto = field(p, "ipProtocol");
  const from = field(p, "fromPort");
  const to = field(p, "toPort");
  return {
    protocol: proto === "-1" ? "all protocols" : proto || "protocol not recorded",
    ports: from && to && from !== to ? `${from}-${to}` : from || to,
  };
}

/** The sources of one permission (items form) or of the top-level request (legacy form). */
function sourcesOf(p: Row, legacy: boolean): { source: string; any: boolean }[] {
  const cidr = (v: string) => (v ? [{ source: v, any: isAnyAddress(v) }] : []);
  if (legacy) {
    const group = field(p, "sourceSecurityGroupName") || field(p, "sourceSecurityGroupId");
    const owner = field(p, "sourceSecurityGroupOwnerId");
    return [
      ...cidr(field(p, "cidrIp")),
      ...cidr(field(p, "cidrIpv6")),
      ...(group ? [{ source: `group ${group}${owner ? ` (owner ${owner})` : ""}`, any: false }] : []),
    ];
  }
  return [
    ...items(getCI(p, "ipRanges")).flatMap((r) => cidr(field(r, "cidrIp"))),
    ...items(getCI(p, "ipv6Ranges")).flatMap((r) => cidr(field(r, "cidrIpv6"))),
    ...items(getCI(p, "groups")).map((g) => ({
      source: `group ${field(g, "groupId") || field(g, "groupName")}${field(g, "userId") ? ` (owner ${field(g, "userId")})` : ""}`,
      any: false,
    })),
    ...items(getCI(p, "prefixListIds")).map((l) => ({
      source: `prefix list ${field(l, "prefixListId")}`,
      any: false,
    })),
  ];
}

/** Every (permission, source) pair of an ingress request: the first few retained, ALL read for the any-source fact. */
export function ingressPermissions(
  request: unknown,
  max: number,
): { retained: Permission[]; anySource: boolean; total: number } {
  if (!isObject(request)) return { retained: [], anySource: false, total: 0 };
  const forms: { p: Row; legacy: boolean }[] = [
    ...items(getCI(request, "ipPermissions")).map((p) => ({ p, legacy: false })),
    { p: request, legacy: true },
  ];
  const all = forms.flatMap(({ p, legacy }) => {
    const proto = protocolOf(p);
    return sourcesOf(p, legacy).map((s) => ({ ...proto, source: s.source, anySource: s.any }));
  });
  return { retained: all.slice(0, max), anySource: all.some((p) => p.anySource), total: all.length };
}

const permissionWords = (p: Permission): string =>
  `${show(p.protocol, 20)}${p.ports ? ` ${show(p.ports, 20)}` : ""} from ${show(p.source, 60)}${p.anySource ? " (any address)" : ""}`;

/** The rule an Authorize/RevokeSecurityGroupIngress request states, or "" for any other call or service. */
export function securityGroupRuleReading(eventName: string, eventSource: string, request: unknown): string {
  const n = eventName.toLowerCase();
  const verb = (
    { authorizesecuritygroupingress: "opens", revokesecuritygroupingress: "removes from" } as const
  )[n];
  if (!verb || !/^ec2(\.amazonaws\.com)?$/i.test(eventSource.trim()) || !isObject(request)) return "";
  const perms = ingressPermissions(request, Number.POSITIVE_INFINITY);
  if (!perms.total) return "";
  const group = show(field(request, "groupId") || field(request, "groupName") || "?", 60);
  // Any-address sources first, so the bounded list never hides the one that matters.
  const ordered = [
    ...perms.retained.filter((p) => p.anySource),
    ...perms.retained.filter((p) => !p.anySource),
  ];
  const more = perms.total > LIST_MAX ? ` (+${perms.total - LIST_MAX} more)` : "";
  const words = ordered.slice(0, LIST_MAX).map(permissionWords).join(", ") + more;
  return verb === "opens" ? `opens ${group} to ${words}` : `removes from ${group} ${words}`;
}
