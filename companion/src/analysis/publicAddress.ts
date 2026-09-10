// Is a source address outside the network, or inside it — and can that be answered at all?
//
// Both cloud passes (#908 items 7 and 8) raise a finding when activity came from an address the
// workload should not have. Each had grown its own private-range table, and both had the same
// defect: a TWO-state answer. An address they could not parse — every IPv6 address, and the
// `::ffff:203.0.113.9` form a dual-stack proxy logs — came back as "not public", which the caller
// then reported as "the source was inside the network". That is an absence presented as a result,
// which is the one thing these findings exist to avoid.
//
// So the answer is three-state and "unreadable" is a value the caller has to handle.
//
// ─────────────────────────── WHY THE RANGES ARE COPIED, NOT IMPORTED ───────────────────────────
//
// `iocValue.ts` has the same table and so do `internalIp.ts`, `urlValidation.ts` and
// `anonymize.ts`. Importing one of those from here would reach UP a layer, which the boundary check
// rejects — so this is the repository's existing pattern, not a new exception: each layer keeps its
// own copy and a test pins it. The CGNAT and link-local rows are the ones that drift, so they are
// the ones the tests name. Change one table and change them all.

export type AddressReach = "public" | "private" | "unreadable";

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Private, internal and link-local IPv4 ranges.
 *
 * 10/8, 172.16/12, 192.168/16, 127/8, 0/8, 169.254/16 (link-local and cloud metadata),
 * 100.64/10 (carrier-grade NAT). Kept in lockstep with iocValue.ts and internalIp.ts.
 */
function isPrivateV4(a: number, b: number): boolean {
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

/** Expand an IPv6 address to its eight groups, honouring `::`. Returns null when it is not one. */
export function ipv6Groups(address: string): number[] | null {
  const raw = address.trim().toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(raw) || !raw.includes(":")) return null;
  if ((raw.match(/::/g) ?? []).length > 1) return null;

  // A trailing dotted-decimal tail (::ffff:203.0.113.9) becomes two hex groups.
  let head = raw;
  const tail: number[] = [];
  const dotted = /:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(raw);
  if (dotted) {
    const octets = dotted[1].split(".").map(Number);
    if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
    tail.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
    // Keep the separating colon. Dropping it turned "::10.0.0.1" into ":" — the "::" was gone, so
    // the compressed form no longer parsed and an IPv4-compatible loopback read as unreadable.
    head = raw.slice(0, raw.length - dotted[1].length);
  }

  const [left, right] = head.includes("::") ? head.split("::") : [head, null];
  const leftParts = left ? left.split(":").filter(Boolean) : [];
  const rightParts = right ? right.split(":").filter(Boolean) : [];
  const parsed = (parts: string[]): number[] | null => {
    const out: number[] = [];
    for (const part of parts) {
      if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
      out.push(parseInt(part, 16));
    }
    return out;
  };
  const l = parsed(leftParts);
  const r = parsed(rightParts);
  if (!l || !r) return null;

  const known = l.length + r.length + tail.length;
  if (right === null) return known === 8 ? [...l, ...tail] : null;
  if (known > 7) return null;
  return [...l, ...Array<number>(8 - known).fill(0), ...r, ...tail];
}

function isPrivateV6(groups: number[]): boolean {
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;
  if (groups.every((g) => g === 0)) return true; // ::
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 1)
    return true; // ::1
  if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) carry an embedded address.
  const embedded = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;
  if (embedded && (g5 === 0xffff || g5 === 0)) return isPrivateV4((g6 >> 8) & 0xff, g6 & 0xff);
  return false;
}

/** Where an address sits, or that it could not be read. */
export function addressReach(address: string): AddressReach {
  const raw = (address ?? "").trim().replace(/^\[|\]$/g, "");
  if (!raw) return "unreadable";

  const v4 = IPV4_RE.exec(raw);
  if (v4) {
    const octets = v4.slice(1).map(Number);
    // Every octet must be a real octet. "999.1.1.1" is not an address, and calling it public would
    // put a fabricated "from outside the network" claim on a finding.
    if (octets.some((o) => o > 255)) return "unreadable";
    return isPrivateV4(octets[0], octets[1]) ? "private" : "public";
  }

  const groups = ipv6Groups(raw);
  if (groups) return isPrivateV6(groups) ? "private" : "public";
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
