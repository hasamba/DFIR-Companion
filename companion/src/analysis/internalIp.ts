// Internal (non-routable) IPv4 classification — ONE table of ranges shared by every importer that
// keeps only PUBLIC IPs as IOCs (Snort / Cisco ASA / ECAR / syslog / email, via siemImport's
// re-export) and by siemImport's logon-risk grading. A future range fix lands everywhere at once —
// the per-importer copies had already drifted (emailImport treated CGNAT and 0/8 as public).

// RFC1918, loopback, 0.0.0.0/8, link-local 169.254/16 and CGNAT 100.64/10. Non-IPv4 strings return
// false — "not internal IPv4", NOT "public": a caller that needs "public IPv4" must also require
// the IPv4 shape (see siemImport's isPublicIpv4).
export function isInternalIpv4(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true; // link-local
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  return false;
}
