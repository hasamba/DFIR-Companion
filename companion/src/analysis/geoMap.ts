import type { InvestigationState, IOC, ForensicEvent, Severity } from "./stateTypes.js";
import { isInternalIp } from "./anonymize.js";
import { countryCentroid } from "./countryCentroids.js";

// Geographic IP map (#133): derived ON READ from the (filtered) case state — never persisted.
// Markers come from IP IOCs that carry GeoIP coordinates (set by GeoIpProvider). Severity is the
// worst severity of events/findings that reference the IP; legitimate/whitelisted IPs render gray.
// Flows connect two geo-resolved endpoints (victim→attacker by RFC1918 classification). Pure.

export type GeoColor = "red" | "orange" | "yellow" | "gray";

export interface GeoMarker {
  iocId: string;
  ip: string;
  lat: number;
  lon: number;
  country?: string;
  city?: string;
  asn?: string;
  severity: Severity;
  color: GeoColor;
  verdict?: string;
  internal: boolean;
  falsePositive: boolean;
  eventCount: number;
  sources: string[];
  firstSeen?: string;
  lastSeen?: string;
  approximate?: boolean;
}

export interface GeoFlow {
  srcIp: string;
  dstIp: string;
  srcLat: number;
  srcLon: number;
  dstLat: number;
  dstLon: number;
  direction: "incoming" | "outgoing" | "lateral";
  count: number;
  severity: Severity;
}

export interface GeoCountry {
  country: string;
  count: number;
  severity: Severity;
}

export interface GeoMapStats {
  totalIps: number;
  resolved: number;
  unresolved: number;
  internal: number;
  external: number;
  distinctCountries: number;
  distinctAsns: number;
  markerCap?: number;
  flowCap?: number;
}

export interface GeoMapData {
  markers: GeoMarker[];
  flows: GeoFlow[];
  countries: GeoCountry[];
  stats: GeoMapStats;
}

export interface GeoMapOptions {
  falsePositiveValues?: string[];
  maxMarkers?: number;
  maxFlows?: number;
  topCountries?: number;
}

const SEV_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function worse(a: Severity, b: Severity): Severity {
  return SEV_RANK[b] < SEV_RANK[a] ? b : a;
}

const VERDICT_ORDER = ["malicious", "suspicious", "harmless", "unknown"];
function worstVerdict(i: IOC): string | undefined {
  let best: string | undefined;
  for (const e of i.enrichments ?? []) {
    if (best === undefined || VERDICT_ORDER.indexOf(e.verdict) < VERDICT_ORDER.indexOf(best)) best = e.verdict;
  }
  return best;
}

function colorFor(sev: Severity, legit: boolean): GeoColor {
  if (legit) return "gray";
  if (sev === "Critical" || sev === "High") return "red";
  if (sev === "Medium") return "orange";
  if (sev === "Low") return "yellow";
  return "gray";
}

// Extract a country signal from a GeoIP-ish enrichment (handles old data without structured country).
function enrichmentCountry(i: IOC): string | undefined {
  const geo = (i.enrichments ?? []).filter(
    (e) => /geoip/i.test(e.source) || /geoip/i.test(e.provider ?? ""),
  );
  for (const e of geo) if (e.country && e.country.trim()) return e.country.trim();   // structured field (code or name)
  for (const e of geo) {
    for (const t of e.tags ?? []) if (/^[A-Za-z]{2}$/.test(t.trim())) return t.trim().toUpperCase();
    const head = e.score?.split(/[·|,;]/)[0]?.trim();
    if (head && /^[A-Za-z]{2}$/.test(head)) return head.toUpperCase();
  }
  return undefined;
}

// Coordinates from the first enrichment that carries them; falls back to country centroid.
export function iocGeo(i: IOC): { lat: number; lon: number; country?: string; city?: string; approximate: boolean } | undefined {
  for (const e of i.enrichments ?? []) {
    if (typeof e.lat === "number" && typeof e.lon === "number" && Number.isFinite(e.lat) && Number.isFinite(e.lon)) {
      return { lat: e.lat, lon: e.lon, country: e.country, city: e.city, approximate: false };
    }
  }
  const country = enrichmentCountry(i);
  if (country) {
    const c = countryCentroid(country);
    if (c) return { lat: c.lat, lon: c.lon, country: c.name, city: undefined, approximate: true };
  }
  return undefined;
}

// "AS####" token from any enrichment's tags (GeoIP puts the ASN there).
export function iocAsn(i: IOC): string | undefined {
  for (const e of i.enrichments ?? []) {
    for (const t of e.tags ?? []) if (/^AS\d+$/i.test(t.trim())) return t.trim().toUpperCase();
  }
  return undefined;
}

interface Agg {
  sev: Severity;
  count: number;
  sources: Set<string>;
  first?: string;
  last?: string;
}

export function buildGeoMap(state: InvestigationState, opts: GeoMapOptions = {}): GeoMapData {
  const maxMarkers = opts.maxMarkers && opts.maxMarkers > 0 ? opts.maxMarkers : 2000;
  const maxFlows = opts.maxFlows && opts.maxFlows > 0 ? opts.maxFlows : 500;
  const topN = opts.topCountries && opts.topCountries > 0 ? opts.topCountries : 10;
  const legit = new Set((opts.falsePositiveValues ?? []).map((v) => v.trim().toLowerCase()));

  const ipIocs = state.iocs.filter((i) => i.type === "ip");
  const byValue = new Map<string, IOC>();
  for (const i of ipIocs) byValue.set(i.value.trim().toLowerCase(), i);

  // Boundary-aware description matchers (so "1.1.1.1" does NOT match inside "11.1.1.10").
  const descMatchers = ipIocs.map((i) => ({
    ioc: i,
    re: new RegExp(`(?<![\\d.])${escapeRegExp(i.value.trim().toLowerCase())}(?![\\d.])`),
  }));

  // Accumulate per-IOC severity / eventCount / sources / first-last from referencing events.
  const agg = new Map<string, Agg>();
  const ensure = (id: string): Agg => {
    let a = agg.get(id);
    if (!a) {
      a = { sev: "Info", count: 0, sources: new Set() };
      agg.set(id, a);
    }
    return a;
  };

  function iocsForEvent(e: ForensicEvent): IOC[] {
    const out = new Map<string, IOC>();
    const add = (v?: string) => {
      if (!v) return;
      const i = byValue.get(v.trim().toLowerCase());
      if (i) out.set(i.id, i);
    };
    add(e.srcIp);
    add(e.dstIp);
    const desc = e.description.toLowerCase();
    for (const { ioc, re } of descMatchers) if (re.test(desc)) out.set(ioc.id, ioc);
    return [...out.values()];
  }

  for (const e of state.forensicTimeline) {
    for (const i of iocsForEvent(e)) {
      const a = ensure(i.id);
      a.sev = worse(a.sev, e.severity);
      a.count++;
      for (const s of e.sources ?? []) a.sources.add(s);
      if (!a.first || e.timestamp < a.first) a.first = e.timestamp;
      const t = e.endTimestamp ?? e.timestamp;
      if (!a.last || t > a.last) a.last = t;
    }
  }
  const ipById = new Map(ipIocs.map((i) => [i.id, i] as const));
  for (const f of state.findings) {
    for (const id of f.relatedIocs) {
      if (ipById.has(id)) ensure(id).sev = worse(ensure(id).sev, f.severity);
    }
  }

  // Markers.
  const coordsByIp = new Map<string, { lat: number; lon: number }>();
  const all: GeoMarker[] = [];
  for (const i of ipIocs) {
    const geo = iocGeo(i);
    if (!geo) continue;
    const a = agg.get(i.id);
    const isLegit = legit.has(i.value.trim().toLowerCase());
    const sev = a?.sev ?? "Info";
    all.push({
      iocId: i.id,
      ip: i.value,
      lat: geo.lat,
      lon: geo.lon,
      country: geo.country,
      city: geo.city,
      asn: iocAsn(i),
      severity: sev,
      color: colorFor(sev, isLegit),
      verdict: worstVerdict(i),
      internal: isInternalIp(i.value),
      falsePositive: isLegit,
      eventCount: a?.count ?? 0,
      sources: a ? [...a.sources].sort() : [],
      firstSeen: a?.first,
      lastSeen: a?.last,
      approximate: geo.approximate,
    });
    coordsByIp.set(i.value.trim().toLowerCase(), { lat: geo.lat, lon: geo.lon });
  }
  all.sort(
    (x, y) =>
      SEV_RANK[x.severity] - SEV_RANK[y.severity] ||
      y.eventCount - x.eventCount ||
      x.ip.localeCompare(y.ip),
  );
  const resolved = all.length;
  const markers = all.slice(0, maxMarkers);

  // Flows: src→dst pairs where both endpoints have coordinates.
  const flowAgg = new Map<string, { count: number; sev: Severity }>();
  for (const e of state.forensicTimeline) {
    const s = (e.srcIp ?? "").trim().toLowerCase();
    const d = (e.dstIp ?? "").trim().toLowerCase();
    if (!s || !d || !coordsByIp.has(s) || !coordsByIp.has(d)) continue;
    const key = `${s}|${d}`;
    let fa = flowAgg.get(key);
    if (!fa) {
      fa = { count: 0, sev: "Info" };
      flowAgg.set(key, fa);
    }
    fa.count += e.count ?? 1;
    fa.sev = worse(fa.sev, e.severity);
  }
  const allFlows: GeoFlow[] = [...flowAgg.entries()]
    .map(([key, fa]) => {
      const [s, d] = key.split("|");
      const sc = coordsByIp.get(s)!;
      const dc = coordsByIp.get(d)!;
      const si = isInternalIp(s);
      const di = isInternalIp(d);
      const direction: GeoFlow["direction"] = si && !di ? "outgoing" : !si && di ? "incoming" : "lateral";
      return { srcIp: s, dstIp: d, srcLat: sc.lat, srcLon: sc.lon, dstLat: dc.lat, dstLon: dc.lon, direction, count: fa.count, severity: fa.sev };
    })
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.count - a.count || a.srcIp.localeCompare(b.srcIp) || a.dstIp.localeCompare(b.dstIp));
  const flows = allFlows.slice(0, maxFlows);

  // Country aggregation over all resolved markers.
  const cAgg = new Map<string, { count: number; sev: Severity }>();
  for (const m of all) {
    if (!m.country) continue;
    let c = cAgg.get(m.country);
    if (!c) {
      c = { count: 0, sev: "Info" };
      cAgg.set(m.country, c);
    }
    c.count++;
    c.sev = worse(c.sev, m.severity);
  }
  const countries: GeoCountry[] = [...cAgg.entries()]
    .map(([country, v]) => ({ country, count: v.count, severity: v.sev }))
    .sort((a, b) => b.count - a.count || SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.country.localeCompare(b.country))
    .slice(0, topN);

  const asns = new Set(all.map((m) => m.asn).filter((x): x is string => Boolean(x)));
  const stats: GeoMapStats = {
    totalIps: ipIocs.length,
    resolved,
    unresolved: ipIocs.length - resolved,
    internal: all.filter((m) => m.internal).length,
    external: all.filter((m) => !m.internal).length,
    distinctCountries: cAgg.size,
    distinctAsns: asns.size,
  };
  if (resolved > maxMarkers) stats.markerCap = maxMarkers;
  if (allFlows.length > maxFlows) stats.flowCap = maxFlows;

  return { markers, flows, countries, stats };
}

export function geoMapEnvOptions(): GeoMapOptions {
  return {
    maxMarkers: Number(process.env.DFIR_GEOMAP_MAX_MARKERS) || 2000,
    maxFlows: Number(process.env.DFIR_GEOMAP_MAX_FLOWS) || 500,
    topCountries: Number(process.env.DFIR_GEOMAP_TOP_COUNTRIES) || 10,
  };
}
