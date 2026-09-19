// The TLS relationship graph across every upload and sensor in a case (#997, cross-upload half).
//
// tlsGraphNodes.ts builds one node row per (sensor, identity) INSIDE one upload — that is what one
// set of records establishes. This reads those rows back from the case (forensic ∪ super-timeline;
// a plain analyst read, no AI in its call graph) and merges them by node identity at read time,
// the way dnsResolverEndpointJoin.ts and proxyWorkstationChain.ts do their cross-upload joins:
// recomputed on every call, never persisted, never a merge-time pass.
//
// What the merged node establishes: the union of what each observation showed — names, server
// endpoints, client addresses, certificate identities — and, per observation, which sensor and
// which upload showed it and when. What it never establishes: that two sensors' observations are
// one operator, that a certificate "moved", or that a difference between sensors means anything
// beyond "these records differ". A difference is stated with both sides; when any side's list was
// incomplete (`atLeast`) the comparison is withheld and says so. Leads keep the sensor that raised
// them. A JA3/JA3S node stays a library signature.

import type { TlsGraphBlock, TlsGraphEdge, TlsGraphLead, TlsGraphNodeKind } from "./canonicalTls.js";

type TlsGraphLeadKind = TlsGraphLead["kind"];

/** Nodes shown per call; the rest are counted. */
export const TLS_CASE_NODES_MAX = 4096;
/** Observations kept per node; the rest are counted (sensors and uploads are still counted over all). */
export const TLS_CASE_OBSERVATIONS_MAX = 64;
/** Values listed per unioned edge. */
export const TLS_CASE_LISTED_MAX = 32;
/** Values named on each side of a stated difference. */
const DIFF_LISTED_MAX = 8;

export interface TlsCaseGraphEventShape {
  id?: string;
  timestamp?: string;
  importBatchId?: string;
  importedAt?: string;
  sources?: string[];
  canonical?: { tlsGraph?: TlsGraphBlock };
}

export interface TlsCaseObservation {
  eventId: string;
  sensor: string;
  upload?: { id: string; importedAt?: string };
  sources: string[];
  first?: string;
  last?: string;
  sessions: number;
  names: TlsGraphEdge;
  servers: TlsGraphEdge;
  clientAddresses: TlsGraphEdge;
  certificates?: TlsGraphEdge;
  leads: { kind: TlsGraphLeadKind; words: string }[];
  chainChecks?: string[];
  certificate?: TlsGraphBlock["certificate"];
}

export interface TlsCaseEdge {
  count: number;
  listed: string[];
  atLeast?: boolean;
}

export interface TlsCaseSpan {
  identity: string;
  alg?: "sha1" | "sha256";
  sensor: string;
  first?: string;
  last?: string;
  sessions: number;
}

export interface TlsCaseNode {
  kind: TlsGraphNodeKind;
  id: string;
  alg?: "sha1" | "sha256";
  sessions: number;
  sensors: number;
  uploads: number;
  first?: string;
  last?: string;
  names: TlsCaseEdge;
  servers: TlsCaseEdge;
  clientAddresses: TlsCaseEdge;
  certificates: TlsCaseEdge;
  spans: TlsCaseSpan[];
  leads: { sensor: string; kind: TlsGraphLeadKind; words: string }[];
  /** Differences between sensors, stated with both sides — or why a comparison was withheld. */
  crossFacts: string[];
  observations: TlsCaseObservation[];
  observationsNotShown: number;
  /** The certificate record's own facts, from the first observation that carried them. */
  certificate?: TlsGraphBlock["certificate"];
}

export interface TlsCaseGraph {
  nodes: TlsCaseNode[];
  notShown: number;
  rowsRead: number;
  /** Node rows an upload folded past its own bound — counted, nothing known about them. */
  folded: number;
  basis: "the case's own TLS-graph rows, every upload and sensor; no contact with any observed infrastructure";
}

const EMPTY: TlsGraphEdge = { count: 0, listed: [] };
const SENSOR_UNNAMED = "sensor not named";

interface UnionEdge {
  seen: Set<string>;
  atLeast: boolean;
  /** Every observation listed all of its values (count === listed.length, no atLeast). */
  complete: boolean;
}
const union = (): UnionEdge => ({ seen: new Set(), atLeast: false, complete: true });
function addEdge(u: UnionEdge, e: TlsGraphEdge | undefined): void {
  if (!e) return;
  for (const v of e.listed) u.seen.add(v);
  if (e.atLeast || e.count > e.listed.length) {
    u.atLeast = true;
    u.complete = false;
  }
}
const edgeOut = (u: UnionEdge): TlsCaseEdge => {
  const listed = [...u.seen].sort();
  return {
    count: listed.length,
    listed: listed.slice(0, TLS_CASE_LISTED_MAX),
    ...(u.atLeast ? { atLeast: true } : {}),
  };
};

const ends = (h: string): string => (h.length > 12 ? `${h.slice(0, 8)}…${h.slice(-4)}` : h);
const sensorOf = (b: TlsGraphBlock): string => ("name" in b.sensor ? b.sensor.name : SENSOR_UNNAMED);
const minIso = (a?: string, b?: string): string | undefined =>
  a === undefined ? b : b === undefined ? a : a < b ? a : b;
const maxIso = (a?: string, b?: string): string | undefined =>
  a === undefined ? b : b === undefined ? a : a > b ? a : b;

interface Acc {
  node: TlsCaseNode;
  names: UnionEdge;
  servers: UnionEdge;
  clientAddresses: UnionEdge;
  certificates: UnionEdge;
  sensorSet: Set<string>;
  uploadSet: Set<string>;
  /** Per sensor: the names (certificate node) or certificate identities (name node) it showed. */
  perSensor: Map<string, { values: Set<string>; complete: boolean }>;
  leadSeen: Set<string>;
}

function observationOf(e: TlsCaseGraphEventShape, b: TlsGraphBlock): TlsCaseObservation {
  return {
    eventId: e.id ?? "",
    sensor: sensorOf(b),
    ...(e.importBatchId
      ? { upload: { id: e.importBatchId, ...(e.importedAt ? { importedAt: e.importedAt } : {}) } }
      : {}),
    sources: e.sources ?? [],
    ...(b.first !== undefined ? { first: b.first } : {}),
    ...(b.last !== undefined ? { last: b.last } : {}),
    sessions: b.sessions,
    names: b.names ?? EMPTY,
    servers: b.servers ?? EMPTY,
    clientAddresses: b.clientAddresses ?? EMPTY,
    ...(b.certificates ? { certificates: b.certificates } : {}),
    leads: b.leads,
    ...(b.chainChecks?.length ? { chainChecks: b.chainChecks } : {}),
    ...(b.certificate ? { certificate: b.certificate } : {}),
  };
}

/** The per-sensor comparison a node kind supports: names for a certificate, certificate identities for a name. */
function comparedEdge(b: TlsGraphBlock): { label: string; edge: TlsGraphEdge | undefined } | undefined {
  if (b.node.kind === "certificate") return { label: "names", edge: b.names };
  if (b.node.kind === "name") return { label: "certificates", edge: b.certificates };
  return undefined;
}

function crossFactsOf(a: Acc): string[] {
  const kind = a.node.kind;
  if (a.perSensor.size < 2 || (kind !== "certificate" && kind !== "name")) return [];
  const label = kind === "certificate" ? "names" : "certificates";
  const shown = (v: string) => (kind === "name" ? ends(v) : v);
  if ([...a.perSensor.values()].some((p) => !p.complete))
    return [`${label} not compared between sensors: a sensor's list is incomplete`];
  const sensors = [...a.perSensor.entries()].sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0));
  const all = new Set(sensors.flatMap(([, p]) => [...p.values]));
  const onlyParts: string[] = [];
  for (const [sensor, p] of sensors) {
    const only = [...p.values]
      .filter((v) => sensors.some(([s2, p2]) => s2 !== sensor && !p2.values.has(v)))
      .sort();
    if (only.length)
      onlyParts.push(
        `${sensor} only ${only.slice(0, DIFF_LISTED_MAX).map(shown).join(", ")}${only.length > DIFF_LISTED_MAX ? ` (+${only.length - DIFF_LISTED_MAX} more)` : ""}`,
      );
  }
  if (!onlyParts.length || all.size === 0) return [];
  return kind === "certificate"
    ? [`names differ between sensors: ${onlyParts.join("; ")}`]
    : [`served with different certificates on different sensors: ${onlyParts.join("; ")}`];
}

export function buildTlsCaseGraph(events: readonly TlsCaseGraphEventShape[]): TlsCaseGraph {
  const accs = new Map<string, Acc>();
  let rowsRead = 0;
  let folded = 0;
  for (const e of events) {
    const b = e.canonical?.tlsGraph;
    if (!b) continue;
    rowsRead += 1;
    if (b.folded) {
      folded += b.records ?? 0;
      continue;
    }
    const key = `${b.node.kind}|${b.node.id}`;
    let a = accs.get(key);
    if (!a) {
      a = {
        node: {
          kind: b.node.kind,
          id: b.node.id,
          ...(b.node.alg ? { alg: b.node.alg } : {}),
          sessions: 0,
          sensors: 0,
          uploads: 0,
          names: { count: 0, listed: [] },
          servers: { count: 0, listed: [] },
          clientAddresses: { count: 0, listed: [] },
          certificates: { count: 0, listed: [] },
          spans: [],
          leads: [],
          crossFacts: [],
          observations: [],
          observationsNotShown: 0,
        },
        names: union(),
        servers: union(),
        clientAddresses: union(),
        certificates: union(),
        sensorSet: new Set(),
        uploadSet: new Set(),
        perSensor: new Map(),
        leadSeen: new Set(),
      };
      accs.set(key, a);
    }
    const o = observationOf(e, b);
    const n = a.node;
    n.sessions += b.sessions;
    n.first = minIso(n.first, b.first);
    n.last = maxIso(n.last, b.last);
    a.sensorSet.add(o.sensor);
    if (o.upload) a.uploadSet.add(o.upload.id);
    addEdge(a.names, b.names);
    addEdge(a.servers, b.servers);
    addEdge(a.clientAddresses, b.clientAddresses);
    addEdge(a.certificates, b.certificates);
    for (const s of b.spans ?? [])
      n.spans.push({
        identity: s.identity,
        ...(s.alg ? { alg: s.alg } : {}),
        sensor: o.sensor,
        ...(s.first ? { first: s.first } : {}),
        ...(s.last ? { last: s.last } : {}),
        sessions: s.sessions,
      });
    for (const l of b.leads) {
      const k = `${o.sensor}|${l.kind}|${l.words}`;
      if (a.leadSeen.has(k)) continue;
      a.leadSeen.add(k);
      n.leads.push({ sensor: o.sensor, kind: l.kind, words: l.words });
    }
    const cmp = comparedEdge(b);
    if (cmp) {
      const p = a.perSensor.get(o.sensor) ?? { values: new Set<string>(), complete: true };
      for (const v of cmp.edge?.listed ?? []) p.values.add(v);
      if (cmp.edge && (cmp.edge.atLeast || cmp.edge.count > cmp.edge.listed.length)) p.complete = false;
      a.perSensor.set(o.sensor, p);
    }
    if (!n.certificate && b.certificate) n.certificate = b.certificate;
    if (n.observations.length < TLS_CASE_OBSERVATIONS_MAX) n.observations.push(o);
    else n.observationsNotShown += 1;
  }

  const nodes: TlsCaseNode[] = [];
  for (const a of accs.values()) {
    const n = a.node;
    n.sensors = a.sensorSet.size;
    n.uploads = a.uploadSet.size;
    n.names = edgeOut(a.names);
    n.servers = edgeOut(a.servers);
    n.clientAddresses = edgeOut(a.clientAddresses);
    n.certificates = edgeOut(a.certificates);
    n.spans.sort((x, y) => (x.first ?? "").localeCompare(y.first ?? "") || x.sensor.localeCompare(y.sensor));
    n.observations.sort(
      (x, y) => (x.first ?? "").localeCompare(y.first ?? "") || x.sensor.localeCompare(y.sensor),
    );
    n.crossFacts = crossFactsOf(a);
    nodes.push(n);
  }
  nodes.sort(
    (x, y) =>
      Number(y.leads.length > 0) - Number(x.leads.length > 0) ||
      y.sessions - x.sessions ||
      (x.first ?? "￿").localeCompare(y.first ?? "￿") ||
      x.id.localeCompare(y.id),
  );
  return {
    nodes: nodes.slice(0, TLS_CASE_NODES_MAX),
    notShown: Math.max(0, nodes.length - TLS_CASE_NODES_MAX),
    rowsRead,
    folded,
    basis:
      "the case's own TLS-graph rows, every upload and sensor; no contact with any observed infrastructure",
  };
}
