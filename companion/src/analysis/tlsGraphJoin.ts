// Un-aggregated TLS observations for one upload, and the one join Zeek's own identifiers allow
// (#933 item 6, second half — #997).
//
// tlsSession.ts folds every record into a shape row; the graph needs each observation on its own,
// so the store keeps sessions un-aggregated up to TLS_OBSERVATIONS_MAX and folds the rest into a
// late tally as they arrive — a session past the bound still has its row, it is only absent from
// the join and the graph, and every graph row says so. Sessions and certificates have SEPARATE
// shape tallies (TLS_SHAPES_MAX each): the retained sessions are folded only after the loop, and
// with one shared tally an upload of 8,192 distinct certificates arriving anywhere in the file
// would have filled it before any session was folded. Certificate observations are tallied as
// they arrive (their rows do not change) and retained, bounded the same way, for the join and the
// node facts; past their bound a session whose chain FUID finds no retained x509 record says
// `not among those read`, never a silent "unavailable".
//
// The join: a Zeek `ssl` row's `cert_chain_fuids[0]` (the leaf) against the `x509` row whose `id`
// equals it, on the same sensor (records that name no sensor are one partition per upload and
// never join records that name one). It fills only what the session record lacks — the identity —
// and never its facts; a session carrying its own `cert_chain_fps[0]` keeps it, and a disagreeing
// x509 fingerprint of the same digest kind is named. A FUID is a locator: Zeek ≥ 4 derives it from
// the certificate's hash so it repeats across connections, and nothing here relies on that — the
// identity always comes from the x509 row's own fields.

import {
  tallyTls,
  tallyTlsOverflow,
  TLS_SHAPES_MAX,
  type CertJoinNote,
  type CertRef,
  type TlsObservation,
  type TlsTally,
} from "./tlsSession.js";

/** Session and certificate observations retained per upload; the rest are counted and folded. */
export const TLS_OBSERVATIONS_MAX = 65_536;

export interface TlsObservations {
  /** Retained un-aggregated sessions — the join's and the graph's input. */
  sessions: TlsObservation[];
  /** Retained certificate observations with an identity. */
  certs: TlsObservation[];
  /** Every certificate row's shape, folded as the records arrive. */
  certTally: Map<string, TlsTally>;
  /** Session shapes: the retained sessions after the join, then the late ones merged in. */
  sessionTally: Map<string, TlsTally>;
  /** Sessions past the retained bound, folded as they arrive; merged after the retained ones. */
  lateTally: Map<string, TlsTally>;
  sessionsTotal: number;
  /** Certificate observations with an identity, retained or not. */
  certsTotal: number;
}

export function emptyTlsObservations(): TlsObservations {
  return {
    sessions: [],
    certs: [],
    certTally: new Map(),
    sessionTally: new Map(),
    lateTally: new Map(),
    sessionsTotal: 0,
    certsTotal: 0,
  };
}

export function addTls(store: TlsObservations, o: TlsObservation): void {
  if (o.kind === "certificate") {
    tallyTls(o, store.certTally);
    if (!o.cert) return;
    store.certsTotal += 1;
    if (store.certs.length < TLS_OBSERVATIONS_MAX) store.certs.push(o);
    return;
  }
  store.sessionsTotal += 1;
  if (store.sessions.length < TLS_OBSERVATIONS_MAX) store.sessions.push(o);
  else tallyTls(o, store.lateTally);
}

/** Fold the late tally into the session tally: a shape already there adds its count; a new one takes a slot or overflows. */
export function mergeLateTally(store: TlsObservations): void {
  for (const [key, late] of store.lateTally) {
    const existing = store.sessionTally.get(key);
    if (existing) {
      existing.count += late.count;
      if (late.firstTs && (!existing.firstTs || late.firstTs < existing.firstTs))
        existing.firstTs = late.firstTs;
    } else if (late.overflow || store.sessionTally.size >= TLS_SHAPES_MAX) {
      // A late overflow row, or a shape past the bound: its records join the session overflow row.
      tallyTlsOverflow(late.first, store.sessionTally, late.count, late.firstTs);
    } else store.sessionTally.set(key, late);
  }
  store.lateTally = new Map();
}

/** The sensor partition a record belongs to: its observer's name, or "" for records that name none. */
export const sensorKeyOf = (o: TlsObservation): string => o.observer?.name ?? "";

// ───────────────────────────── x509 index ─────────────────────────────

interface X509Entry {
  /** Distinct identities the x509 records for this id carry — more than one is a disagreement. */
  refs: CertRef[];
  /** The first record's own facts, for the subject/issuer comparison. */
  subject?: string;
  issuer?: string;
}

const sameRef = (a: CertRef, b: CertRef): boolean =>
  a.kind === b.kind && a.value === b.value && a.alg === b.alg;

/** sensor → role bucket → FUID → entry. Zeek marks which side sent the certificate; an unmarked record fits either. */
function indexX509(store: TlsObservations): Map<string, Map<string, X509Entry>> {
  const bySensor = new Map<string, Map<string, X509Entry>>();
  for (const c of store.certs) {
    if (c.source !== "zeek-x509" || !c.locatorId || !c.cert) continue;
    const sensor = sensorKeyOf(c);
    const byId = bySensor.get(sensor) ?? bySensor.set(sensor, new Map()).get(sensor)!;
    const key = `${c.role ?? "any"}|${c.locatorId}`;
    const entry = byId.get(key);
    if (!entry) {
      byId.set(key, {
        refs: [c.cert],
        ...(c.subject !== undefined ? { subject: c.subject } : {}),
        ...(c.issuer !== undefined ? { issuer: c.issuer } : {}),
      });
    } else if (!entry.refs.some((r) => sameRef(r, c.cert!))) entry.refs.push(c.cert);
  }
  return bySensor;
}

/**
 * Every x509 record eligible for a chain: the ones marked with the role the chain names AND the
 * unmarked ones, as one entry — so a marked and an unmarked record for one FUID that carry
 * different identities are a disagreement, never a silent pick of the marked one.
 */
function lookup(
  byId: Map<string, X509Entry> | undefined,
  fuid: string,
  role: "server" | "client",
): X509Entry | undefined {
  const marked = byId?.get(`${role}|${fuid}`);
  const unmarked = byId?.get(`any|${fuid}`);
  if (!marked || !unmarked) return marked ?? unmarked;
  const refs = [...marked.refs];
  for (const r of unmarked.refs) if (!refs.some((m) => sameRef(m, r))) refs.push(r);
  return { ...marked, refs };
}

// ───────────────────────────── the join ─────────────────────────────

interface JoinOutcome {
  ref?: CertRef;
  from?: "x509";
  note?: CertJoinNote;
}

/** What the x509 record establishes for one chain: an identity, a disagreement, or an absence with its reason. */
function joinOne(
  entry: X509Entry | undefined,
  own: CertRef | undefined,
  ownSubject: string | undefined,
  ownIssuer: string | undefined,
  certsIncomplete: boolean,
): JoinOutcome {
  if (!entry) return certsIncomplete ? { note: "not among those read" } : {};
  if (entry.refs.length > 1) return { note: "records disagree" };
  const [ref] = entry.refs;
  if (own) {
    // The record's own identity stands. Two digests of one kind that differ are a disagreement;
    // an issuer+serial identity beside a fingerprint, or two digest kinds, are not comparable.
    if (
      own.kind === "fingerprint" &&
      ref.kind === "fingerprint" &&
      own.alg === ref.alg &&
      own.value !== ref.value
    )
      return { note: "disagrees with this record" };
    return {};
  }
  const differ =
    (ownSubject !== undefined && entry.subject !== undefined && ownSubject.trim() !== entry.subject.trim()) ||
    (ownIssuer !== undefined && entry.issuer !== undefined && ownIssuer.trim() !== entry.issuer.trim());
  return { ref, from: "x509", ...(differ ? { note: "subject/issuer differ" } : {}) };
}

/**
 * Every retained session, with the identity its chain FUID finds in the same sensor's x509 records
 * — a new object per joined session; nothing is mutated. Sessions that carry no chain FUID (every
 * Suricata session, a Zeek row with no certificate) come back as they are.
 */
export function joinSessionsToCertificates(store: TlsObservations): TlsObservation[] {
  const index = indexX509(store);
  const certsIncomplete = store.certsTotal > store.certs.length;
  return store.sessions.map((o) => {
    if (o.source !== "zeek-ssl") return o;
    const byId = index.get(sensorKeyOf(o));
    let out = o;
    const serverFuid = o.certChainFuids?.[0];
    if (serverFuid) {
      const j = joinOne(lookup(byId, serverFuid, "server"), o.cert, o.subject, o.issuer, certsIncomplete);
      if (j.ref || j.note)
        out = {
          ...out,
          ...(j.ref ? { cert: j.ref } : {}),
          ...(j.from ? { certFrom: j.from } : {}),
          ...(j.note ? { certJoinNote: j.note } : {}),
        };
    }
    const clientFuid = o.clientCert?.chainFuids?.[0];
    if (clientFuid && o.clientCert) {
      const cc = o.clientCert;
      const j = joinOne(lookup(byId, clientFuid, "client"), cc.ref, cc.subject, cc.issuer, certsIncomplete);
      if (j.ref || j.note)
        out = {
          ...out,
          clientCert: {
            ...cc,
            ...(j.ref ? { ref: j.ref } : {}),
            ...(j.from ? { from: j.from } : {}),
            ...(j.note ? { joinNote: j.note } : {}),
          },
        };
    }
    return out;
  });
}
