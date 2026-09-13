// Web request rows and transfer rows: identity, bound, envelope, indicators (#993). The shape of
// a row is EVERYTHING its words and envelope show — a digest over the whole `web` / `transfer`
// block with the locators and the count removed — so two rows with different chains are two rows
// and two records of one chain fold into one (the spec's "a chain row aggregates only with an
// identical chain"). Locators (uid, depth, fuid, flow_id, tx_id, stream_id) are never keyed.
//
// The row is bounded the way TLS rows are (tlsSession.ts): shapes past WEB_SHAPES_MAX fold into
// one overflow row per kind and source that shows no shape; under the import's event budget the
// rows that name a file identity come first, then graded rows, then the most seen.
//
// Grading reuses the combined-log path (#930 item 3): an attack pattern or a secret in a
// Zeek-seen target grades exactly as it would in an Apache line. Everything else is Info and
// carries no technique — a request proves nothing on its own.

import type { Severity } from "./stateTypes.js";
import type { CoverageKind } from "./canonicalWeb.js";
import { createCanonicalEvent, type CanonicalEventEnvelope } from "./canonicalEvent.js";
import { addIoc, mergeRowIocs, type MappedEvent, type SiemIoc } from "./siemImport.js";
import { identityMark, keyDigest, packTags, showToken } from "./recordIdentity.js";
import { inspectRequestFields, type RequestInspection } from "./webRequestDecode.js";
import { secretSpillSignal } from "./secretSpillRules.js";
import {
  coverageOf,
  isFileIdentity,
  WEB_BODIES_MAX,
  type BodyHop,
  type RequestChain,
  type TransferChain,
  type WebObservations,
} from "./webChainJoin.js";
import {
  bodyFacts,
  requestHead,
  requestTags,
  type RequestTagGroups,
  targetView,
  transferBlock,
  transferHead,
  transferTags,
  webBlock,
} from "./webChainWords.js";
import { isIP } from "node:net";
import { readTarget } from "./webRecordFields.js";

/** Distinct row shapes one import keeps per kind; every later new shape folds into an overflow row. */
export const WEB_SHAPES_MAX = 8192;
const DESCRIPTION_MAX = 600;
const ATTACK_SLOT_MAX = 120;

type Kind = "web" | "transfer";
type Source = RequestChain["req"]["source"] | TransferChain["xfer"]["source"];

export interface WebTally {
  kind: Kind;
  source: Source;
  first?: RequestChain | TransferChain;
  /** The first request's inspection (attack / spill), computed once and reused by key and words. */
  inspection?: Inspection;
  count: number;
  firstTs: string;
  key: string;
  /** Rows carrying a digest that names a file rank first under the budget. */
  namesFile: boolean;
  graded: boolean;
  overflow?: boolean;
}

// ───────────────────────────── identity ─────────────────────────────

const stableJson = (v: unknown): string =>
  JSON.stringify(v, (_k, val) =>
    val && typeof val === "object" && !Array.isArray(val)
      ? Object.fromEntries(
          Object.entries(val as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : 1)),
        )
      : val,
  );

// The block with its locators and count stripped: what is left is every fact the row shows.
function stripLocators(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stripLocators);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (k === "locator" || k === "records" || k === "id") continue;
      out[k] = stripLocators(val);
    }
    return out;
  }
  return v;
}

const sensorSeg = (o: { observer?: { name: string } }): string =>
  o.observer ? `t:${keyDigest(o.observer.name)}` : "-";

const hopCoverage = (c: RequestChain) => (hop: BodyHop) =>
  hop.transfer ? coverageOf(hop.transfer, c.req.status) : undefined;

interface Inspection {
  attack: RequestInspection | null;
  spillFamilies: string[];
  spillMitre: string[];
}

function inspect(c: RequestChain): Inspection {
  const r = c.req;
  const { inspection, decodedTarget, decodedReferer } = inspectRequestFields({
    target: r.target,
    referer: r.referrer,
    ua: r.userAgent,
  });
  const spill = secretSpillSignal(`${r.target} ${r.referrer} ${decodedTarget} ${decodedReferer}`);
  return { attack: inspection, spillFamilies: spill?.families ?? [], spillMitre: spill?.mitre ?? [] };
}

export function requestKey(c: RequestChain, insp: Inspection = inspect(c)): string {
  const r = c.req;
  const { attack, spillFamilies } = insp;
  // The block shows WEB_BODIES_MAX bodies; the identity covers every body the record named.
  const cov = hopCoverage(c);
  const facts = keyDigest(
    stableJson(
      stripLocators({
        block: webBlock(c, cov, 1),
        tail: c.bodies.slice(WEB_BODIES_MAX).map((h) => bodyFacts(h, cov(h))),
      }),
    ),
  );
  return [
    "web",
    r.source,
    sensorSeg(r),
    r.src ?? "-",
    r.dst ?? "-",
    r.port ?? "-",
    r.method,
    r.status ?? "-",
    attack ? `attack:${attack.families.join(",")}:${attack.digest}` : "-",
    spillFamilies.length ? `spill:${spillFamilies.join(",")}` : "-",
    `f:${facts}`,
  ].join("|");
}

export function transferKey(c: TransferChain): string {
  const x = c.xfer;
  const facts = keyDigest(stableJson(stripLocators(transferBlock(c, 1))));
  return ["xfer", x.source, sensorSeg(x), x.over ?? "-", c.coverage, `f:${facts}`].join("|");
}

const OVERFLOW_KEY = (kind: Kind, source: Source): string => `${kind}|${source}|overflow`;

// ───────────────────────────── indicators ─────────────────────────────

function requestIocs(c: RequestChain, sink: Map<string, SiemIoc>): void {
  const r = c.req;
  const view = targetView(r);
  // The destination host the client named — an address is an ip, a name a domain (the
  // combined-log rule). A CONNECT names a tunnel target the same way.
  const host = view.host;
  const bare = host.startsWith("[") ? host.slice(1, -1) : host;
  if (bare && isIP(bare)) addIoc(sink, "ip", bare);
  else if (host) addIoc(sink, "domain", host);
  if (view.reading.form === "absolute" && /^https?:\/\//i.test(r.target))
    addIoc(sink, "url", r.target.slice(0, 300));
  // A Referer is a claim the client makes: a named host is a domain indicator, an address is not,
  // and a Referer carrying a query string is kept whole as the secret-leak surface (#933 item 1).
  if (r.referrer) {
    const ref = r.referrer;
    const refHost = readHostOf(ref);
    if (
      refHost &&
      !isIP(refHost.startsWith("[") ? refHost.slice(1, -1) : refHost) &&
      !refHost.startsWith("[")
    )
      addIoc(sink, "domain", refHost);
    if (/^https?:\/\//i.test(ref) && ref.includes("?")) addIoc(sink, "url", ref.slice(0, 300));
  }
}

const readHostOf = (url: string): string => readTarget("GET", url).host;

function transferIocs(c: TransferChain, sink: Map<string, SiemIoc>): void {
  const x = c.xfer;
  // A digest is a hash indicator only when it names the whole object (webChainJoin.ts coverage):
  // a partial digest matches no file anywhere and would be a false identity.
  if (isFileIdentity(c.coverage)) {
    if (x.sha256) addIoc(sink, "hash", x.sha256);
    if (x.md5) addIoc(sink, "hash", x.md5);
    if (x.sha1) addIoc(sink, "hash", x.sha1);
  }
  const name = x.filename?.trim();
  if (name && name !== "-" && name.length > 1) addIoc(sink, "file", name.slice(0, 300));
}

// ───────────────────────────── tally ─────────────────────────────

interface Shape {
  key: string;
  kind: Kind;
  source: Source;
  ts: string;
  first: RequestChain | TransferChain;
  namesFile: boolean;
  graded: boolean;
  inspection?: Inspection;
}

function fold(sink: Map<string, WebTally>, shape: Shape): void {
  const { key, kind, source, ts, first, namesFile, graded, inspection } = shape;
  const existing = sink.get(key);
  if (existing) {
    existing.count += 1;
    if (ts && (!existing.firstTs || ts < existing.firstTs)) existing.firstTs = ts;
    return;
  }
  if (sink.size >= WEB_SHAPES_MAX) {
    const ok = OVERFLOW_KEY(kind, source);
    const over = sink.get(ok);
    if (over) {
      over.count += 1;
      if (ts && (!over.firstTs || ts < over.firstTs)) over.firstTs = ts;
    } else
      sink.set(ok, {
        kind,
        source,
        count: 1,
        firstTs: ts,
        key: ok,
        namesFile: false,
        graded: false,
        overflow: true,
      });
    return;
  }
  sink.set(key, {
    kind,
    source,
    first,
    ...(inspection ? { inspection } : {}),
    count: 1,
    firstTs: ts,
    key,
    namesFile,
    graded,
  });
}

/**
 * Fold every joined chain into row shapes, minting each chain's indicators against its row key so
 * the hash IOC's provenance names the transfer row (extractedFrom). Records past the retained
 * bound (WebObservations overflow) join the kind's overflow row: counted, never read.
 */
export function tallyWebChains(
  obs: WebObservations,
  joined: { requests: RequestChain[]; transfers: TransferChain[] },
  iocSink: Map<string, SiemIoc>,
): Map<string, WebTally> {
  const sink = new Map<string, WebTally>();
  const hasDigest = (x: { sha256?: string; md5?: string; sha1?: string }): boolean =>
    !!(x.sha256 || x.md5 || x.sha1);
  for (const c of joined.requests) {
    const inspection = inspect(c);
    const key = requestKey(c, inspection);
    const rowIocs = new Map<string, SiemIoc>();
    requestIocs(c, rowIocs);
    mergeRowIocs(iocSink, rowIocs, key);
    const namesFile = c.bodies.some(
      (h) => h.transfer && isFileIdentity(coverageOf(h.transfer, c.req.status)) && hasDigest(h.transfer),
    );
    const graded = Boolean(inspection.attack) || inspection.spillFamilies.length > 0;
    fold(sink, {
      key,
      kind: "web",
      source: c.req.source,
      ts: c.req.timestamp,
      first: c,
      namesFile,
      graded,
      inspection,
    });
  }
  for (const c of joined.transfers) {
    const key = transferKey(c);
    const rowIocs = new Map<string, SiemIoc>();
    transferIocs(c, rowIocs);
    mergeRowIocs(iocSink, rowIocs, key);
    const namesFile = isFileIdentity(c.coverage) && hasDigest(c.xfer);
    fold(sink, {
      key,
      kind: "transfer",
      source: c.xfer.source,
      ts: c.xfer.timestamp,
      first: c,
      namesFile,
      graded: false,
    });
  }
  const overflow = (kind: Kind, source: Source, n: number): void => {
    if (!n) return;
    const ok = OVERFLOW_KEY(kind, source);
    const over = sink.get(ok);
    if (over) over.count += n;
    else
      sink.set(ok, {
        kind,
        source,
        count: n,
        firstTs: "",
        key: ok,
        namesFile: false,
        graded: false,
        overflow: true,
      });
  };
  overflow("web", joined.requests[0]?.req.source ?? "zeek-http", obs.requestsOverflow);
  overflow("transfer", joined.transfers[0]?.xfer.source ?? "zeek-files", obs.transfersOverflow);
  return sink;
}

// ───────────────────────────── rows ─────────────────────────────

function envelopeOf(t: WebTally): CanonicalEventEnvelope {
  const c = t.first;
  const ts = t.firstTs;
  if (t.overflow || !c) {
    return createCanonicalEvent({
      event: { category: "network", type: t.kind === "web" ? "http" : "transfer" },
      ...(t.kind === "web"
        ? {
            web: {
              method: "-",
              targetForm: "invalid",
              responseState: "not recorded",
              bodies: [],
              bodiesTotal: 0,
              records: t.count,
              folded: true,
            },
          }
        : {
            transfer: {
              coverage: "not-recorded",
              requests: [],
              requestsTotal: 0,
              requestState: "no request identity",
              records: t.count,
              folded: true,
            },
          }),
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: [{ source: t.source, locator: t.key }] },
      producer: { importer: "network", parserVersion: "1", mappingVersion: "web-chain-v1" },
    });
  }
  if ("req" in c) {
    const r = c.req;
    const view = targetView(r);
    const rawRecords = [
      { source: r.source, locator: r.locator, ...(r.uid ? { recordId: r.uid } : {}) },
      ...c.bodies.flatMap((h) =>
        h.transfer
          ? [
              {
                source: h.transfer.source,
                locator: h.transfer.locator,
                ...(h.transfer.fuid ? { recordId: h.transfer.fuid } : {}),
              },
            ]
          : [],
      ),
      ...(c.redirect?.next ? [{ source: c.redirect.next.source, locator: c.redirect.next.locator }] : []),
    ];
    const locatorMap: Record<string, string> = {};
    c.bodies.forEach((h, i) => {
      if (h.transfer) locatorMap[`web.bodies.${i}.transfer`] = h.transfer.locator;
    });
    if (c.redirect?.next) locatorMap["web.redirect.next"] = c.redirect.next.locator;
    return createCanonicalEvent({
      event: {
        category: "network",
        type: "http",
        action: r.method.toLowerCase(),
        ...(r.status !== undefined ? { outcome: String(r.status) } : {}),
      },
      ...(r.src ? { actor: { kind: "network", address: r.src } } : {}),
      ...(r.dst || view.host
        ? {
            target: {
              kind: "network",
              ...(r.dst ? { address: r.dst } : {}),
              ...(view.host ? { domain: view.host } : {}),
              ...(r.port ? { port: r.port } : {}),
            },
          }
        : {}),
      ...(r.src || r.dst
        ? {
            network: {
              ...(r.src ? { source: { address: r.src } } : {}),
              ...(r.dst ? { destination: { address: r.dst, ...(r.port ? { port: r.port } : {}) } } : {}),
              protocol: "http",
            },
          }
        : {}),
      web: webBlock(c, hopCoverage(c), t.count),
      time: { observed: ts, normalized: ts },
      evidence: { rawRecords: dedupRecords(rawRecords) },
      producer: { importer: "network", parserVersion: "1", mappingVersion: "web-chain-v1" },
      rawFieldMap: {
        "web.method": [r.source === "zeek-http" ? "method" : "http.http_method"],
        "time.observed": [r.source === "zeek-http" ? "ts" : "timestamp"],
      },
      locatorMap,
    });
  }
  const x = c.xfer;
  const rawRecords = [
    { source: x.source, locator: x.locator, ...(x.fuid ? { recordId: x.fuid } : {}) },
    ...c.requests.map((r) => ({
      source: r.source,
      locator: r.locator,
      ...(r.uid ? { recordId: r.uid } : {}),
    })),
  ];
  const locatorMap: Record<string, string> = {};
  c.requests.forEach((r, i) => {
    locatorMap[`transfer.requests.${i}`] = r.locator;
  });
  const identity = isFileIdentity(c.coverage);
  return createCanonicalEvent({
    event: { category: "network", type: "transfer", ...(x.over ? { action: x.over.toLowerCase() } : {}) },
    ...(x.tx?.length || x.rx?.length
      ? {
          ...(x.tx?.[0] ? { actor: { kind: "network", address: x.tx[0] } } : {}),
          ...(x.rx?.[0] ? { target: { kind: "network", address: x.rx[0] } } : {}),
        }
      : {}),
    ...(identity && (x.sha256 || x.md5)
      ? {
          file: {
            ...(x.sha256 ? { sha256: x.sha256 } : {}),
            ...(x.md5 ? { md5: x.md5 } : {}),
            ...(x.filename ? { name: x.filename } : {}),
          },
        }
      : x.filename
        ? { file: { name: x.filename } }
        : {}),
    transfer: transferBlock(c, t.count),
    time: { observed: ts, normalized: ts },
    evidence: { rawRecords: dedupRecords(rawRecords) },
    producer: { importer: "network", parserVersion: "1", mappingVersion: "web-chain-v1" },
    rawFieldMap: {
      "time.observed": [x.source === "zeek-files" ? "ts" : "timestamp"],
      ...(identity && x.sha256
        ? { "file.sha256": [x.source === "zeek-files" ? "sha256" : "fileinfo.sha256"] }
        : {}),
    },
    locatorMap,
  });
}

function dedupRecords<T extends { locator: string }>(records: T[]): T[] {
  const seen = new Set<string>();
  return records.filter((r) => (seen.has(r.locator) ? false : (seen.add(r.locator), true)));
}

function attackTags(attack: RequestInspection | null): string[] {
  if (!attack) return [];
  const clip = (t: string): string =>
    t.length > ATTACK_SLOT_MAX ? `${t.slice(0, ATTACK_SLOT_MAX - 1)}…` : t;
  return [
    `web-attack: ${showToken(attack.labels.join(","))}`,
    ...attack.slots.map((s) => `matched: ${clip(showToken(s))}`),
  ];
}

function describe(head: string, tags: string[], tail: string, mark: string): string {
  const room = DESCRIPTION_MAX - mark.length - head.length - tail.length;
  return `${head}${packTags(tags, Math.max(0, room))}${tail}${mark}`;
}

// A request row packs its bodies one by one into the room the fixed tags leave, and names the
// bodies it could not show with a count that is TRUE of the words — never "+1 more" over a list
// the length bound silently cut short.
function describeRequest(head: string, groups: RequestTagGroups, tail: string, mark: string): string {
  const fixed = DESCRIPTION_MAX - mark.length - head.length - tail.length;
  const beforeText = packTags(groups.before, fixed);
  const afterText = packTags(groups.after, Math.max(0, fixed - beforeText.length));
  const remainder = (n: number): string => (n > 0 ? ` [+${n} more bod${n === 1 ? "y" : "ies"}]` : "");
  let room = fixed - beforeText.length - afterText.length;
  const shown: string[] = [];
  for (const tag of groups.bodies) {
    const left = groups.bodiesTotal - shown.length - 1;
    if (tag.length + 3 + remainder(left).length > room) break;
    shown.push(tag);
    room -= tag.length + 3;
  }
  const bodiesText = shown.length ? ` [${shown.join("] [")}]` : "";
  return `${head}${beforeText}${bodiesText}${remainder(groups.bodiesTotal - shown.length)}${afterText}${tail}${mark}`;
}

function mapRow(t: WebTally): MappedEvent {
  const mark = identityMark(t.key);
  const n = t.count;
  const plural = n === 1 ? "" : "s";
  if (t.overflow || !t.first) {
    const what = t.kind === "web" ? "request" : "transfer";
    return {
      timestamp: t.firstTs,
      description: `[overflow: ${n} ${what} record${plural} beyond the retained bound folded; none shown]${mark}`,
      severity: "Info",
      mitre: [],
      canonical: envelopeOf(t),
      aggKey: t.key,
      sources: [t.source.startsWith("zeek") ? "Zeek" : "Suricata"],
      origin: "wire",
    };
  }
  const c = t.first;
  if ("req" in c) {
    const { attack, spillFamilies, spillMitre } = t.inspection ?? inspect(c);
    const graded: Severity = attack || spillFamilies.length ? "Medium" : "Info";
    const mitre = [...new Set([...spillMitre, ...(attack ? ["T1190"] : [])])];
    const groups = requestTags(c, hopCoverage(c));
    const before = [
      ...attackTags(attack),
      ...(spillFamilies.length ? [`secret in request: ${spillFamilies.join(",")}`] : []),
      ...groups.before,
    ];
    return {
      timestamp: t.firstTs,
      description: describeRequest(requestHead(c), { ...groups, before }, ` — ${n} record${plural}`, mark),
      severity: graded,
      mitre,
      canonical: envelopeOf(t),
      aggKey: t.key,
      sources: [c.req.source === "zeek-http" ? "Zeek" : "Suricata"],
      origin: "wire",
      ...(c.req.src ? { srcIp: c.req.src } : {}),
      ...(c.req.dst ? { dstIp: c.req.dst } : {}),
      ...(c.req.port ? { port: c.req.port } : {}),
    };
  }
  const x = c.xfer;
  const identity = isFileIdentity(c.coverage);
  return {
    timestamp: t.firstTs,
    description: describe(transferHead(c), transferTags(c), ` — ${n} record${plural}`, mark),
    severity: "Info",
    mitre: [],
    canonical: envelopeOf(t),
    aggKey: t.key,
    sources: [x.source === "zeek-files" ? "Zeek" : "Suricata"],
    origin: "wire",
    ...(identity && x.sha256 ? { sha256: x.sha256 } : {}),
    ...(identity && x.md5 ? { md5: x.md5 } : {}),
    ...(x.flowSrc ? { srcIp: x.flowSrc } : {}),
    ...(x.flowDst ? { dstIp: x.flowDst } : {}),
  };
}

/** Rows naming a file first, then graded rows, then the most seen, then the earliest — up to `budget`. */
export function mapWebRows(sink: Map<string, WebTally>, budget: number): MappedEvent[] {
  return [...sink.values()]
    .sort(
      (a, b) =>
        Number(b.namesFile) - Number(a.namesFile) ||
        Number(b.graded) - Number(a.graded) ||
        b.count - a.count ||
        a.firstTs.localeCompare(b.firstTs),
    )
    .slice(0, budget)
    .map(mapRow);
}

export type { CoverageKind };
