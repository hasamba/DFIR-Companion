// Web server and proxy access-log lines as Sigma records (#2203). Pure.
//
// The combined-log importer has no JSON record, so it hands Sigma a synthetic one written in
// Sigma's own web field names, built from what the line actually logged:
//   - "-" (not logged) OMITS the field, so a `field: null` rule (ReGeorg) can match; a logged empty
//     value stays "" (an empty-UA rule) — absent and empty are different facts.
//   - URI fields carry the raw text AND its decoding when they differ, split into path and query on
//     the RAW target first; decoding never resolves `../`.
//   - A field the request inspector clipped is listed in `__sigmaIncomplete`, so the evaluator
//     treats it as unknown rather than as complete evidence (Codex plan review).
// Which pack grades an import is decided once per import, never per line: one crafted absolute-URL
// request must not move itself into the proxy rules.

import { decodeRequestTarget } from "./webRequestDecode.js";
import type { SigmaRuleRef } from "./sigmaRuleSet.js";

export type WebPack = "webserver" | "proxy";

export interface WebLineParts {
  method: string;
  /** The request target as logged (clipped). */
  target: string;
  referer: string;
  ua: string;
  /** `%u` only — never the client-asserted ident. "" when not logged. */
  user: string;
  host: string;
  client: string;
  status: number;
  /** Which of target / referer / ua the inspector clipped. */
  clipped: ReadonlySet<string>;
}

type Record_ = Record<string, unknown>;

const notLogged = (v: string): boolean => v === "-";
/** The raw text, plus its decoding when that differs. */
const rawAndDecoded = (raw: string, decoded: string): string | string[] =>
  decoded !== raw ? [raw, decoded] : raw;
const decodePath = (p: string): string => decodeRequestTarget(p).decoded;
const decodeQuery = (q: string): string => decodeRequestTarget(`?${q}`).decoded.slice(1);

function split(target: string): { path: string; query: string | null } {
  const q = target.indexOf("?");
  return q >= 0 ? { path: target.slice(0, q), query: target.slice(q + 1) } : { path: target, query: null };
}

/** The origin-form part of an absolute URL (`http://h/p?q` → `/p?q`), or the target as is. */
function originForm(target: string): string {
  const m = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*(.*)$/i.exec(target);
  return m ? m[1] || "/" : target;
}

function extension(path: string): string | undefined {
  const last = path.split("/").pop() ?? "";
  const dot = last.lastIndexOf(".");
  return dot > 0 && dot < last.length - 1 ? last.slice(dot + 1) : undefined;
}

function set(rec: Record_, key: string, value: string | string[] | undefined): void {
  if (value !== undefined) rec[key] = value;
}

function common(rec: Record_, p: WebLineParts, uaKey: string): void {
  rec["cs-method"] = p.method;
  rec["sc-status"] = String(p.status);
  if (!notLogged(p.ua)) rec[uaKey] = p.ua;
  if (p.user && !notLogged(p.user)) rec["cs-username"] = p.user;
  if (p.host) rec["cs-host"] = p.host;
  if (p.client) rec["c-ip"] = p.client;
}

export function buildWebSigmaRecord(p: WebLineParts, pack: WebPack): Record_ {
  const rec: Record_ = {};
  const incomplete: string[] = [];
  const clipped = (field: string, keys: string[]) => {
    if (p.clipped.has(field)) incomplete.push(...keys);
  };
  if (pack === "webserver") {
    const { path } = split(p.target);
    set(rec, "cs-uri-query", rawAndDecoded(p.target, decodeRequestTarget(p.target).decoded));
    set(rec, "cs-uri-stem", rawAndDecoded(path, decodePath(path)));
    if (!notLogged(p.referer))
      set(rec, "cs-referer", rawAndDecoded(p.referer, decodeRequestTarget(p.referer).decoded));
    common(rec, p, "cs-user-agent");
    clipped("target", ["cs-uri-query", "cs-uri-stem"]);
    clipped("referer", ["cs-referer"]);
    clipped("ua", ["cs-user-agent"]);
  } else {
    set(rec, "c-uri", rawAndDecoded(p.target, decodeRequestTarget(p.target).decoded));
    if (p.method.toUpperCase() !== "CONNECT") {
      const origin = originForm(p.target);
      const { path, query } = split(origin);
      set(rec, "cs-uri", rawAndDecoded(origin, decodeRequestTarget(origin).decoded));
      const stem = rawAndDecoded(path, decodePath(path));
      set(rec, "c-uri-stem", stem);
      set(rec, "cs-uri-stem", stem);
      if (query !== null) set(rec, "c-uri-query", rawAndDecoded(query, decodeQuery(query)));
      set(rec, "c-uri-extension", extension(decodePath(path)));
    }
    if (!notLogged(p.referer)) set(rec, "cs-referer", p.referer);
    common(rec, p, "c-useragent");
    clipped("target", ["c-uri", "cs-uri", "c-uri-stem", "cs-uri-stem", "c-uri-query", "c-uri-extension"]);
    clipped("referer", ["cs-referer"]);
    clipped("ua", ["c-useragent"]);
  }
  if (incomplete.length) rec.__sigmaIncomplete = incomplete;
  return rec;
}

const REQUEST = /"([A-Z]+)\s+(\S+)[^"]*"/;

/** The pack for a whole import: a declared Squid log, else proxy only when most requests say so. */
export function chooseWebPack(
  lines: readonly string[],
  declaredSquid: boolean,
): { sourceId: "web-proxy" | "web-server"; pack: WebPack; reason: string } {
  if (declaredSquid) return { sourceId: "web-proxy", pack: "proxy", reason: "declared Squid log" };
  let requests = 0;
  let proxyShaped = 0;
  for (const line of lines) {
    const m = REQUEST.exec(line);
    if (!m) continue;
    requests++;
    if (m[1] === "CONNECT" || /^[a-z][a-z0-9+.-]*:\/\//i.test(m[2])) proxyShaped++;
  }
  const pct = requests ? Math.round((proxyShaped / requests) * 100) : 0;
  return requests > 0 && proxyShaped * 2 >= requests
    ? {
        sourceId: "web-proxy",
        pack: "proxy",
        reason: `inferred: ${pct}% of requests absolute-form or CONNECT`,
      }
    : {
        sourceId: "web-server",
        pack: "webserver",
        reason: `inferred: ${pct}% of requests absolute-form or CONNECT`,
      };
}

/**
 * May this rule RAISE severity on this line? Internet-facing servers are probed all day, so on a
 * webserver a match on a request the server did not answer 2xx/3xx only tags — unless the rule is a
 * web-shell rule (T1505.003), or constrains the status itself (its author already decided). Proxy
 * rules are never vetoed: a C2 beacon answered 404 is still C2.
 */
export function webSigmaMayGrade(sourceId: string, status: number): (ref: SigmaRuleRef) => boolean {
  if (sourceId !== "web-server") return () => true;
  const answered = status >= 200 && status < 400;
  return (ref) =>
    answered ||
    ref.mitre.some((t) => t === "T1505.003") ||
    (ref.fields ?? []).some((f) => f.toLowerCase() === "sc-status");
}

/** The note a vetoed match carries. */
export const WEB_VETO_NOTE =
  "not graded — the server did not answer this request with 2xx/3xx; scanners probe constantly, so only an answered request (or a web-shell rule) raises severity";
