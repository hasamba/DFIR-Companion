import type { Adapter } from "./types.js";
import { splunkAdapter } from "./splunk.js";
import { velociraptorAdapter } from "./velociraptor.js";
import { elasticAdapter } from "./elastic.js";
import { crowdstrikeAdapter } from "./crowdstrike.js";
import { securityOnionAdapter } from "./securityonion.js";
import { socratesAdapter } from "./socrates.js";
import { volwebAdapter } from "./volweb.js";

// The known-tool registry. Order is significance-only (matchUrl is meant to be mutually exclusive
// across these consoles); the first matching adapter wins.
export const ADAPTERS: readonly Adapter[] = [
  splunkAdapter,
  velociraptorAdapter,
  securityOnionAdapter,
  socratesAdapter,
  elasticAdapter,
  crowdstrikeAdapter,
  volwebAdapter,
];

/**
 * Return the adapter that recognizes this page URL, or null. Pure. URL-only — see adapterForPage()
 * below for the DOM-aware version the content script actually calls as its DEFAULT activation
 * decision (on an unrecognized site, plain screenshot capture is used unless the popup's manual
 * override forces an adapter on — see adapters/override.ts). Invalid URLs yield null rather than
 * throwing.
 */
export function adapterForUrl(href: string): Adapter | null {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  // Only consider real web pages — never chrome:// / extension pages.
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  for (const adapter of ADAPTERS) {
    try {
      if (adapter.matchUrl(url)) return adapter;
    } catch {
      /* a misbehaving matcher must not break detection of the others */
    }
  }
  return null;
}

export function adapterById(id: string): Adapter | null {
  return ADAPTERS.find((a) => a.id === id) ?? null;
}

/**
 * Same as adapterForUrl, but when no adapter's matchUrl wins, falls back to each adapter's DOM
 * signature (matchDom) — covers a known tool deployed behind a reverse proxy, a vanity hostname, or
 * a custom path that the URL alone can't identify (issue #76). URL match always takes precedence:
 * matchDom is only consulted once every matchUrl has already failed, so a confident URL match is
 * never shadowed by a coincidental DOM match. `doc` is optional so callers without a DOM (tests,
 * background/service-worker contexts) still get plain URL-only behavior.
 */
export function adapterForPage(href: string, doc?: Document): Adapter | null {
  const byUrl = adapterForUrl(href);
  if (byUrl) return byUrl;
  if (!doc) return null;
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  for (const adapter of ADAPTERS) {
    if (!adapter.matchDom) continue;
    try {
      if (adapter.matchDom(doc)) return adapter;
    } catch {
      /* a misbehaving matcher must not break detection of the others */
    }
  }
  return null;
}
