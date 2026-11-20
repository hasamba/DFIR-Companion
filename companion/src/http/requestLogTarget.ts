/**
 * What the request logger writes for a request URL: the path, plus at most the NAMES of its query
 * parameters. Never their values.
 *
 * The request log is persistent and is copied into support bundles, and query strings carry values
 * that do not belong there — sign-in codes and state on the OIDC callback, return addresses on the
 * login page, tokens on download links. The names are enough to tell which variant of a route ran.
 */

/** A name longer than this, or a URL with more names than the cap, is not worth logging. */
const MAX_NAME_LENGTH = 64;
const MAX_NAMES = 16;
/** Plain identifiers only: anything else could be a value smuggled into the name slot. */
const SAFE_NAME = /^[A-Za-z0-9_.[\]-]+$/;

export function requestLogTarget(url: string): string {
  const noFragment = url.split("#", 1)[0];
  const q = noFragment.indexOf("?");
  if (q < 0) return noFragment;
  const path = noFragment.slice(0, q);
  const names = queryNames(noFragment.slice(q + 1));
  return names.length > 0 ? `${path}?${names.join("&")}` : path;
}

function queryNames(query: string): string[] {
  const names: string[] = [];
  for (const pair of query.split("&")) {
    const name = pair.split("=", 1)[0];
    if (!name || name.length > MAX_NAME_LENGTH || !SAFE_NAME.test(name)) continue;
    if (names.includes(name)) continue;
    names.push(name);
    if (names.length >= MAX_NAMES) break;
  }
  return names;
}
