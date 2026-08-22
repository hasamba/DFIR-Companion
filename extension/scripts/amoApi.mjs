// The two AMO API calls the release workflow needs, in a file that can be unit-tested.
//
// They started as `node -e` one-liners inside release-artifacts.yml. That is the worst place for
// logic whose failure modes are "silently submits nothing" and "reports success against the wrong
// add-on": the job only runs on a tag, so a mistake surfaces on a release, hours later, once.

/**
 * AMO authenticates with a short-lived HS256 JWT minted from the issuer/secret pair, NOT with a
 * bearer token you can store. Signed here rather than pulled from a library so the release path
 * has one less thing to install.
 *
 * @param {string} issuer AMO_JWT_ISSUER
 * @param {string} secret AMO_JWT_SECRET
 * @param {{ now?: number, jti?: string }} [opts] Injected for tests; both default sensibly.
 * @returns {Promise<string>} A signed JWT, valid for four minutes.
 */
export async function mintJwt(issuer, secret, opts = {}) {
  const { createHmac, randomUUID } = await import("node:crypto");
  if (!issuer || !secret) throw new Error("mintJwt needs both an issuer and a secret");
  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  const iat = opts.now ?? Math.floor(Date.now() / 1000);
  const head = b64({ alg: "HS256", typ: "JWT" });
  // `jti` must be unique per request — AMO rejects a replayed one. randomUUID, not Math.random:
  // a collision here reads as an auth failure on a release, which is a miserable thing to debug.
  const body = b64({ iss: issuer, jti: opts.jti ?? randomUUID(), iat, exp: iat + 240 });
  const sig = createHmac("sha256", secret).update(`${head}.${body}`).digest("base64url");
  return `${head}.${body}.${sig}`;
}

/**
 * Does AMO already hold this version of this add-on?
 *
 * Deliberately strict about what counts as "no". An unparseable body, an auth error, or a
 * results-shaped object that is not an array are all UNKNOWN, never "no" — because the caller
 * turns "no" into "submit" and "yes" into "skip", and guessing either way on a release is worse
 * than stopping. See the CLI at the bottom.
 *
 * @param {string} raw The raw response body.
 * @param {string} version The version to look for, e.g. "0.36.0".
 * @returns {{ status: "yes" | "no" | "unknown", seen: string[], reason?: string }}
 */
export function findVersion(raw, version) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { status: "unknown", seen: [], reason: "response was not JSON" };
  }
  if (!parsed || typeof parsed !== "object") {
    return { status: "unknown", seen: [], reason: "response was not an object" };
  }
  if (!Array.isArray(parsed.results)) {
    // AMO's error bodies are objects with `detail`; an add-on with no versions still returns
    // `results: []`. A missing `results` therefore means the call failed, not that it is empty.
    const detail = typeof parsed.detail === "string" ? parsed.detail : "no results array";
    return { status: "unknown", seen: [], reason: detail };
  }
  const seen = parsed.results.map((v) => (v && typeof v.version === "string" ? v.version : "?"));
  return { status: seen.includes(version) ? "yes" : "no", seen };
}

/** Versions endpoint including unlisted/in-review ones — a fresh upload is not public yet. */
export function versionsUrl(addonId) {
  return `https://addons.mozilla.org/api/v5/addons/addon/${encodeURIComponent(addonId)}/versions/?filter=all_with_unlisted`;
}

/** Only AMO's own host may be followed. `next` is server-supplied data, not a trusted instruction. */
export function isAmoUrl(url) {
  try {
    return new URL(url).origin === "https://addons.mozilla.org";
  } catch {
    return false;
  }
}

/**
 * How many pages to follow before giving up. 25 versions per page, so this covers 2000 — far past
 * anything this add-on will reach, and still a bound rather than a `while (true)` against a remote
 * server that decides when the list ends.
 */
export const MAX_PAGES = 80;

/**
 * Does AMO hold this version, across ALL pages?
 *
 * The endpoint paginates at 25. Reading only the first page and concluding "absent" is wrong the
 * moment the add-on has 26 versions — and wrong in the one direction that hurts, because the
 * caller turns "no" into "submit" and AMO then rejects the duplicate. Re-running an OLDER tag's
 * workflow is exactly when the version sought is deep in the list.
 *
 * Every incomplete read is UNKNOWN, never "no": a failed page, a `next` pointing somewhere that is
 * not AMO, or running out of the page budget. "No" is returned only after the list is exhausted.
 *
 * Known limitation, not solvable from here: AMO reserves the version numbers of DELETED versions,
 * but listing those needs `filter=all_with_deleted`, which requires admin permissions this token
 * does not have. If a version was submitted and later deleted, this reports "no" and the upload
 * fails at AMO with a duplicate-version error. That failure is loud and correct; it just is not
 * one the pre-flight can pre-empt.
 *
 * @param {object} args
 * @param {string} args.addonId
 * @param {string} args.version
 * @param {string} args.token A JWT from mintJwt.
 * @param {typeof fetch} [args.fetchImpl] Injected by tests.
 * @param {number} [args.maxPages]
 * @returns {Promise<{ status: "yes" | "no" | "unknown", seen: string[], reason?: string, pages: number }>}
 */
export async function hasVersion({ addonId, version, token, fetchImpl = fetch, maxPages = MAX_PAGES }) {
  let url = versionsUrl(addonId);
  const seen = [];
  for (let page = 1; page <= maxPages; page++) {
    let raw;
    try {
      const res = await fetchImpl(url, { headers: { Authorization: `JWT ${token}` } });
      raw = await res.text();
    } catch (err) {
      return { status: "unknown", seen, reason: `request failed on page ${page}: ${err.message}`, pages: page };
    }
    const parsed = findVersion(raw, version);
    if (parsed.status === "unknown") {
      return { status: "unknown", seen, reason: parsed.reason, pages: page };
    }
    seen.push(...parsed.seen);
    if (parsed.status === "yes") return { status: "yes", seen, pages: page };

    const next = readNext(raw);
    if (!next) return { status: "no", seen, pages: page }; // list exhausted — a real absence
    if (!isAmoUrl(next)) {
      return { status: "unknown", seen, reason: `next page pointed off-site: ${next}`, pages: page };
    }
    url = next;
  }
  return {
    status: "unknown",
    seen,
    reason: `gave up after ${maxPages} pages without exhausting the list`,
    pages: maxPages,
  };
}

/** `next` from a page body, or null when this is the last page. Never throws — the body is parsed. */
function readNext(raw) {
  try {
    const next = JSON.parse(raw).next;
    return typeof next === "string" && next ? next : null;
  } catch {
    return null;
  }
}

/**
 * CLI: `node amoApi.mjs has-version <addonId> <version>`
 *
 * Prints `yes` or `no` on stdout. Exits 0 for either — both are answers. Exits 2 when the answer
 * is UNKNOWN, which the workflow treats as a stop rather than a guess.
 */
if (process.argv[1] && process.argv[1].endsWith("amoApi.mjs")) {
  const [, , command, addonId, version] = process.argv;
  if (command !== "has-version" || !addonId || !version) {
    console.error("usage: node amoApi.mjs has-version <addonId> <version>");
    process.exit(2);
  }
  const token = await mintJwt(process.env.AMO_JWT_ISSUER, process.env.AMO_JWT_SECRET);
  // Two attempts: a single transient 5xx should not decide a release, but a real outage should
  // stop it rather than be retried into a duplicate submission.
  let last = { status: "unknown", seen: [], reason: "not attempted", pages: 0 };
  for (let attempt = 1; attempt <= 2; attempt++) {
    last = await hasVersion({ addonId, version, token });
    if (last.status !== "unknown") break;
  }
  if (last.status === "unknown") {
    console.error(`could not determine whether AMO holds ${version}: ${last.reason}`);
    process.exit(2);
  }
  if (last.status === "no" && last.seen.length) {
    console.error(`AMO has: ${last.seen.slice(0, 5).join(", ")}`);
  }
  console.log(last.status);
}
