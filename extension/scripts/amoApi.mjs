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
 * A version string this code can actually act on.
 *
 * `""` is a string, and that is the whole problem: it satisfied a `typeof` check, entered the list
 * of versions read, and let a page containing an entry whose version was never really read produce
 * a definitive "not there" — while padding that list so the server's count reconciled. Blank is
 * unread, and unread is unknown. `readNext` has always held empty strings to this standard; this
 * is the same rule applied where it was missing.
 */
export function isReadableVersion(value) {
  return typeof value === "string" && value.trim() !== "";
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
  // Asking whether AMO holds version "" is a programming error, not a question with an answer.
  // Left unchecked it is a quiet one: an empty sought version against an empty entry "matches",
  // and against a healthy list returns a confident absence.
  if (!isReadableVersion(version)) {
    throw new TypeError(`findVersion needs a non-blank version, got ${JSON.stringify(version)}`);
  }
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
  // An entry whose `version` cannot be read is a version this code did NOT read — it may well be
  // the one being sought. Mapping it to a placeholder and concluding "not found" turns a contract
  // violation into the answer that makes the caller submit.
  //
  // It also quietly defeated the count reconciliation below: placeholders padded `seen`, so
  // seen.length matched the server's total while some versions had never actually been read.
  const readable = [];
  let unreadable = 0;
  for (const entry of parsed.results) {
    if (entry && typeof entry === "object" && isReadableVersion(entry.version)) {
      readable.push(entry.version);
    } else {
      unreadable++;
    }
  }

  // Precedence matters. A hit is definitive whatever else the page contained: the version is
  // there, so there is nothing left to be uncertain about and nothing to submit.
  if (readable.includes(version)) return { status: "yes", seen: readable };
  if (unreadable > 0) {
    return {
      status: "unknown",
      seen: readable,
      reason: `${unreadable} of ${parsed.results.length} entries had no readable version string`,
    };
  }
  return { status: "no", seen: readable };
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
    // Keep whatever the page DID yield, including when it is being rejected. When this stops a
    // release, the log should say what it managed to read — "unknown, saw 0.40.0 and 0.39.0" is a
    // diagnosis; "unknown, saw nothing" reads like a broken token.
    seen.push(...parsed.seen);
    if (parsed.status === "unknown") {
      return { status: "unknown", seen, reason: parsed.reason, pages: page };
    }
    if (parsed.status === "yes") return { status: "yes", seen, pages: page };

    const next = readNext(raw);
    if (next.kind === "malformed") {
      // `next` was present but not a usable link. That is not "the list ended" — it is a response
      // this code does not understand, and the two must not collapse into the same answer.
      return { status: "unknown", seen, reason: next.reason, pages: page };
    }
    if (next.kind === "end") {
      // The only path that may return a definitive absence, and only once the server's own count
      // agrees that everything was read.
      const total = readCount(raw);
      if (total.kind === "malformed") {
        return { status: "unknown", seen, reason: total.reason, pages: page };
      }
      if (total.kind === "number" && seen.length < total.value) {
        return {
          status: "unknown",
          seen,
          reason: `list ended after ${seen.length} version(s) but the server reported ${total.value}`,
          pages: page,
        };
      }
      return { status: "no", seen, pages: page };
    }
    if (!isAmoUrl(next.url)) {
      return { status: "unknown", seen, reason: `next page pointed off-site: ${next.url}`, pages: page };
    }
    url = next.url;
  }
  return {
    status: "unknown",
    seen,
    reason: `gave up after ${maxPages} pages without exhausting the list`,
    pages: maxPages,
  };
}

/**
 * Classify a page's `next` field into the THREE outcomes it actually has.
 *
 * Collapsing them into "falsy means the end" is what made malformed metadata read as a definitive
 * absence: `next: 42`, `next: {}` and `next: ""` are not "no more pages", they are a response this
 * code does not understand — and absence is the answer that makes the caller submit.
 *
 * @returns {{ kind: "url", url: string } | { kind: "end" } | { kind: "malformed", reason: string }}
 */
export function readNext(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { kind: "malformed", reason: "page body was not JSON" };
  }
  if (!parsed || typeof parsed !== "object") {
    return { kind: "malformed", reason: "page body was not an object" };
  }
  // Only an explicit null (or an absent key) means the list is finished. That is what AMO sends.
  if (parsed.next === null || parsed.next === undefined) return { kind: "end" };
  if (typeof parsed.next !== "string" || parsed.next === "") {
    return { kind: "malformed", reason: `next was ${JSON.stringify(parsed.next)}, not a URL` };
  }
  return { kind: "url", url: parsed.next };
}

/**
 * The server's own total, used to reconcile against what was actually read.
 *
 * Without it, a response claiming 99 versions while returning 25 and no `next` yields a confident
 * "not there" from a list that was never finished.
 *
 * @returns {{ kind: "number", value: number } | { kind: "absent" } | { kind: "malformed", reason: string }}
 */
export function readCount(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { kind: "malformed", reason: "page body was not JSON" };
  }
  if (!parsed || typeof parsed !== "object" || parsed.count === undefined || parsed.count === null) {
    // Not every paginated body is required to carry it, and failing every run over a missing
    // optional field would make the pre-flight useless. Absent means "cannot reconcile", not
    // "broken" — the `next` chain is still the primary signal.
    return { kind: "absent" };
  }
  if (typeof parsed.count !== "number" || !Number.isInteger(parsed.count) || parsed.count < 0) {
    return { kind: "malformed", reason: `count was ${JSON.stringify(parsed.count)}, not a whole number` };
  }
  return { kind: "number", value: parsed.count };
}

/**
 * CLI: `node amoApi.mjs has-version <addonId> <version>`
 *
 * Prints `yes` or `no` on stdout. Exits 0 for either — both are answers. Exits 2 when the answer
 * is UNKNOWN, which the workflow treats as a stop rather than a guess.
 */
if (process.argv[1] && process.argv[1].endsWith("amoApi.mjs")) {
  const [, , command, addonId, version] = process.argv;
  // `!version` alone lets " " through, and a blank version asks AMO a question with no answer.
  // Exit 2, the same code as "cannot tell", so the workflow stops rather than submitting.
  if (command !== "has-version" || !isReadableVersion(addonId) || !isReadableVersion(version)) {
    console.error("usage: node amoApi.mjs has-version <addonId> <version>  (neither may be blank)");
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
