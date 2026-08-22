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
  let last = { status: "unknown", seen: [], reason: "not attempted" };
  for (let attempt = 1; attempt <= 2; attempt++) {
    let raw = "";
    try {
      const res = await fetch(versionsUrl(addonId), { headers: { Authorization: `JWT ${token}` } });
      raw = await res.text();
    } catch (err) {
      last = { status: "unknown", seen: [], reason: `request failed: ${err.message}` };
      continue;
    }
    last = findVersion(raw, version);
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
