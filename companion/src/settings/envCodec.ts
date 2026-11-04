import { parse } from "dotenv";

/**
 * The ONE reader and the ONE value encoder for the settings (.env) file (#2280).
 *
 * The server loads this file with dotenv at startup, so every in-process reader — Test /
 * reconnect, the Settings view, the AI key move — parses it with dotenv too. A second parser that
 * disagreed with startup is how a secret containing `#` passed Test and broke after a restart.
 *
 * The file has one more reader outside Node: `docker-entrypoint.sh` (`env_file_get`) pulls path
 * settings out of it before the privilege drop. That shell reader understands single and double
 * quotes taken literally and nothing else — no escapes, no backticks. So the encoder only writes
 * shapes both readers agree on:
 *
 *   1. bare, when dotenv reads it back exactly and it does not open with a quote character;
 *   2. 'single-quoted' (literal in dotenv, the entrypoint and Docker compose);
 *   3. "double-quoted", only when dotenv's round trip proves no escape sequence was expanded;
 *
 * and anything else — a value only a backtick could hold — is refused rather than written lossy.
 */

const QUOTE_CHARS = ["'", '"', "`"];
const PROBE_KEY = "K";

/** Parse settings-file text exactly as the server's startup loader does. */
export function parseEnvText(raw: string): Record<string, string> {
  return { ...parse(raw) };
}

function roundTrips(encoded: string, value: string): boolean {
  return parse(`${PROBE_KEY}=${encoded}`)[PROBE_KEY] === value;
}

/**
 * The text to write after `KEY=` so every reader gets `value` back unchanged, or null when no
 * encoding both readers share can hold it.
 */
export function encodeEnvValue(value: string): string | null {
  if (!QUOTE_CHARS.includes(value.charAt(0)) && roundTrips(value, value)) return value;
  for (const quote of ["'", '"']) {
    if (value.includes(quote)) continue;
    const encoded = `${quote}${value}${quote}`;
    if (roundTrips(encoded, value)) return encoded;
  }
  return null;
}
