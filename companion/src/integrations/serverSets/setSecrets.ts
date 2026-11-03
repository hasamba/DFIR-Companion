import { readFileSync } from "node:fs";
import type { ServerSet } from "./types.js";

// A PEM body line or a bare token: no spaces, no key: prefix. Header lines and YAML keys do not match.
const SECRET_LINE = /^[A-Za-z0-9+/=_-]{16,}$/;

const PEM_BEGIN = /^-----BEGIN [A-Z0-9 ]+-----$/;
const PEM_END = /^-----END [A-Z0-9 ]+-----$/;

/**
 * The key and certificate lines of a Velociraptor API config file: every body line between PEM
 * BEGIN/END markers (any length, so a short last line counts), plus any long bare token line.
 * Empty when the file cannot be read.
 */
export function veloConfigSecrets(path: string): string[] {
  try {
    const out = new Set<string>();
    let inPem = false;
    for (const raw of readFileSync(path, "utf8").split(/\r?\n/)) {
      const line = raw.trim();
      if (PEM_BEGIN.test(line)) inPem = true;
      else if (PEM_END.test(line)) inPem = false;
      else if (line && (inPem || SECRET_LINE.test(line))) out.add(line);
    }
    return [...out];
  } catch {
    return [];
  }
}

/** Every secret value one opened set holds: IRIS key, Timesketch password, Velociraptor key material. */
export function secretsOfSet(set: ServerSet): string[] {
  const out: string[] = [];
  if (set.iris?.apiKey) out.push(set.iris.apiKey);
  if (set.timesketch?.password) out.push(set.timesketch.password);
  if (set.velociraptor?.apiConfigPath) out.push(...veloConfigSecrets(set.velociraptor.apiConfigPath));
  return out;
}
