// A Velociraptor api.config.yaml shaped like the real one: block-style PEM blocks, 64-char body lines,
// a short last line per block. `sentinel` sits inside the private-key body. Values are word-like fakes.
export const VELO_SHORT_LAST_LINE = "shortlastline=";

const body = (word: string): string[] => [word.repeat(8).slice(0, 64), word.repeat(8).slice(0, 64)];

function pem(label: string, lines: string[]): string {
  const indented = [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`].map((l) => `  ${l}`);
  return indented.join("\n");
}

/** The 64-char private-key body line that carries the sentinel. */
export function veloKeyBodyLine(sentinel: string): string {
  return `${"A".repeat(19)}${sentinel}${"B".repeat(64 - 19 - sentinel.length)}`;
}

export function veloApiConfigYaml(sentinel: string): string {
  const keyLine = veloKeyBodyLine(sentinel);
  return [
    "version:",
    "  name: velociraptor",
    "ca_certificate: |",
    pem("CERTIFICATE", [...body("cafake"), VELO_SHORT_LAST_LINE]),
    "client_cert: |",
    pem("CERTIFICATE", [...body("clientfake"), VELO_SHORT_LAST_LINE]),
    "client_private_key: |",
    pem("RSA PRIVATE KEY", [...body("keyfake"), keyLine, VELO_SHORT_LAST_LINE]),
    "api_connection_string: velo.example.com:8001",
    "name: api-analyst",
    "",
  ].join("\n");
}
