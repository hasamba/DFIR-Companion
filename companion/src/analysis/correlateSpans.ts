// The client- and resolver-written spans correlation must never read as an artifact, split out of
// correlate.ts (#1714) so that file stays under the size limit. Behaviour is unchanged.

// A span an importer shows VERBATIM from a client- or resolver-written field — a web-log line's
// appended trailer (#933 item 1), a DNS record's queried name and returned values (#933 item 2), a
// TLS record's SNI and certificate names (#933 item 6), a quarantine record's agent, URLs, origin
// title and sender (#933 item 7) —
// is a label, never an artifact: nothing inside it may become a fallback hash or path, or an
// attacker who appends `/tmp/payload.exe` to a request, or answers a TXT query with 32 hex, would
// union that row with the endpoint event that really carries the file or the hash. Each span is
// well-formed by construction (the importer turns `]` into `)` inside it), so it cannot close early.
// A web request or transfer row (#993) shows the request target, the MIME type, the filename, the
// user, the Referer, the User-Agent, the proxy headers and the server's stated redirect target the
// same way — each in its own span. A TLS relationship row (#997) shows names, subjects, issuers,
// chain-check strings and its leads (which name SNIs) in the spans listed last; a quarantine
// attribute row (#1037) shows the file's path and the joined download facts the same way, and the
// merge-time persistence link (quarantinePersistenceLink.ts) its program path and download facts.
const UNTRUSTED_SPAN_RE =
  /\[(?:trailer|query|returned|answers|rcode|the record also carries returned values|sni|cert|client cert|certificate|kind|agent|data url|origin|sender|quarantine mark|quarantine mark \(not decodable\)|quarantine url|event identifier not decodable|target|mime|filename|user|referrer|ua|proxied|matched|redirect target \(stated by the server\)|name|subject|issuer|presented under|presented by|presented to|under|served with|chain check|lead|certificate records for this identity disagree|file|local file|local files|download event|download record|persisted as|origin page visited|download URL visited|preceded a quarantine record|ran a quarantine-marked file|quarantine-marked file used|a quarantine-marked file|path): [^\]]*\]/g;
export function scannedText(description: string): string {
  return description.replace(UNTRUSTED_SPAN_RE, " ");
}
