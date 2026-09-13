# #933 item 7 — PREREQUISITE PHASE: a quarantine record says what it establishes (design v5 — converged at round 5; rounds 1–5 folded)

## The proposal
"Join supplied quarantine database records, extended attributes and download metadata using
genuine event/file identifiers. Preserve origin/referrer versus downloaded-resource distinctions and
decode each artifact's documented time representation explicitly." Guardrails: supported epoch/unit
combinations, missing attributes, differing browser behaviour, ambiguous identifiers, renamed files
and duplicate basenames; never infer local file identity from a URL basename; never convert every
timestamp with one epoch; never label quarantine presence as execution or maliciousness; version
fixtures separate legacy from current formats.

## State at 212b1128 (feat/batch-1)
`macosImport.ts` `mapQuarantine` (LSQuarantineEventsV2 dumped to CSV): the native Cocoa REAL
timestamp is not recognised (only a pre-converted ISO string works); the data URL's basename is
shown as the file (`: installer.dmg`); the key is `agent|host(dataUrl)` while the row shows the
full URLs and the sender (two downloads from one host fold); `LSQuarantineTypeNumber`,
`AgentBundleIdentifier`, `SenderAddress`, `OriginTitle`, `OriginAlias`, `EventIdentifier` are not
read; both URLs mint `url` + `domain` IOCs whatever their scheme; the `com.apple.quarantine` xattr
value is not decoded anywhere (the persistence collection captures a URL under `# quarantine:`).
Severity Info throughout — unchanged.

## The contract (authoritative)

### Sources
- **LSQuarantineEventsV2** rows (CSV/JSON dump). Native columns: `LSQuarantineEventIdentifier`
  (UUID), `LSQuarantineTimeStamp` (REAL, Cocoa seconds since 2001-01-01 — the DB's documented
  type), `LSQuarantineAgentBundleIdentifier`, `LSQuarantineAgentName`, `LSQuarantineDataURLString`,
  `LSQuarantineSenderName`, `LSQuarantineSenderAddress`, `LSQuarantineTypeNumber`,
  `LSQuarantineOriginTitle`, `LSQuarantineOriginURLString`, `LSQuarantineOriginAlias`. Aliases a
  converted export may use: `agent`, `data_url`/`url`, `origin_url`/`referrer`, `sender`,
  `timestamp`/`time`.
- **`com.apple.quarantine` xattr** value, collected verbatim under a persistence plist header
  (`# quarantine: 0083;5f3a1b2c;Safari;550E8400-E29B-41D4-A716-446655440000`); the legacy header
  form (a bare URL) stays accepted as `quarantineUrl`.

### Time (decoded by declared representation — never by magnitude)
- `LSQuarantineTimeStamp` holding a NUMBER → Cocoa seconds (schema fact). A Cocoa reading before
  2001-01-01 (negative) → unreadable.
- Any column holding an ISO-8601 string → ISO.
- A NUMBER under a column that names its epoch → that epoch: `unix_time` / `unix_seconds` /
  `epoch` / `epoch_seconds` = Unix seconds; `unix_ms` / `unix_millis` / `epoch_ms` / `epoch_millis`
  = Unix milliseconds (the column name is the exporter's declaration; the row names the column).
- A NUMBER under a generic header (`timestamp`, `time`) establishes NO epoch (an export may alias
  the native column: `SELECT LSQuarantineTimeStamp AS timestamp`) → unreadable. There is no import
  option: one existed through round 6 and was reachable only from unit tests (Codex round 7).
- The xattr's 2nd field → Unix epoch hex seconds (its documented form; NOT Cocoa).
- Unreadable → no timestamp claim: the row's timestamp is empty, the raw text is kept in the
  envelope (`timeRaw`), and the words say `[time: not readable — <encoding expected>]`. The
  encoding used is always named: `[time: Cocoa seconds]`, `[time: ISO]`, `[time: Unix seconds
  (column unix_time)]`.

### Row (one per DB record)
`macOS quarantine [kind: web download] [agent: Safari (com.apple.Safari)] [data url: https://…]
[origin: https://… ("title")] [sender: name <address>] [time: Cocoa seconds] [event: <UUID>]
[local file: not in this record — joined by the event identifier]`.
- Kind from `LSQuarantineTypeNumber` per Apple's `LSQuarantineType`: 0 web download, 1 other
  download, 2 email attachment, 3 message attachment, 4 calendar attachment, 5 other attachment;
  unknown → `type N (not in the table)`; absent → `kind not in this record`.
- "data url" is the downloaded RESOURCE; its last path segment is never called the file. Origin is
  the referring page — a distinct fact, shown apart.
- Every agent-written value (agent name, bundle id, both URLs, origin title, sender name and
  address) is rendered inside its labelled span through `showToken` + `breakHashRuns`, URLs ≤ 200
  chars; the labels `agent`, `data url`, `origin`, `sender`, `quarantine mark` join
  `UNTRUSTED_SPAN_RE`. A lossy row carries the identity mark.
- Severity Info; no MITRE.

### Identity
- **UUID grammar**: `8-4-4-4-12` hex, case-insensitive, canonicalised to lowercase (DB and xattr
  alike). Anything else is NOT an identifier: the row reads as "no UUID" (keyed on its facts) and
  says `[event identifier not decodable: <value, neutralised>]`; the value is never a join handle,
  but it IS a shown fact: the no-UUID key includes a framed digest of it (`eventIdRaw` in the
  envelope), so two records with different malformed ids stay two rows.
- With a valid UUID: `macos-quarantine|event:<uuid>|<facts digest>` — the UUID AND the digest of
  every shown fact (type, agent, bundle, URLs, title, sender, time). A re-dump of one record (same
  UUID, same facts) folds; two records that share a UUID but disagree on a fact are two rows, each
  saying `[event identifier shared by records with different facts]` (a post-parse pass over the
  file marks both), and the spec's join must refuse a UUID that names more than one fact set.
- Without: `macos-quarantine|<type>|<agent digest>|<bundle digest>|<data url digest>|<origin url
  digest>|<origin title digest>|<sender digest>|<time>` — every shown fact INCLUDING the time (a
  record is one download event; two a month apart are two): the normalised ISO time, or for an
  unreadable one `t?:<digest of timeRaw>`. The words say `[event identifier not in this record]`.

### Indicators
- Data URL → `url`; its host → `ip` or `domain` (the resource the agent fetched). Only `http(s)`
  and `ftp` data URLs mint; `file:`/`x-apple-…`/other schemes mint nothing.
- Origin URL → `url` + host ONLY when http(s) (a lure page); `mailto:` and others mint nothing.
- Sender name/address → never an indicator (kept in the envelope).

### xattr (`macosPersistRules.ts`)
`<flags hex>;<unix hex seconds>;<agent>;<UUID>` → flags per QuarantineSPI.h: 0x0001 download,
0x0002 sandbox, 0x0004 hard (no user consent), 0x0040 user-approved; other set bits shown as hex,
named nothing (`0083` = 0x0080 | 0x0002 | 0x0001 → `download, sandbox (+0x0080)`; `00c3` →
`download, sandbox, user-approved (+0x0080)`). Words: `quarantine mark: download, sandbox
(+0x0080); agent Safari; marked 2020-08-17T05:52:44Z (Unix hex); event 550E8400-…`. Each named bit
and the UTC conversion are tested independently. A malformed value (fewer than 4 fields, non-hex flags/time) is shown as text:
`quarantine mark (not decodable): <value>`. The agent and the raw value go through `showToken` +
`breakHashRuns`. The legacy URL form keeps today's words.

### Envelope (`canonicalEvent.ts`, additive)
`quarantine?: { kind?, typeNumber?, agent?, bundleId?, dataUrl?, originUrl?, originTitle?,
senderName?, senderAddress?, eventId?, timeEncoding: "cocoa-seconds" | "iso" | "unix-seconds" |
"unix-ms" | "unreadable", timeRaw?, localFile: "not in this record" }`.

### Manual, CHANGELOG, spec
- `importing.md`: "macOS quarantine records: what one record establishes" + the collection snippet
  switches to the raw xattr value (legacy accepted); CHANGELOG bullet.
- Spec: DB record ↔ file xattr by UUID; xattr ↔ file (path, mtime, hash); download → execution
  (a spawn of the file, Gatekeeper/XProtect log lines) — each an observed edge or an explicit
  gap; renamed files and duplicate basenames as fixtures; browser-history joins.

## Tests (TDD)
- `quarantineRecord.test.ts`: time — native number = Cocoa (with fraction), native ISO, generic
  numeric header = unreadable, epoch-named column = declared, negative,
  garbage; every type value + unknown + absent; xattr `0083;5f3a1b2c;Safari;UUID` exact words,
  unnamed bits, malformed; identity with/without UUID (re-dump folds; no-UUID rows keyed on every
  shown fact incl. origin title); indicators (http data URL yes; file: no; mailto origin no;
  address host → ip; sender never); an agent name that is an MD5 vs a structured-MD5 file event
  through `correlateEvents`; a data URL with brackets; a 2 KB URL keyed whole and marked; ≤ 600;
  UUID: upper/lower case fold; an invalid id is no identifier; one UUID with two fact sets = two
  marked rows; one UUID re-dumped = one row.
- `macosImport.test.ts`: existing four adjusted (`installer.dmg` appears inside `[data url: …]`,
  never as a file claim); a raw Cocoa dump parses to the right date.
- `macosPersist*.test.ts`: header with the raw xattr value → the decoded words; legacy URL form.

## Out of scope (stated)
The joins, Gatekeeper/XProtect logs, browser history, any grade above Info.

## Rounds
- Round 1 (4): flags reversed → SPI table; UUIDs lost by folding → UUID is the identity; agent
  fields outside the spans → all spans; magnitude-based epoch → declared encoding.
- Round 5 (1): an invalid id was shown but not keyed → `eventIdRaw` digest in the facts key.
- Round 4 (1): no UUID grammar/case/duplicate policy → strict grammar, lowercase canonical form,
  invalid = no identifier, UUID + facts digest keyed, shared-UUID-different-facts rows marked.
- Round 3 (2): the xattr fixture asserted a bit it does not carry and a wrong UTC conversion →
  corrected, bits tested singly; no-UUID identity omitted time → time keyed.
- Round 2 (2): superseded rules still normative → rewritten as one contract; generic numeric
  headers assumed Unix → unreadable unless declared.

## Code round 1 (Codex, five findings)
1. Alias-only converted dumps (no `LSQuarantine` header) routed to the unified-log mapper. Fix:
   a coherent alias set (data_url/origin_url + event_id/agent/referrer) is a quarantine dump.
2. A non-ISO date string ("May 7, 2026 @ …") was normalised and labelled ISO/UTC. Fix: an explicit
   ISO-8601-with-zone grammar or unreadable.
3. A Cocoa row and an ISO row of one instant shared a facts digest. Fix: the encoding is framed
   into the facts.
4. An undecodable xattr fell back to "downloaded from <garbage>". Fix: legacy URL only when it is
   a URL; otherwise `quarantine mark (not decodable): …`.
5. A URL-less record (an email attachment) was dropped. Fix: every record with any fact is a row.

## Code round 2 (Codex, three findings)
1. The legacy URL was rendered raw → a hash-shaped path joined a file event. Fix: `[quarantine
   url: …]` span, neutralised and hash-broken; label in `UNTRUSTED_SPAN_RE`.
2. `Date.parse` rolled impossible dates (04-31, 02-29 in a common year). Fix: components checked
   against a UTC probe before normalisation.
3. Variants under one UUID were unbounded and pushed a legitimate record past the cap. Fix:
   `boundQuarantineVariants` — 16 fact sets per UUID, the rest fold into one overflow row.

## Code round 3 (Codex, four findings)
1. An overflow row kept one folded record's envelope. Fix: a `folded: true` envelope with only the
   identifier; no IOCs from folded rows.
2. Alias routing counted synonyms twice and missed `url`. Fix: resource dimension (`data_url`/`url`)
   + one signal dimension (event_id | agent | origin_url/referrer).
3. A generic `id` was promoted to the event UUID. Fix: only `LSQuarantineEventIdentifier`/`event_id`.
4. IOCs were minted for every variant before the bound. Fix: per-row IOCs merged after the bound,
   linked to the surviving rows only.

## Code round 4 (Codex, three findings)
1. A clipped malformed id or an unreadable time was identity the words did not carry → no mark →
   folded after import. Fix: both count as lossy.
2. The JSON route classified the whole array. Fix: record by record.
3. Signed bitwise math showed `0x80000000` as negative. Fix: unsigned (`>>> 0`).

## Code round 5 (Codex, two findings)
1. With aggregation off, the per-UUID bound only renamed the excess rows; 300 variants still emitted
   300 rows. Fix: `boundQuarantineVariants` returns the rows that remain — every kept variant and
   ONE overflow row per UUID that says how many records it folds — and the importer drops the rest
   from the mapped list before aggregation.
2. A numeric time outside Date's range came back as a readable encoding with an empty ISO. Fix: an
   empty conversion is `unreadable` in every numeric branch (raw kept, row marked).

## Code round 6 (Codex, three findings)
1. Two unreadable type values (`x`, `y`) folded into one "kind not readable" row. Fix: the raw
   value is kept (`typeRaw`), shown neutralised, and part of the facts digest.
2. A URL past 500 characters minted a prefix as the `url` indicator — a URL the record never
   held. Fix: the whole URL or no `url` indicator (the host still is one); the envelope says why.
3. The overflow row's canonical time was built from the first folded record, then its timestamp
   moved to the earliest. Fix: words, envelope and canonical form are built once, after the time is
   final.

## Code round 7 (Codex, one finding)
1. The `quarantineTime` import option was reachable only from unit tests: no route, job parameter
   or dashboard field carried it, so a converted dump's numbers were always unreadable in
   production. Fix: the option is gone; a converted dump declares its epoch in the column name
   (`unix_time`/`epoch` = seconds, `unix_ms`/`epoch_ms` = milliseconds), which needs no route or
   UI and is the exporter's own declaration. Generic `timestamp`/`time` stay unreadable.

## Code round 8 (Codex, one finding)
1. Three epoch spellings `declaredEpoch` accepted (`epoch_seconds`, `unix_millis`, `epoch_millis`)
   were not in the column list the reader extracts, so their rows had no time and two rows with
   different declared times folded. Fix: the column list holds every spelling; a test walks each
   through the import and keeps two declared times as two rows.
