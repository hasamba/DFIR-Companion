# Custom (declarative) importers

A **custom importer** teaches the DFIR Companion to ingest a file format it doesn't ship a
built-in parser for — your EDR's CSV export, a bespoke SIEM dump, a tool's JSON — **without
writing any code**. You describe, in a small JSON file, (1) how to **recognise** the file and
(2) how to **map** each row into a forensic event + IOCs. It is pure data: the Companion
interprets it, nothing from your file is ever executed.

A matching file then imports through the normal **Import** button on the dashboard — detection
is automatic, and the events/IOCs flow through the exact same pipeline as a built-in importer
(cross-source correlation → import diff → IOC-whitelist/NSRL auto-legitimate → re-synthesis).

## Where importer files live

Drop each importer's `*.json` file into the **importers folder**:

- Default: an `importers/` directory **beside your `cases/` root** (created on first save).
- Override: set **`DFIR_IMPORTERS_DIR`** in `.env` to a folder of your choice (absolute path
  used as-is; a relative path anchors to the cases-root parent).

Files **auto-load at server startup**. After adding or editing a file, click
**Settings → Importers → Reload** (or restart the server) to apply it without losing your place.
**Invalid files are never fatal** — a malformed importer is skipped and shown with its
field-pathed errors in Settings → Importers, while the valid ones keep working.

## Authoring with an LLM (the easy path)

1. On the dashboard, go to **Settings → Importers** and click **Copy LLM prompt**.
2. Paste that prompt into any LLM, then paste a **representative sample of your exported file**
   (a few rows/records) below it.
3. The LLM returns one JSON importer definition. Save it into the importers folder as
   `<your-id>.json`.
4. Click **Reload** in Settings → Importers (or restart). If the file has errors, they're shown
   inline — paste them back to the LLM to fix.

The prompt embeds the full schema and a worked example, so the LLM has everything it needs.

## `ImporterSpec` field reference

A definition is one JSON object:

- **`id`** — kebab-case unique id (`a-z`, `0-9`, `-`); must not collide with a built-in importer
  name.
- **`label`** — human-readable name shown in the UI.
- **`version`** — always `1`.
- **`description`** — optional free text.
- **`match`** — how to detect the file:
  - **`format`** — `csv` | `json` | `ndjson` | `auto`.
  - For **CSV**: **`requireHeaders`** (all must be present) and/or **`anyHeaders`** (≥1 present).
  - For **JSON**: **`requireKeys`** / **`anyKeys`**, and **`keyEquals`** (`{ key: regexp }`).
  - **`filenamePattern`** — optional regex on the filename.
  - **`priority`** — lower is tried earlier (default `100`).
- **`map`** — how to turn each record into an event + IOCs:
  - **`timestamp`** *(required)* — `{ from: [columns], format: auto|iso|epoch_s|epoch_ms }`.
  - **`description`** *(required)* — a template string with `{{ColumnName}}` placeholders.
  - **`severity`** — a fixed level, OR `{ from: [col], map: { value: Level }, default: Level }`.
  - **`asset`** (host), **`user`** (account), **`processName`**, **`parentName`**, **`sha256`**,
    **`md5`**, **`path`**, **`srcIp`**, **`dstIp`**, **`port`** — each
    `{ from: [columns], transform? }`.
  - **`mitre`** — `{ from: [col] }` (parses `Txxxx` techniques) or `{ fixed: [ "T1059", … ] }`.
  - **`iocs`** — a list of `{ type, from: [columns] }` (types: `ip` | `domain` | `hash` | `file`
    | `process` | `url` | `other`) or `{ autoExtract: [columns] }` (scrape any IOC from those
    columns).
  - **Levels**: `Critical` | `High` | `Medium` | `Low` | `Info`.
  - **Transforms**: `trim` | `lowercase` | `basename` | `cleanIp` | `defang` | `refang`.
- **`options`** — `{ aggregate: true, minSeverity?, maxEvents?, maxIocs? }`.

## Worked example

See **[`mde-advanced-hunting.json`](./mde-advanced-hunting.json)** in this folder — a complete,
valid importer for a Microsoft Defender XDR *Advanced Hunting* CSV/JSON export. It's the same
example embedded in the LLM-authoring prompt, so it can never drift from the schema. Copy it as a
starting point and adapt the headers/columns to your own export.

## Precedence: built-in vs. custom

When a file could match both a built-in importer and one of yours, a per-server setting decides
who wins (Settings → Importers):

- **`builtin-first`** *(default)* — a specific built-in parser wins; a custom importer only fills
  a gap the built-ins don't confidently claim.
- **`external-first`** — your custom importers are tried before the built-ins.

## Security

Importers are **declarative only — no code is ever executed**. Your file's contents are parsed,
not run. User-supplied regexes are length-bounded to guard against catastrophic backtracking
(ReDoS), and the `description` template engine is helper-free (no expression injection). Custom
importers feed the same downstream chain as built-ins, with the same safety filters.
