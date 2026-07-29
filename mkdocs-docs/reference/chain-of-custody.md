# Chain of Custody

A court-ready record of what happened to every piece of evidence the Companion stores: who collected it, when, from where, its SHA-256, and every subsequent access, transfer or export.

The Activity Log answers *what was done to this case*. Chain of custody answers *what happened to this artifact* — the question you have to be able to answer if a case goes to court or in front of a regulator.

---

## What gets recorded, and when

**Nothing to switch on, and nothing to remember.** Every artifact the Companion writes to disk is recorded automatically:

| Artifact | Recorded as |
|---|---|
| Screenshots from the browser extension | `collected` — with the page URL it came from, the capture trigger, and `browser-extension` as the collector |
| Imports (every format) | `collected` |
| Files dropped in the case's `drop/` folder | `collected`, once a tool ingests them |

Recording is hooked onto the two functions that actually write evidence, not onto the individual import routes — so an import path added in a future version is covered from the day it ships, rather than silently skipping custody.

**Exports** append an `exported` event for every artifact in the case, re-hashed at the moment it leaves:

- Encrypted case archive (`.dfircase`)
- ZIP case archive
- Redacted case package

Report, STIX, IRIS and ClickUp exports carry conclusions rather than evidence, so they are left to the Activity Log.

### Recording something by hand

Evidence the Companion never stored itself — a mounted disk image, output from an external tool, or a physical handover — is recorded through the API:

```bash
curl -X POST http://127.0.0.1:4773/cases/INC-1/custody \
  -H 'content-type: application/json' \
  -d '{"artifactPath":"/mnt/evidence/laptop.dd","collectedBy":"alice","source":"seized 2026-07-28","event":"collected"}'
```

`event` is one of `collected`, `accessed`, `transferred`, `exported`. An unrecognised value is **rejected** rather than quietly filed as a collection — a custody chain that silently relabels what happened is worse than one that refuses the entry. The Companion hashes the file itself; you cannot supply the hash.

The path is read as given and may live outside the case directory, which is deliberate: evidence usually does. A closed or archived case refuses new records until you reopen or restore it.

---

## The chain

Records live in `custody.jsonl` inside the case's `metadata/` folder, one JSON object per line. Each record carries:

| Field | Meaning |
|---|---|
| `artifactPath` | Where the artifact is. Stored **relative to the case folder** when it lives inside it, so archiving a case or moving the cases root does not invalidate the record |
| `sha256` | The artifact's hash at the moment of this event |
| `event` | `collected` / `accessed` / `transferred` / `exported` |
| `collectedBy`, `collectedAt`, `source`, `trigger` | Who, when, from where, and what caused it |
| `seq` | Position in this case's chain |
| `prevHash` | SHA-256 of the **previous line in the file** |

That last field is what makes the log a chain rather than a list. Editing or removing an entry breaks the link at the following line, so tampering is visible instead of silent.

!!! note "Two things are deliberately *not* treated as tampering"
    Records written before a case had a chain carry no `prevHash` and are skipped rather than condemned. And a **gap** in `seq` is legal — a failed write burns its number by design, so numbers are never reused, only skipped. Only a `seq` that fails to advance is flagged, because that means a replay.

---

## Verification

Two questions get asked, and both matter:

- **Did the evidence change?** Every artifact is re-hashed and compared.
- **Did the log change?** The chain is walked link by link.

Checking one without the other misses a whole class of tampering: swapping a file leaves the chain intact, and rewriting who collected an artifact leaves every hash intact.

### When it runs

| Trigger | Default | What it covers |
|---|---|---|
| **When you open a case** | On | Just that case, in the background, re-checked at most every 4 hours |
| **Scheduled sweep** | Off | Every case including archived ones, on a timer you set |

The on-open check is the default because it gives you a fresh answer at the moment you are actually relying on the evidence, without an idle install spending hours re-hashing cases nobody is looking at.

!!! warning "What the default does not cover"
    On-open verification cannot see corruption in a case nobody opens — you find out when you next open it. If you want unattended assurance across the whole store, switch the scheduled sweep on (see [Settings](settings.md)).

Failures raise a warning in the server log and a notification on the affected case, and show up in **Diagnostics**:

```
-- Evidence integrity --
  verifies: on case open (re-checked after 4h)
  last verified 2h ago — all 1247 artifacts OK across 3 case(s)
```

### Verifying by hand

The **Chain of Custody** panel (see [Dashboard Panels](dashboard.md)) has a **Verify now** button that re-hashes the current case immediately and marks any failed artifact in red. The same check is available at `GET /cases/:id/custody/verify`, which returns both `mismatches` (evidence that changed) and `chainBreaks` (log entries that changed).

---

## The signed manifest

`custody-manifest.json` lists every artifact with its full chain, and is signed with this installation's secret (HMAC-SHA256 — the same secret that signs case-unlock cookies).

It exists to close a gap the chain cannot close on its own: **chopping entries off the end of the log leaves a shorter chain that verifies perfectly.** Nothing inside the file can detect that, because the file is exactly what an attacker controls. So the manifest records where the chain *ends* — the record count, the final `seq`, and the hash of the last line — and signs that along with the records.

You get it in four places:

- **In the report folder**, written every time you generate a report
- **Inside the encrypted case archive**
- **Inside the redacted case package** — built over the *redacted* records, so it describes the appendix that package actually ships
- **On demand** at `GET /cases/:id/custody/manifest`, or the **Signed manifest** link in the dashboard panel

!!! info "What the signature does and does not prove"
    A shared-secret signature proves the manifest has not been altered since *this installation* signed it — so **you** can later prove what you sent. It does **not** let a recipient verify anything on their own: verification needs the instance secret, which they do not have. Treat the manifest as a seal you can check, plus a machine-readable index of the chain for them, not as proof they can independently validate. Signing with an external PKI or HSM would change that, and is deliberately out of scope.

---

## In the report

The **Chain of Custody** appendix lists each artifact with its hash and every event that touched it. It is a normal report section: reorder or switch it off in **Settings → Report Templates**, like any other. It is on in the Standard template and off in the Executive Brief, where a per-artifact table is operator detail rather than client-facing content.

!!! info "What a redacted export keeps"
    In a **redacted case package** the appendix is redacted field by field rather than wholesale. Artifact hashes (`sha256`, `prevHash`), the ordinal and the event name survive intact, so a recipient can still check the chain against the evidence they hold — a SHA-256 reveals nothing about a file's contents, name or origin. Paths, source hosts and collector names are tokenized, and so is any field added to the record in future: only the four named above are exempt, so a new field is redacted by default rather than leaking by default.

---

## API summary

| Endpoint | What it does |
|---|---|
| `GET /cases/:id/custody` | Every custody record for the case |
| `POST /cases/:id/custody` | Record an artifact by hand (see above) |
| `GET /cases/:id/custody/verify` | Re-hash everything and walk the chain; returns `mismatches` + `chainBreaks` |
| `POST /cases/:id/custody/verify` | Kick off the same check in the background; returns immediately |
| `GET /cases/:id/custody/manifest` | The signed manifest |
