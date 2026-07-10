# Case Management

## Creating a Case

Toolbar → **+ New case**. Fill in Case ID, name, and investigator.

Cases live in the `cases/` folder (location configured by `DFIR_CASES_ROOT`).

## Switching Between Cases

The case selector dropdown (top-left of dashboard) lists all cases, newest first. Select one to load it.

## Case Lifecycle

Each case has a status: **Open** or **Closed**.

Toolbar **☰ Case lifecycle** menu lets you:

- **Close** a case (marks it inactive)
- **Archive** a case — packages it as a ZIP with a SHA-256 manifest
- **🔒 Password…** — set, change, or remove a password on this case (see below)
- **🗑️ Delete…** a case — permanently removes the case's directory (see below)

The toolbar also shows a disk-space warning if the cases folder is running low.

## Case Password Protection

**☰ Case lifecycle → 🔒 Password…** sets a password on a case: opening it in the dashboard then
requires that password. A **"remember on this computer"** checkbox skips the prompt on later visits
from the same browser; leave it unchecked and the case re-locks the moment you switch away, refresh,
or close the tab.

Enforced server-side — an unlock cookie gates every `/cases/:id/*` route, not just a UI prompt — but
the capture extension's evidence ingestion keeps working while a case is locked, so screenshots aren't
lost while you're away. Setting or changing a password does not auto-unlock the browser that set it;
you're prompted the same as anyone else. **Remove password** is only available when the case is
currently unlocked and has a password set.

## Permanently Deleting a Case

**☰ Case lifecycle → 🗑️ Delete…** removes a case's directory for good — this cannot be undone. The
dialog offers an optional ZIP/encrypted archive taken first, so you can keep an off-disk copy before
the case is wiped. Guardrails: it refuses to touch a directory that isn't a real case, and it won't
delete an already-archived case's live folder out from under its archive.

## Encrypted Case Archive (Export / Import)

**Export archive:** toolbar → **Export → Export encrypted case archive (.dfircase)**. Enter a password (min 8 characters). Produces a single `.dfircase` file containing the ENTIRE case — findings, timeline, IOCs, MITRE, playbook, analyst notes, tags, AND screenshots/raw evidence — encrypted with AES-256-GCM. Only openable via another DFIR Companion's Import.

**Import archive:** toolbar → **Import case → Encrypted case archive (.dfircase)**. Restores as a new case. If the Case ID already exists you get a conflict warning.

!!! info "What's in the archive"
    Everything under the case directory travels with the export — screenshots, raw imported artifact files, and all analyst decisions. The AI configuration (keys) is never included — keys live in `.env` and never enter the case directory. The recipient's copy inherits settings like external-enrichment opt-in as they were on the exporting machine, since the archive is a verbatim copy.
