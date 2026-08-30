# Case Management

## Creating a Case

Toolbar → **+ New case**. Fill in Case ID, name, and investigator.

Cases live in the `cases/` folder (location configured by `DFIR_CASES_ROOT`).

## Incident Types

The **Incident type** dropdown on the New case dialog pre-configures the investigation for a
recurring incident pattern, so the first thirty minutes are not spent rebuilding the same checklist
under pressure. Eight types ship built in:

| Type | Type |
|---|---|
| Ransomware | Insider Threat |
| BEC / Email Compromise | Cloud Compromise |
| Data Exfiltration | Web App Intrusion |
| Network Intrusion | Malware Outbreak |

Picking one seeds the case with:

- **Key questions** tailored to the incident — a BEC case asks about inbox rules and OAuth grants; a
  ransomware case asks about VSS deletion and double extortion.
- **Recommended next steps**, priority-ordered, each with its rationale and where to look.
- **Expected findings** as open *confirm or deny* questions, badged `[type-seed]`, so you work
  through what this incident type usually involves instead of starting from a blank page. Dismiss any
  that don't apply.
- **A collection plan** — the evidence this incident type calls for, in order, shown in its own
  dashboard panel. Each item ticks itself off once matching evidence is imported, whichever tool
  produced it, so "Windows event logs" is satisfied by Chainsaw, Hayabusa, or raw event logs alike.
  Mark an item *N/A* when your environment can't provide it (no EDR, no badge system) and it stops
  being proposed.
- **AI framing** — synthesis is told which incident type this is, so it prioritizes the relevant
  ATT&CK techniques. This is prompt context only; it never appears in your report.

The dropdown also lists any **templates you saved yourself** (Case lifecycle → Save as template).

!!! tip "Changing your mind"
    Re-picking a type from the API (`POST /cases/<id>/incident-type`) *merges* — your own questions
    and answers survive, and nothing is duplicated. Send `{"replace": true}` to start that case's
    questions over from the new type.

### Custom incident types

Drop a `.json` file into the `incident-types/` folder beside your cases root and it appears in the
dropdown, marked ★. Copy any built-in from `companion/data/incident-types/` as a starting point and
edit the questions, next steps, and expected findings for how your organization actually runs that
incident. A file with a broken definition is skipped rather than breaking the dropdown, and a custom
file cannot override a built-in type of the same name.

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

**If the archive was exported by v0.31.0–v0.33.0**, the import warns you that it used an older, weaker key derivation. Export the case again afterwards to upgrade the file to the current encryption. See [SECURITY.md](https://github.com/hasamba/DFIR-Companion/blob/master/SECURITY.md) for the detail.

!!! info "What's in the archive"
    Everything under the case directory travels with the export — screenshots, raw imported artifact files, and all analyst decisions. The AI configuration (keys) is never included — keys live in `.env` and never enter the case directory. The recipient's copy inherits settings like external-enrichment opt-in as they were on the exporting machine, since the archive is a verbatim copy.
