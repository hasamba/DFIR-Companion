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
- **Delete** a case (destructive — prompts for confirmation)

The toolbar also shows a disk-space warning if the cases folder is running low.

## Investigation Snapshot (Export / Import)

**Export snapshot:** toolbar → **Export → Investigation snapshot**. Produces a single JSON file containing all investigation data (findings, timeline, IOCs, MITRE, playbook, analyst notes, tags, etc.) but no raw evidence bytes. Share with a colleague or restore on another machine.

**Import snapshot:** toolbar → **Import case → Investigation snapshot**. Restores as a new case. If the Case ID already exists you get a conflict warning.

!!! info "What is NOT in the snapshot"
    Raw screenshots and imported artifact files are not included — only the derived investigation state. This keeps the snapshot small and shareable. The AI configuration (keys, provider) is also excluded so the recipient opts in to enrichment themselves.
