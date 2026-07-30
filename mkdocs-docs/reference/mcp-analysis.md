# MCP Analysis

MCP Analysis lets you describe a forensic task in plain English. Claude Code decides which tools
the selected MCP server should use, supplies their arguments, and returns a report that can be
previewed and imported into the case.

For example:

> Extract this password-protected archive using password `infected`, then statically analyze every
> executable it contains. Report the extracted filenames, computed hashes, analysis performed, and
> limitations.

You normally do **not** need to name an MCP tool or write JSON arguments. The manual tool-call form is
available under **Advanced** for testing and exceptional cases.

!!! important "The connection and the evidence path are separate"
    Configuring an MCP server in Claude Code gives the agent a way to call analysis tools. It does
    not move a ZIP, memory image, or binary to the analysis host. In Companion you must separately
    configure a shared path or SCP delivery. Most `FILE_NOT_FOUND` failures are caused by completing
    the first step but not the second.

---

## Recommended DFIR MCP servers

These third-party projects are not bundled with or maintained by DFIR Companion. Install them on
dedicated analysis systems and follow their upstream security and update guidance.

| MCP server | Recommended use |
|---|---|
| [REMnux MCP Server](https://github.com/REMnux/remnux-mcp-server) | Malware triage, archives, suspicious documents, static binary analysis, strings, capabilities, and IOC extraction with REMnux tools |
| [AppliedIR SIFT MCP (Valhuntir)](https://github.com/AppliedIR/sift-mcp) | Memory, disk, filesystem, registry, and event-log investigations using SIFT Workstation tools and its MCP gateway |

Use REMnux for a suspicious executable or password-protected malware archive. Use SIFT for a RAM
image, disk image, MFT, registry hives, or broader host-forensics workflow. Both projects expose
powerful command-running capabilities: a disposable VM or container is the security boundary, not
the language model.

---

## 1. Configure the server in Claude Code

Claude Code must be installed and authenticated on the **same machine that runs Companion**.
Companion deliberately stores no MCP URL or bearer token; it asks your existing Claude Code
installation to reach the server.

Install the chosen MCP project by following its current upstream README, then register it with
Claude Code. These are representative commands from the upstream projects.

### REMnux: Docker or a remote VM

For a local REMnux Docker container:

```bash
claude mcp add remnux -- npx @remnux/mcp-server --mode=docker --container=remnux
```

For a REMnux VM reached over SSH:

```bash
claude mcp add remnux -- npx @remnux/mcp-server \
  --mode=ssh --host=REMNUX_IP --user=REMNUX_USER
```

For a local/container deployment, enable the server's sandbox and give it an explicit ingest root
where practical:

```bash
claude mcp add remnux -- npx @remnux/mcp-server \
  --mode=docker --container=remnux \
  --sandbox --ingest-root="$HOME/remnux-samples"
```

The REMnux project also supports a remote HTTP transport. Its bearer token is sent in the
`Authorization` header, so protect non-loopback deployments with TLS or a trusted tunnel; do not
expose plain HTTP to an untrusted network. See the
[REMnux deployment scenarios](https://github.com/REMnux/remnux-mcp-server#deployment-scenarios) for
the current commands and security notes.

### SIFT MCP / Valhuntir

Valhuntir is a gateway with several forensic MCP backends. Install it on a SIFT Workstation from
the project's
[quick-start instructions](https://github.com/AppliedIR/sift-mcp#quick-start):

```bash
curl -fsSL https://raw.githubusercontent.com/AppliedIR/sift-mcp/main/quickstart.sh \
  -o /tmp/vhir-quickstart.sh
bash /tmp/vhir-quickstart.sh --recommended
```

The SIFT MCP endpoint is normally:

```text
http://localhost:4508/mcp/sift-mcp
```

Register that HTTP endpoint in Claude Code:

```bash
claude mcp add sift-mcp --transport http \
  http://localhost:4508/mcp/sift-mcp
```

If SIFT runs on another host, use Valhuntir's documented `--remote` installation. It generates TLS
certificates and a bearer token; register its HTTPS endpoint and authorization header rather than
publishing the unauthenticated localhost endpoint.

### Check the connection

Run:

```bash
claude mcp list
```

The exact server name shown here—such as `remnux` or `sift-mcp`—is the name you must allow in
Companion. Resolve any `Failed to connect` status before continuing.

!!! warning
    Depending on the Claude Code version and transport, diagnostic output may include the server
    command or an authorization header. Do not paste unredacted output into tickets or reports.

---

## 2. Allow the server in Companion

Open **Settings → All → Tools → MCP servers**:

1. Click **Refresh from Claude Code**.
2. Under **Allow one of Claude Code's servers**, select the exact server name.
3. Optionally enter a friendly label.
4. Leave **Restrict to tools** blank to permit every tool that server offers, or enter a
   comma-separated allowlist to narrow it.
5. Configure evidence delivery as described below.
6. Click **Allow this server**.

Enabling a server is the permission boundary for plain-English investigations. Once enabled,
Companion automatically permits Claude Code to use that server's allowed tools for the run; you
should not have to approve each tool individually.

Some servers expose a general command runner. A tool allowlist can prevent the agent from selecting
that tool. **Restrict to commands** applies only to the advanced manual-call form; it cannot constrain
arguments chosen inside an autonomous plain-English run.

---

## 3. Configure evidence delivery

Choose the method that reflects your actual deployment.

=== "Shared path"

    Use **Shared path (no copy)** only when the Companion host and analysis host can already see the
    same evidence, for example through an NFS mount or a bind-mounted container directory.

    - Leave both prefixes blank if the file has the same absolute path on both hosts.
    - Otherwise set **Local prefix** to the Companion-side root and **Remote prefix** to the
      analysis-side root.

    Example:

    ```text
    Local prefix:  /srv/cases
    Remote prefix: /mnt/dfir
    ```

    Companion then translates `/srv/cases/CASE-1/imports/memory.raw` to
    `/mnt/dfir/CASE-1/imports/memory.raw`.

=== "SCP"

    Use **scp (push the file)** when REMnux or SIFT is a separate VM or workstation. Enter:

    - **SSH host** and, when needed, **SSH user** and **SSH port**
    - **Identity file** for a passphrase-free key or a key already loaded in an SSH agent
    - **Remote staging dir**, an absolute directory the SSH user can write

    Companion runs non-interactively, so trust the host key and test key authentication first:

    ```bash
    ssh -i /path/to/key -o BatchMode=yes ANALYST@ANALYSIS_HOST true
    scp -i /path/to/key /path/to/benign-test-file \
      ANALYST@ANALYSIS_HOST:/absolute/staging/directory/
    ```

    The staged copy is deleted after the investigation. Its transfer and hashes are recorded in the
    case chain of custody.

The staging directory must also be inside the MCP server's permitted sample/ingest area. For a
REMnux service running as a non-default account, for example, align all three paths:

```text
REMnux samples directory: /home/ANALYST/files/samples
REMnux sandbox ingest root: /home/ANALYST/files/samples
Companion remote staging dir: /home/ANALYST/files/samples
```

Do not assume `/home/remnux/files/samples` exists when the service runs as another user. Likewise,
the SSH account needs write and delete permission on the staging directory, while the MCP service
needs read permission.

---

## 4. Verify the complete path

Before sending real evidence:

1. Confirm the server is connected in `claude mcp list`.
2. Confirm it appears as connected and enabled under **Settings → All → Tools → MCP servers**.
3. Select a small, benign test file in **MCP Analysis** and ask for its name, type, size, and SHA-256.
4. Verify the reported analysis-host path and hash against the source file.
5. Check the case chain of custody for the transfer record.

For a password-protected archive, a successful result should identify every extracted filename,
compute hashes of the extracted files, and state which analyses ran against each payload. ZIP
metadata, archive listings, or a hash of the outer ZIP alone do **not** prove that its binary was
investigated.

---

## Run a plain-English investigation

Open a case and expand **MCP Analysis**:

1. Describe the forensic goal under **What should the MCP app investigate?**
2. Select the **MCP app**.
3. Under **Evidence file**, either select a path already inside the case or click **Browse…** to
   upload a local file.
4. Keep **Preview before importing** selected.
5. Click **Investigate**, review the proposed report, then import or discard it.

Browser uploads are limited to 180 MB by default. For larger memory or disk images, place the
evidence in the case first and select its case-relative path.

After import, the reviewed output remains visible in **Imported analysis history** with its import
time and the number of findings added or updated, events, and IOCs. The history is stored inside the
case and travels with a full case archive. Importing does not turn an overall maliciousness score
into hidden prose: the agent is required to provide a verdict and supporting findings, and
Companion creates a visible finding when a malicious or suspicious verdict arrives without one.

The agent chooses tools and arguments from your instruction. Use **Advanced: call one MCP tool
manually** only when you deliberately need to test a specific tool or reproduce an exact call.

---

## Monitor a long investigation

Memory and disk investigations can run for tens of minutes. The MCP Analysis panel remains attached
to the background job until it finishes, including after a dashboard refresh. It shows:

- the current phase and four-step progress;
- bytes transferred, total size, and percentage while SCP delivery is in progress (measured from
  the staged file with GNU `stat`; hosts without it still show total size and elapsed time);
- elapsed time and the configured time limit;
- sanitized MCP activity such as the tool name being run, without displaying its arguments or raw
  forensic output;
- a warning when the backend has stopped sending heartbeats;
- **Cancel** while the process is active and **Retry** after a failure or cancellation.

The default agent timeout is one hour. Change **Settings → All → Tools → MCP servers →
Investigation timeout**, or set `DFIR_MCP_AGENT_TIMEOUT_MS` to a value from `60000` (one minute) to
`86400000` (24 hours), then click **Reconnect / apply**. The limit stops the Claude Code process; it
does not guarantee that a remote MCP command will stop if that server detached the command into its
own background process.

If a job says it may be stalled, first check whether its last tool is legitimately slow. If the
activity age keeps increasing, cancel the job and check the Companion log, Claude Code
authentication, MCP server health, and analysis-host process list before retrying. A provider error
such as HTTP 529 is upstream failure, not evidence that the remote forensic command completed.

---

## Prompt examples

Good prompts state the evidence type, scope, safety boundary, expected checks, and required proof.
They do not need MCP tool names or JSON.

### Password-protected malware archive

```text
Extract this password-protected archive using password "infected". Identify the real file type and
compute SHA-256 for every extracted file. Statically analyze every executable payload for headers,
sections, imports, strings, packing, capabilities, and IOCs. Do not execute the payload. Report the
extracted filenames, computed hashes, analysis actually performed, evidence supporting each
conclusion, and limitations. Do not claim a payload was analyzed unless extraction succeeded.
```

### Suspicious binary with REMnux

```text
Perform static malware triage on this binary. Determine its real file type and hashes; inspect its
format, sections, imports, strings, embedded content, packing indicators, likely capabilities, and
network or host IOCs. Separate capabilities inferred from static evidence from behavior actually
observed. Do not execute it.
```

### Memory image with SIFT

```text
Investigate this memory image for signs of compromise. Identify the operating system, reconstruct
the process tree and command lines, inspect network connections, suspicious modules, injected
regions, credential-access indicators, and persistence clues. Corroborate important findings with
more than one artifact where possible, include timestamps and process IDs, and state any profile or
acquisition limitations.
```

### Windows event logs

```text
Analyze these Windows event logs for initial access, suspicious process creation, credential access,
lateral movement, persistence, and log tampering. Build a UTC timeline, correlate related events by
host, user, logon session, and process, map supported findings to MITRE ATT&CK, and distinguish
confirmed activity from hypotheses.
```

### Filesystem or disk evidence

```text
Build a focused filesystem timeline around the suspected compromise window. Highlight executable
creation, downloads, archive extraction, persistence locations, deletion, timestamp anomalies, and
user activity. Correlate related paths and hashes, preserve source timestamps, and explain gaps or
unsupported conclusions.
```

### Verification follow-up

```text
Before finalizing, state the exact evidence path seen on the analysis host, its computed SHA-256,
every extracted filename and hash, and which analyses completed successfully. Clearly list anything
that was skipped, failed, timed out, or was inferred without direct tool output.
```

---

## Troubleshooting

| Symptom | What to check |
|---|---|
| `Claude Code CLI not found` | Install and authenticate Claude Code on the Companion host, not only on the analysis VM. |
| Server is absent after refresh | Compare the exact name with `claude mcp list`; Companion and the interactive shell must run as the same OS user. |
| Claude asks permission for every MCP call | Remove and re-add the allowed server, ensure it is enabled, and restart an older Companion version. Current versions authorize the enabled server's allowed tools for the investigation. |
| `FILE_NOT_FOUND` | The MCP connection works, but evidence delivery or path translation does not. Verify the shared prefixes or the SCP destination. |
| `DIR_NOT_FOUND` under `/home/remnux` | The server is using a default sample/output path that does not exist for its service account. Set explicit sample, output, and ingest paths. |
| `Host key verification failed` | Connect once as the Companion OS user and verify the analysis host's SSH fingerprint. |
| `Permission denied (publickey)` | Check the selected identity, remote username, file permissions, and `BatchMode=yes` authentication. |
| `Claude Code: error_max_turns` | The run exhausted its agent loop. Companion attempts to recover the report; if no useful report appears, narrow the prompt or evidence scope and retry. |
| Report describes only the ZIP | Require extraction proof, inner filenames and hashes, and analysis performed per extracted payload. |

!!! danger
    Treat suspicious evidence as hostile. Prefer immutable source evidence, work on staged copies,
    keep the analysis host isolated, avoid dynamic execution unless separately authorized, review
    the preview, and verify important conclusions against the underlying tool output.
