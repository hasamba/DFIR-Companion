# Security

## Posture

DFIR Companion is a **localhost** tool. The server binds `127.0.0.1` by default, evidence
stays on disk, threat-intel enrichment is **off by default** and only sends indicators
externally after a per-case opt-in, and AI input is anonymized in transit (see the
Anonymization section of [`companion/README.md`](companion/README.md)). It is intended to run
on a trusted analyst workstation or a trusted LAN segment.

The default **single-user mode** (`DFIR_AUTH_MODE=single-user`) has **no sign-in**, so the server
refuses to start on a non-loopback address (for example `DFIR_HOST=0.0.0.0`) in that mode. To
share one Companion between several investigators, use **team mode** (`DFIR_AUTH_MODE=team`).
It adds local accounts, optional OpenID Connect sign-in, per-case roles and CSRF-protected
sessions — see [Team Accounts and Case Roles](mkdocs-docs/reference/team-authentication.md).
`DFIR_ALLOW_UNAUTHENTICATED_REMOTE` is the documented opt-out for two cases only: a container
whose port is published only on host loopback (`container-loopback-proxy`), and a throwaway
public demo that anyone who finds the URL can use (`public-demo`).

## Trust boundaries that are deliberate

Findings against these come up in every automated review; they are design decisions, not gaps.

- **Operator-configured service URLs are trusted.** The base URLs of integrations and
  enrichment providers (SO-CRATES, MISP, YETI, OpenCTI, DFIR-IRIS, Timesketch, Jira, ServiceNow,
  the notification webhooks and SMTP host, and the rest) are set by the global administrator in
  Settings or the environment, and are used as given — including plain `http://`, loopback and
  private addresses, because SO-CRATES binds `127.0.0.1` by design and a self-hosted MISP or
  Mattermost usually lives on the LAN. The outbound-fetch guard
  (`companion/src/routes/outboundFetchGuard.ts`) exists for the one place a URL comes from a
  request body rather than from the operator (`POST /kev/import-url`). Someone who can rewrite
  the companion's integration settings already holds the credentials those settings carry; the
  control that matters is who may edit Settings — global administrators only in team mode.
- **Single-user mode has no CSRF token.** The dashboard and the capture extension are the
  trusted callers. A cross-origin page is stopped by the origin guard
  (`companion/src/http/originGuard.ts`) before any route runs, the unlock cookie is
  `SameSite=Strict`, and a request with no `Origin` header is by definition not a browser page.
  Team mode adds a per-session CSRF token on top (`X-DFIR-CSRF`).
- **A locked case is a read and a write gate, with one exception: the push key.** Since #2135,
  `POST /cases/:id/import` and `POST /captures` into a locked case need the unlock cookie or the
  case password in the request body, and a wrong password counts toward the same lockout as
  `/unlock`. `POST /cases/:id/push` is the exception by design: it still authenticates only with a
  push key, and the shared all-cases key keeps working on a locked case. That key is a secret the
  operator hands out; anyone who holds it can still add events to a locked case. A per-case push
  key made before the password was set also keeps working, so rotate the case's push key when you
  lock a case you suspect. The browser extension holds a case password in browser session memory
  only (never on disk, never in its capture queue), and forgets it after one rejection so a wrong
  password costs one attempt. In team mode every route also requires an authenticated session
  holding write on the case.
- **Anyone who can write to the cases folder on disk is trusted, and backups are not
  content-authenticated.** That includes each case's `state/backups/` directory. Restoring a
  backup checks the filename, allows only the known state files, and runs a SQLite integrity
  check on the database copy, but it does not verify that the content was written by this
  installation. Someone who can write `state/backups/` can also overwrite the live `state/`
  files directly and read the instance secret, which sits in the same folder. A signature keyed
  by that instance secret would therefore be forgeable by the very writer it is meant to stop,
  and it would make older unsigned backups and the backups inside imported cases unrestorable.
  Protect the cases folder with file-system permissions instead.

## Reporting a vulnerability

Please report security issues privately via a **GitHub security advisory**
(repo → Security → *Report a vulnerability*) rather than a public issue.

## Encrypted case archives (`.dfircase`)

An exported `.dfircase` file is AES-256-GCM encrypted under a key derived from your password
with scrypt. The 8-byte magic at the front of the file is a **format version**, and the version
selects the scrypt cost:

| Version | Magic | scrypt `N` | Written by |
| --- | --- | --- | --- |
| v1 | `DFIRCZ01` | 2^14 (16,384) | v0.31.0 – v0.33.0 |
| v2 | `DFIRCZ02` | 2^17 (131,072) | v0.34.0 onward |

**v1 is weaker than it should be.** `N=2^14` is Node's `scryptSync` default. It is too low for a
file an attacker holds with unlimited offline attempts, which is exactly the situation a
`.dfircase` file is in. v2 raises it to OWASP's recommendation for sensitive data at rest.

**If you hold a `.dfircase` file exported by v0.31.0, v0.32.0 or v0.33.0, re-export it.** Import
it into a current build and export the case again — the new file is v2. Importing a v1 archive
now prints a warning saying exactly this.

Nothing refuses to open a v1 archive. It stays readable, so an archive that the
delete-with-archive flow left as a case's only remaining copy is never stranded. This also means
re-exporting is the only thing that upgrades a file you already hold; no build will silently
re-key it.

The parameters of an existing version are never changed. Raising the cost always means adding a
new version, because re-keying an existing one would make every archive already written under it
unopenable while reporting itself as a wrong password.

## Stored passwords

Two kinds of password are stored on the server as salted scrypt hashes, at a lower cost than a
`.dfircase` archive:

| Password | Stored in | scrypt `N` | `r`, `p` | How it is checked |
| --- | --- | --- | --- | --- |
| Team-mode local account | `<dataDir>/auth.sqlite` | 2^14 (16,384) | 8, 1 | online, rate-limited, with lockout |
| Case-lock password | the case's `case.json` | 2^14 (16,384) | 8, 1 (Node defaults) | online, rate-limited, with lockout |

This is deliberate, not an oversight of the `.dfircase` bar above. A `.dfircase` file faces
unlimited **offline** guessing, so its cost is the only thing slowing an attacker. These two are
checked **online**: every attempt goes through the server's rate limiter and lockout, which bounds
the guesses an attacker gets. And the scrypt derivation is the CPU each admitted attempt costs the
server, so a higher `N` would make every wrong guess a stronger CPU-exhaustion lever.

The hashes are only exposed to offline guessing if the files that hold them leak. **Treat
`auth.sqlite` and the data directory as a credential store**: restrict who can read them, and do
not copy them anywhere less protected than the server itself.

## Known dependency advisories (tracked, deferred)

`npm audit` in `companion/` currently reports **5 advisories (4 moderate, 1 critical)**. They
are **deferred deliberately** — see the rationale below. Last reviewed **2026-06-11**.

All five are in the **`vitest` test toolchain**, which is a **`devDependency`**: it is used
only by `npm test` / `npm run build` and **does not ship** in the running companion server, the
Docker image, or the SEA/portable-EXE binary. They are **not** introduced by any runtime
dependency.

| Package (installed) | Severity | Advisory | Exploit precondition (not met by this project) |
| --- | --- | --- | --- |
| `vitest` 2.1.9 | critical | [GHSA-5xrq-8626-4rwp](https://github.com/advisories/GHSA-5xrq-8626-4rwp) | The **Vitest UI server** is listening (`vitest --ui`). This repo runs `vitest run` — one-shot, no UI/API server. |
| `esbuild` 0.24.2 | moderate | [GHSA-67mh-4wv8-2f99](https://github.com/advisories/GHSA-67mh-4wv8-2f99) | The esbuild **dev/serve** server is listening **and** you browse a malicious site concurrently. Not used. |
| `vite` 5.4.21 | moderate | [GHSA-4w7w-66w2-5vf9](https://github.com/advisories/GHSA-4w7w-66w2-5vf9) | The vite **dev server** is listening **and** you browse a malicious site concurrently. Not used. |
| `@vitest/mocker` | moderate | (transitive via `vite`) | — |
| `vite-node` | moderate | (transitive via `vite`) | — |

**Why deferred:** the only fix `npm audit` offers is `vitest@4.1.8` — a **two-major** upgrade
(2.x → 4.x, pulling vite 6/7 + esbuild 0.25+ underneath), a breaking change that requires
re-validating the full test suite and the SEA build. There is **no patched 2.x/3.x** release.
Given the chain is dev-only and the exploit preconditions (a listening dev/UI server while
browsing a hostile site) never occur in this project's `npm test` / `npm run dev` workflow, the
real-world risk on a trusted workstation is low and does not justify a forced breaking upgrade.

**Revisit when:** upgrading the test toolchain to `vitest@^4` (do it on a branch, run
`npm test` + `npm run package:sea`, land only if green), or if any of these packages becomes a
**runtime** dependency.
