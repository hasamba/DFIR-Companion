# Security

## Posture

DFIR Companion is a **localhost** tool. The server binds `127.0.0.1` by default, evidence
stays on disk, threat-intel enrichment is **off by default** and only sends indicators
externally after a per-case opt-in, and AI input is anonymized in transit (see the
Anonymization section of [`companion/README.md`](companion/README.md)). It is intended to run
on a trusted analyst workstation or a trusted LAN segment; there is **no built-in
authentication** — if you expose it beyond localhost (`DFIR_HOST=0.0.0.0`), put it behind your
own auth/reverse proxy.

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
