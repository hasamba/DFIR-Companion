# Team Accounts and Case Roles

DFIR Companion still starts in its original mode by default: one analyst, bound to
`127.0.0.1`, with no sign-in screen. Team mode is an explicit deployment choice for a Companion
shared by several investigators.

Team mode adds:

- browser sessions with `HttpOnly`, `SameSite` cookies and CSRF protection;
- optional OpenID Connect sign-in using authorization code, nonce, state, and S256 PKCE;
- a local emergency account when the identity provider is unavailable;
- reader, investigator, reviewer, and administrator access per case;
- immutable user identities in activity and chain-of-custody records;
- case-scoped service identities for the capture extension and automation;
- an authentication audit covering sign-ins, role changes, users, tokens, and cloud accounts.

Local account passwords have one rule: they must contain at least six characters.

Every HTTP case route and live WebSocket subscription passes the same case-role check. A user who
has no role on a case sees neither the case in the list nor whether a guessed case ID exists.

## Choose a deployment mode

### Single-user (default)

```dotenv
DFIR_AUTH_MODE=single-user
DFIR_HOST=127.0.0.1
```

No setup or sign-in is required. The server refuses to start if this unauthenticated mode is bound
to a non-loopback address, unless `DFIR_ALLOW_UNAUTHENTICATED_REMOTE` is set to one of two
values. The supplied Docker Compose file sets `container-loopback-proxy`, which is safe because its
container port is published only on the host's `127.0.0.1`. `public-demo` is for a server that is
really exposed on purpose; pair it with `DFIR_DEMO_MODE=1` for a read-only public demo. See
[Public Demo and Network Exposure](advanced.md#public-demo-and-network-exposure).

### Team mode

At minimum:

```dotenv
DFIR_AUTH_MODE=team
DFIR_HOST=0.0.0.0
DFIR_PUBLIC_URL=https://dfir.example.com
DFIR_AUTH_BOOTSTRAP_TOKEN=replace-with-a-long-random-value
```

The token must be at least 32 characters; a shorter value stops the server at startup. Generate
one with `openssl rand -base64 32`. Five wrong guesses lock the endpoint for 30 seconds, doubling
after each further failure, and every rejected guess is written to the audit log with the source
address. The lockout applies to the token, not the client, so it can also delay you: if you are
locked out of your own first setup, someone else is trying the endpoint.

Put the Companion behind HTTPS. Team-mode cookies are `Secure` by default and therefore are not
sent over plain HTTP. The Companion now does this itself: with `DFIR_HTTPS=auto` (the default) it
serves HTTPS whenever team mode is on — see [Running over HTTPS](#running-over-https).
`DFIR_AUTH_COOKIE_SECURE=false` exists for an HTTP-only loopback lab, not a network-facing
deployment.

Restart the server, open `/login`, and create the first local administrator. The bootstrap token
must match, whatever address the server is bound to and wherever the browser runs: the server
refuses to start team mode without one while no identity exists. A loopback bind is not a
substitute — behind a same-host reverse proxy every client arrives as a loopback peer. Remove
`DFIR_AUTH_BOOTSTRAP_TOKEN` from the environment after setup; the server starts without it once
the first administrator exists. In Docker, first make sure the account folder is mounted (see
[Where accounts are stored](#where-accounts-are-stored)). If it is not mounted, the restart that
removes the token also deletes the administrator.

### Where accounts are stored

Team mode keeps its accounts, sessions, case roles, service tokens and authentication audit in one
folder. `DFIR_AUTH_DATA_DIR` sets that folder. If you do not set it, the server uses a hidden
`.dfir-auth-<hash>` folder next to the cases folder.

**Docker Compose.** The supplied `docker-compose.yml` sets `DFIR_AUTH_DATA_DIR=/data/auth` and
mounts `./auth:/data/auth`. The accounts are kept in `./auth`, next to `./cases`,
`./server-sets` and `./data`. Back up all four folders. `./auth` holds password hashes, so keep it
private.

**Older compose files.** Compose files before this change did not mount the account folder. Docker
recreates the container when you edit the compose file and run `docker compose up -d`. With an old
compose file, that recreate deletes every account. The next start then stops with
`first team-mode startup requires DFIR_AUTH_BOOTSTRAP_TOKEN while no identity exists`. To repair
it, add these two lines to the `companion` service, set a new bootstrap token, and create the first
administrator again:

```yaml
    environment:
      DFIR_AUTH_DATA_DIR: "/data/auth"
    volumes:
      - ./auth:/data/auth
```

**`docker run`.** Add `-v /your/auth:/data/auth -e DFIR_AUTH_DATA_DIR=/data/auth`.

### Emergency access

The first local administrator is the emergency-access account. Local sign-in while OIDC is
configured is recorded as emergency access, and the final active global administrator cannot be
disabled or demoted.

### Switching modes

One server process starts in one mode. To switch, stop the server, change `DFIR_AUTH_MODE`, and
restart it. Switching to `single-user` does not delete team accounts, case roles, tokens, or the
authentication audit; switching back to `team` makes that data active again.

Single-user mode bypasses all team roles, so the server only permits it on a loopback address,
unless you set one of the two documented opt-outs (see
[Public Demo and Network Exposure](advanced.md#public-demo-and-network-exposure)). Use
single-user mode for one analyst working locally and team mode whenever another person or machine
can reach the Companion.

## OpenID Connect

Register this callback with the identity provider:

```text
https://dfir.example.com/auth/oidc/callback
```

Then configure:

```dotenv
DFIR_AUTH_OIDC_ISSUER=https://id.example.com
DFIR_AUTH_OIDC_CLIENT_ID=dfir-companion
DFIR_AUTH_OIDC_CLIENT_SECRET=replace-me
# DFIR_AUTH_OIDC_REDIRECT_URI=https://dfir.example.com/auth/oidc/callback
# DFIR_AUTH_OIDC_SCOPES=openid profile email
```

The client discovers provider endpoints from the configured issuer, accepts HTTPS endpoints only,
uses authorization code with S256 PKCE, binds the callback to the initiating browser, validates the
nonce, and verifies the ID token signature and issuer/audience/time claims. The implementation
follows [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0-final.html),
[PKCE](https://www.rfc-editor.org/rfc/rfc7636), and the
[OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700).

OIDC users are created with no case role on first sign-in. A global or case administrator opens the
profile icon and chooses **Account & team** to grant their first role.

## Case roles

Roles express different jobs; they are not a simple rank.

| Role | View | Edit/investigate | Review/approve | Export | Manage case access |
|---|---:|---:|---:|---:|---:|
| Reader | Yes | No | No | Yes | No |
| Investigator | Yes | Yes | No | Yes | No |
| Reviewer | Yes | No | Yes | Yes | No |
| Administrator | Yes | Yes | Yes | Yes | Yes |

A global administrator manages local users and can administer every case. A case administrator can
manage roles and service identities only for that case. Role changes are audited with the
administrator's immutable identity.

**Cloud accounts** (the credentials for live cloud collection) belong to cases. Seeing, adding
and using a case's cloud accounts needs **write** on the case — Investigator or Administrator;
Readers and Reviewers do not see them. Editing or deleting an account shared by several cases needs
write on every one of them. See [Cloud accounts](settings.md#cloud-accounts).

The older per-case password remains available as a second evidence barrier. It is not a user
identity and does not replace a team-mode role.

## Sessions and emergency access

Open the profile icon, then **Account & team**, to:

- see your active sessions and sign out the others;
- create, disable, or promote local users (global administrators);
- grant or remove case roles;
- inspect the authentication audit (global administrators).

Passwords are stored with salted scrypt hashes, at a cost tuned for rate-limited online checks;
see "Stored passwords" in
[SECURITY.md](https://github.com/hasamba/DFIR-Companion/blob/master/SECURITY.md#stored-passwords)
for the parameters and why they differ from encrypted case archives. Session and service-token secrets are stored only
as SHA-256 digests. Disabling a user revokes their sessions. Signing out, disabling or demoting a
user, or removing their case role also closes their open live dashboard connections at once. An
expired session loses its live connection within about 30 seconds. Local password attempts are rate
limited.

## Capture extension and automation

In **Account & team → Service identities**, create a token for one case and choose the smallest needed
permissions:

- `capture` for screenshot ingestion;
- `write` for imported artifacts or push ingestion (it also permits reading that case in the
  extension's case picker);
- `read`, `review`, or `export` only when that automation needs the corresponding operation.

The token is shown once. Paste it into **DFIR Capture → Team service token**. The extension stores
it in that browser profile and sends it as a Bearer credential. A token cannot list or access a
different case, even if the caller knows its ID.

For scripts:

```bash
curl -H "Authorization: Bearer $DFIR_SERVICE_TOKEN" \
  https://dfir.example.com/cases/CASE_ID/state
```

Revoke a token from **Access** when a collector is retired or a browser profile is lost.

## Concurrency and storage

The case and authentication databases use SQLite transactions and WAL journaling. Concurrent
browser sessions are supported, and case state writes remain serialized so one analyst's update
does not overwrite another's.

Team mode intentionally supports one Companion writer process per cases root. Startup acquires an
exclusive process guard and refuses a second live process. Run one server process and scale the
reverse proxy, not the Companion process. A stale guard left by a crashed process is detected and
replaced on the next startup. In Docker, a restarted container replaces it at once. A container
that was recreated after a crash (for example, on an image upgrade) waits up to one minute, because
a live server refreshes its guard and the new container must see that no server does. A guard
left by a crash of an earlier version cannot show that its server stopped. Startup then names the
file to delete; delete it only when no other server uses the cases folder.

Authentication data defaults to a dedicated sibling directory keyed to the cases-root path. A
deployment may move it with `DFIR_AUTH_DATA_DIR`. Treat that directory and the cases root as one
backup set.

## Running over HTTPS

Team mode turns on the built-in HTTPS listener by default, on the same port as before
(`DFIR_PORT`, 4773). No reverse proxy, no extra software: this works the same in `npm run dev`, the
portable Windows EXE, the Linux AppImage and Docker.

**Certificates.** On its very first start — with HTTPS on or off — the Companion creates a private
certificate authority (valid 10 years) in a `tls` folder beside the cases folder (`./data/tls` in
Docker), and uses it to issue the server's certificate. That certificate covers `localhost`, the
machine's name and its IP addresses. It renews itself from the same authority 30 days before it
expires, and whenever the machine's names or addresses change, without a restart. Add any other
name or address teammates type with `DFIR_HTTPS_HOSTNAMES` — in Docker this is required, because a
container cannot see the host's name or IP.

The startup log prints two fingerprints:

```text
[https] HTTPS is on because team mode is on (DFIR_HTTPS=auto). certificate SHA-256 A6:AF:… · expires 2029-02-06
[https] teammates trust this server via the local CA — CA SHA-256 D1:DD:… · expires 2036-11-01; download /tls/ca.crt
```

Share the **CA** fingerprint with the team over a channel you already trust (chat, ticket, phone).

**What teammates do.** Either:

- **Click through the browser warning.** It works, and the browser remembers the exception. They
  see the warning again only when the server certificate is re-issued — about every two years, or
  sooner if the server's name or IP addresses change. Check
  that the fingerprint in the warning's certificate details matches the server certificate's.
- **Install the certificate once** — no warnings ever, across renewals. Download it from the
  **Download the server certificate** link on the sign-in page or in Settings → Authentication, or
  from `https://<server>:<port>/tls/ca.crt`. Compare its SHA-256 fingerprint with the CA fingerprint
  you were given, then install it as a trusted root: on Windows double-click → *Install
  Certificate* → *Local Machine* → *Trusted Root Certification Authorities*; on macOS add it to the
  System keychain and set *Always Trust*; on Linux copy it to `/usr/local/share/ca-certificates/`
  and run `sudo update-ca-certificates`. Firefox keeps its own list: *Settings → Privacy & Security
  → Certificates → View Certificates → Authorities → Import*.

**The browser extension needs the certificate installed.** Its background uploads cannot show a
warning page, so a clicked-through exception is not enough. After installing, set the extension's
companion URL to `https://<server>:<port>` and approve the permission prompt.

**Your own certificate.** To use a certificate from your organization instead, set
`DFIR_HTTPS_CERT` (PEM; may include the chain) and `DFIR_HTTPS_KEY` (unencrypted PEM key). The
Companion never renews it: it warns in the log and in Settings 30 days before expiry, and on every
start once expired. It reloads the files within a day when you replace them, or at the next restart.
The download link is hidden in this mode, because the local CA does not vouch for your certificate.

**An optional plain-HTTP port.** `DFIR_HTTPS_PLAIN_HTTP=redirect` opens a second port
(`DFIR_HTTPS_PLAIN_HTTP_PORT`, default 4774) that sends anyone who types `http://` to the `https://`
address. It redirects page loads only; a sign-in or upload sent there is refused, never forwarded.
`serve` answers with the full app over plain HTTP, for scripts on the server itself. It binds
`127.0.0.1` unless you set `DFIR_HTTPS_PLAIN_HTTP_HOST`, and then logs a warning.

**Behind a reverse proxy?** If a proxy already terminates HTTPS and talks plain HTTP to the
Companion, set `DFIR_HTTPS=off` — otherwise the proxy reaches a TLS port it does not expect.

**If the certificate authority is damaged.** The Companion never replaces `tls/ca.pem` on its own,
because teammates trust it. If it is unreadable or expired, HTTPS refuses to start and says so.
Move the file aside and restart to create a new one; everyone who installed the old certificate
must install the new one.

## Deployment checklist

- Leave the built-in HTTPS on (the team-mode default), or terminate HTTPS at a reverse proxy and
  set `DFIR_HTTPS=off`.
- Set `DFIR_PUBLIC_URL` to the exact externally visible origin.
- Add the server's or proxy's hostname to `DFIR_ALLOWED_HOSTS` (and, with the built-in HTTPS, to
  `DFIR_HTTPS_HOSTNAMES`).
- Keep secure cookies enabled.
- Store OIDC and bootstrap secrets in the deployment's secret store.
- Bootstrap and test the emergency local administrator before relying on OIDC.
- Create the least-privileged role and service-token scope each analyst or collector needs.
- Back up the authentication data directory with the cases root.
- Run exactly one Companion process for a cases root.
