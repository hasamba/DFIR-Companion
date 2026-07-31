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
- an authentication audit covering sign-ins, role changes, users, and tokens.

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
to a non-loopback address. The supplied Docker Compose file remains safe because its container
port is published only on the host's `127.0.0.1`; its narrowly scoped override documents that
proxy boundary.

### Team mode

At minimum:

```dotenv
DFIR_AUTH_MODE=team
DFIR_HOST=0.0.0.0
DFIR_PUBLIC_URL=https://dfir.example.com
DFIR_AUTH_BOOTSTRAP_TOKEN=replace-with-a-long-random-value
```

Put the Companion behind HTTPS. Team-mode cookies are `Secure` by default and therefore are not
sent over plain HTTP. `DFIR_AUTH_COOKIE_SECURE=false` exists for an HTTP-only loopback lab, not a
network-facing deployment.

Restart the server, open `/login`, and create the first local administrator. When setup is being
performed from a different machine, the bootstrap token must match. Remove
`DFIR_AUTH_BOOTSTRAP_TOKEN` from the environment after setup.

The first local administrator is the emergency-access account. Local sign-in while OIDC is
configured is recorded as emergency access, and the final active global administrator cannot be
disabled or demoted.

### Switching modes

One server process starts in one mode. To switch, stop the server, change `DFIR_AUTH_MODE`, and
restart it. Switching to `single-user` does not delete team accounts, case roles, tokens, or the
authentication audit; switching back to `team` makes that data active again.

Single-user mode bypasses all team roles, so the server only permits it on a loopback address. Use
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

The older per-case password remains available as a second evidence barrier. It is not a user
identity and does not replace a team-mode role.

## Sessions and emergency access

Open the profile icon, then **Account & team**, to:

- see your active sessions and sign out the others;
- create, disable, or promote local users (global administrators);
- grant or remove case roles;
- inspect the authentication audit (global administrators).

Passwords are stored with salted scrypt hashes. Session and service-token secrets are stored only
as SHA-256 digests. Disabling a user revokes their sessions. Local password attempts are rate
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
replaced on the next startup.

Authentication data defaults to a dedicated sibling directory keyed to the cases-root path. A
deployment may move it with `DFIR_AUTH_DATA_DIR`. Treat that directory and the cases root as one
backup set.

## Deployment checklist

- Terminate HTTPS at the Companion or its reverse proxy.
- Set `DFIR_PUBLIC_URL` to the exact externally visible origin.
- Add the proxy hostname to `DFIR_ALLOWED_HOSTS`.
- Keep secure cookies enabled.
- Store OIDC and bootstrap secrets in the deployment's secret store.
- Bootstrap and test the emergency local administrator before relying on OIDC.
- Create the least-privileged role and service-token scope each analyst or collector needs.
- Back up the authentication data directory with the cases root.
- Run exactly one Companion process for a cases root.
