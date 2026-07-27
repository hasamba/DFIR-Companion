# War-Room Slash-Command Bot

Run the case from your incident channel instead of switching to the dashboard for every question. Works with **Slack**, **Microsoft Teams** and **Telegram**.

This is the inbound counterpart to [Notifications](../reference/settings.md): notifications push findings *out* to a channel; this lets the channel ask questions *back*.

---

## Commands

```
/dfir bind IR-2026-014       bind this channel to a case
/dfir status                 events, findings, IOCs, open questions
/dfir findings               top 5 by severity (dismissed excluded)
/dfir finding f002           one finding card, by id
/dfir iocs malicious         IOCs by verdict — flagged | malicious
/dfir ask <question>         grounded AI answer, posted when ready
/dfir synthesize             trigger a re-synthesis
/dfir hunt T1059.001         note a technique to hunt
/dfir unbind                 clear the binding
/dfir help                   usage
```

Once a channel is bound, every command can omit the case id. Name a case explicitly at any time (`/dfir findings OTHER-CASE`) to override the binding for that one command.

`status`, `findings`, `finding` and `iocs` answer immediately. `ask`, `synthesize` and `hunt` reply "working…" first and post the result when it's ready — chat platforms only wait about three seconds, and an AI answer takes longer.

`hunt` records the technique against the case and points you at the dashboard; it does **not** launch the hunt. Deploying one needs per-client targeting and artifact selection, which is more than a chat line can carry — see [Threat Hunting](threat-hunting.md).

---

## You need a public URL

The chat platform delivers commands to the Companion, so it has to be able to reach it. On a normal workstation install that means a tunnel.

!!! note "This is the opposite direction from notifications"
    Outbound Telegram/Slack notifications work with no tunnel, because the Companion calls *them*. Commands arrive the other way, so they need an address the platform can reach.

Cloudflare's quick tunnel needs no account:

```bash
cloudflared tunnel --url http://127.0.0.1:4773
```

It prints a hostname like `https://random-words-here.trycloudflare.com`. Leave it running — a quick tunnel gets a **new hostname every restart**, and you'll have to re-register the webhook when it changes. For anything beyond a one-off test, use a named Cloudflare tunnel or an `ngrok` reserved domain so the hostname is stable.

### Allow the hostname

The Companion refuses requests arriving under a hostname it doesn't recognise — that's the DNS-rebinding guard, and it runs before any route. Add your tunnel hostname to `.env`:

```
DFIR_ALLOWED_HOSTS=random-words-here.trycloudflare.com
```

Hostname only — no `https://`, no path. Restart after changing it.

!!! warning "This is the most common setup failure"
    If commands do nothing and the platform reports **403**, this is almost always why. The response body says which hostname was refused.

---

## Slack

1. [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → From scratch, pick your workspace.
2. **Slash Commands** → **Create New Command**:
   - Command: `/dfir`
   - Request URL: `https://<your-tunnel>/integrations/slack/command`
3. **Install to Workspace**.
4. **Basic Information** → copy the **Signing Secret** into `.env`:

```
DFIR_SLACK_SIGNING_SECRET=<signing secret>
```

Restart the Companion. Every request is HMAC-verified against that secret with a five-minute replay window, so an intercepted request can't be replayed later.

---

## Microsoft Teams

Teams uses the webhook-based slash-command variant (not the Bot Framework). Point your channel's outgoing webhook at:

```
https://<your-tunnel>/integrations/teams/command
```

and set the shared secret it sends in the `Authorization` header:

```
DFIR_TEAMS_TOKEN=<shared secret>
```

---

## Telegram

1. Message [@BotFather](https://t.me/BotFather) → `/newbot` → copy the token (`123456789:AAF…`).
2. Invent a long random string for the webhook secret.
3. Add both to `.env`:

```
DFIR_TELEGRAM_SECRET_TOKEN=<long random string>
DFIR_TELEGRAM_BOT_TOKEN=123456789:AAF...
```

4. Restart, then register the webhook:

```bash
curl -F url=https://<your-tunnel>/integrations/telegram/command -F secret_token=<long random string> https://api.telegram.org/bot<TOKEN>/setWebhook
```

Check it took:

```bash
curl https://api.telegram.org/bot<TOKEN>/getWebhookInfo
```

`last_error_message` should be absent. A **403** there means the hostname isn't in `DFIR_ALLOWED_HOSTS`.

Both tokens are needed and they do different jobs: the **secret token** proves an incoming update really came from Telegram, and the **bot token** is how the Companion sends `ask`/`hunt`/`synthesize` results back, since those arrive too late for the webhook reply.

!!! tip "Groups and command names"
    In a group chat Telegram appends the bot's name to commands — `/status@YourBot`. The Companion handles that. Starting in a direct message with the bot avoids Telegram's group privacy rules while you're getting set up.

!!! warning "One bot, one webhook"
    Setting a webhook replaces any previous one for that bot. If you also use this bot for outbound notifications that's fine — but don't point two Companion instances at the same bot.

---

## Who is allowed to do what

By default the bot is open: anyone who can post in the channel can run any command. That matches the rest of this localhost-first tool, but a war room usually has more people in it than you want spending AI budget.

Name the responders who may run privileged commands:

```
DFIR_SLACK_ACTION_USERS=U012ABCDEF,U034GHIJKL
DFIR_TEAMS_ACTION_USERS=...
DFIR_TELEGRAM_ACTION_USERS=8675309,5551212
```

Comma-separated platform user ids (Telegram's are numeric — `getUpdates` or [@getidsbot](https://t.me/getidsbot) will tell you yours).

Setting a list changes two things:

- **`ask`, `hunt`, `synthesize` and `bind` become responder-only.** `bind` is on that list because it decides which case the whole room can read.
- **Everyone else is confined to the channel's bound case.** Without this, any channel member could read any case on the server just by naming it.

Reading a case (`status`, `findings`, `finding`, `iocs`) stays open to the channel either way.

!!! warning "OPSEC"
    Anyone who can post in the channel can pull case content — finding titles, IOC values, descriptions — into a third-party chat service. Treat a bound channel as a copy of the case. Password-protected cases are refused over chat entirely: a chat message carries no unlock, so the bot will not serve them at all.

Every command is written to the case's activity log with the platform and user id that sent it, including refusals — so the audit trail shows who asked for what, and who was turned away.

---

## Try it with the demo case

Seed a case with real findings to see something meaningful:

```bash
curl -X POST http://127.0.0.1:4773/cases/seed-demo -H "content-type: application/json" -d "{}"
```

Then from the channel:

```
/dfir bind demo
/dfir findings
```

which answers:

```
Top 5 finding(s) for demo
• Critical · f002 conf 99% [T1003.001] — Domain Administrator Credentials Compromised via Mimikatz
• Critical · f001 conf 97% [T1071.001, T1105, T1055] — Active Cobalt Strike C2 Beacon — Persistent Backdoor
• Critical · f009 conf 96% [T1190] — Internet-Facing WEB01 Exploited via CVE-2021-41773 + CVE-2021-44228
• High · f003 conf 95% [T1566.001, T1204.002, T1059.001] — Spear-Phishing Email — Initial Access via Malicious Excel Macro
• High · f004 conf 92% [T1021.002] — Lateral Movement via PsExec to DC01, FS01, and WEB01
```

If you see that, the whole chain works: tunnel → hostname guard → secret verification → binding → case read → reply.

---

## When it doesn't work

| What you see | Cause |
|---|---|
| Platform reports **403**, nothing in the channel | Tunnel hostname missing from `DFIR_ALLOWED_HOSTS` |
| Platform reports **401** | Wrong or unset signing secret / bearer token / Telegram secret token |
| *"A valid caseId is required"* | Channel isn't bound — run `/dfir bind <caseId>` |
| *"No such case: X"* | Case id typo, or the case doesn't exist on this instance |
| *"…is password-protected and is not available over chat"* | Working as intended — use the dashboard |
| *"may only use this channel's bound case"* | An allowlist is set and you aren't on it; you can only read the bound case |
| *"Working on /dfir ask…"* then nothing | No AI provider configured, or the result couldn't be delivered — check the server log |
| Rate-limited after ~20 commands a minute | Per-channel cap; wait a minute |

Full variable list: [Settings Reference → War-Room Bot](settings.md#war-room-bot).
