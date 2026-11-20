import type { NotificationChannel } from "../../analysis/notifications.js";

// A failed notification send surfaces the remote's reply in the error text (dashboard + server
// log). A remote or proxy that repeats the request back would put the channel's own secret there —
// the Telegram bot token sits in the URL path, a Slack/Discord/Teams/Mattermost webhook URL IS the
// credential, and an SMTP server could repeat the AUTH line. Every error text is passed through
// redactSecrets with the channel's secrets before it leaves the sender.

const MASK = "[redacted]";
// Shorter strings match too much ordinary text to be worth replacing.
const MIN_SECRET_LENGTH = 4;
// A webhook path segment or query value worth treating as a key: long, or mid-length with a digit —
// not a plain word like "services" or a flag like "wait=true".
const KEY_SEGMENT = /^(?:[^/]{16,}|(?=.*\d)[^/]{8,})$/;

function variants(secret: string): string[] {
  const out = new Set<string>([secret]);
  try {
    out.add(encodeURIComponent(secret));
  } catch {
    // a lone surrogate cannot be URI-encoded; the plain form is still replaced
  }
  out.add(Buffer.from(secret, "utf8").toString("base64"));
  return [...out];
}

/** Replace every known secret (plain, URL-encoded and base64 forms) with a mask. Longest first, so a
 *  secret that contains another is masked whole. */
export function redactSecrets(text: string, secrets: readonly (string | undefined)[]): string {
  const all = secrets
    .filter((s): s is string => typeof s === "string" && s.length >= MIN_SECRET_LENGTH)
    .flatMap(variants)
    .filter((s) => s.length >= MIN_SECRET_LENGTH)
    .sort((a, b) => b.length - a.length);
  let out = text;
  for (const s of all) out = out.split(s).join(MASK);
  return out;
}

/** The parts of a webhook URL that carry its credential: the whole URL, its path and query, and
 *  each key-shaped path segment or query value. */
export function webhookUrlSecrets(url: string | undefined): string[] {
  if (!url) return [];
  const out = [url];
  try {
    const u = new URL(url);
    out.push(`${u.pathname}${u.search}`);
    if (u.pathname.length > 1) out.push(u.pathname);
    if (u.search.length > 1) out.push(u.search.slice(1));
    for (const seg of u.pathname.split("/")) if (KEY_SEGMENT.test(seg)) out.push(seg);
    for (const v of u.searchParams.values()) if (KEY_SEGMENT.test(v)) out.push(v);
  } catch {
    // an unparsable URL is still masked whole
  }
  return out.filter((s) => s !== "/");
}

/** The Telegram bot token, and its secret half after the colon on its own. */
export function telegramTokenSecrets(token: string | undefined): string[] {
  if (!token) return [];
  const colon = token.indexOf(":");
  return colon >= 0 ? [token, token.slice(colon + 1)] : [token];
}

/** Every secret a channel's error text must never carry. `botToken` is the token actually used,
 *  which may be the env-borrowed one rather than the channel's own. */
export function channelSecrets(channel: NotificationChannel, botToken?: string): string[] {
  return [
    ...webhookUrlSecrets(channel.webhookUrl),
    ...telegramTokenSecrets(botToken),
    ...telegramTokenSecrets(channel.telegram?.botToken),
    ...(channel.smtp?.password ? [channel.smtp.password] : []),
  ];
}
