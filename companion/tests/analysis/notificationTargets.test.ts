import { describe, it, expect } from "vitest";
import { parseChannelInput, type NotificationChannel } from "../../src/analysis/notifications.js";

// Issue #2146: a notification channel could be saved pointing at the cloud metadata service. The
// save-time check is synchronous and literal-only (the send-time guard re-checks what a name
// resolves to); LAN and loopback targets stay allowed.
describe("parseChannelInput — cloud-metadata and link-local targets (#2146)", () => {
  it.each([
    "http://169.254.169.254/x",
    "http://[::ffff:a9fe:a9fe]/x",
    "http://[fd00:ec2::254]/x",
    "http://100.100.100.200/x",
    "http://metadata.google.internal/computeMetadata/v1/",
    "https://[fe80::1]/hook",
  ])("refuses a webhook URL at %s, and says why", (webhookUrl) => {
    const r = parseChannelInput({ type: "slack", webhookUrl });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/blocked because it is a cloud-metadata or link-local address/);
  });

  it.each([
    ["slack", "https://hooks.slack.com/services/x"],
    ["mattermost", "http://192.168.1.20:8065/hooks/x"],
    ["mattermost", "http://127.0.0.1:8065/hooks/x"],
    ["discord", "https://discord.com/api/webhooks/1/x"],
    ["teams", "https://hooks"],
  ] as const)("accepts a %s webhook at %s", (type, webhookUrl) => {
    expect(parseChannelInput({ type, webhookUrl }).ok).toBe(true);
  });

  it("does not block an edit that leaves a previously saved URL untouched (the toggle path)", () => {
    // A channel saved before this check existed must stay editable — the dashboard's enable/disable
    // toggle PUTs a blank URL. It cannot SEND (the send-time guard refuses it, and Test says why).
    const existing = {
      id: "c1",
      type: "slack",
      name: "Old",
      enabled: true,
      minSeverity: "High",
      events: {},
      webhookUrl: "http://169.254.169.254/x",
    } as unknown as NotificationChannel;
    expect(parseChannelInput({ type: "slack", enabled: false }, existing).ok).toBe(true);
  });

  it.each(["169.254.169.254", "metadata.google.internal", "fd00:ec2::254", "[fe80::1]"])(
    "refuses an SMTP host of %s",
    (host) => {
      const r = parseChannelInput({ type: "email", smtp: { host, port: 25, from: "a@b.c", to: "x@y.z" } });
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/blocked because it is a cloud-metadata or link-local address/);
    },
  );

  it.each(["mail.lan", "10.0.0.25", "127.0.0.1", "smtp.example.com"])(
    "accepts an SMTP host of %s",
    (host) => {
      expect(
        parseChannelInput({ type: "email", smtp: { host, port: 587, from: "a@b.c", to: "x@y.z" } }).ok,
      ).toBe(true);
    },
  );
});
