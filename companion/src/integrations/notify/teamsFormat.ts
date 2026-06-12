import type { NotificationEvent } from "../../analysis/notifications.js";
import type { Severity } from "../../analysis/stateTypes.js";

// Pure: a NotificationEvent → an MS Teams "MessageCard" (legacy connector / Power Automate
// "Post adaptive card via Incoming Webhook" both accept this Office 365 connector card schema).
// We use a MessageCard rather than a full Adaptive Card because incoming webhooks accept it
// directly with a coloured theme stripe. No I/O — unit-tested.

const SEVERITY_COLOR: Record<Severity, string> = {
  Critical: "D00000", // red
  High: "E8590C",     // orange
  Medium: "F1C40F",   // amber
  Low: "2D7DD2",      // blue
  Info: "868E96",     // grey
};

export interface TeamsCard {
  "@type": "MessageCard";
  "@context": "http://schema.org/extensions";
  themeColor: string;
  summary: string;
  sections: Array<{
    activityTitle: string;
    activitySubtitle?: string;
    text?: string;
    facts?: Array<{ name: string; value: string }>;
    markdown: boolean;
  }>;
  potentialAction?: unknown[];
}

export function formatTeams(event: NotificationEvent): TeamsCard {
  // Render lines that look like "Key: value" as facts; the rest become the card text.
  const facts: Array<{ name: string; value: string }> = [];
  const textLines: string[] = [];
  for (const line of event.lines.filter(Boolean)) {
    const m = /^([A-Za-z][\w .]{0,40}?):\s+(.+)$/.exec(line);
    if (m) facts.push({ name: m[1], value: m[2] });
    else textLines.push(line);
  }
  facts.push({ name: "Severity", value: event.severity });

  const card: TeamsCard = {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    themeColor: SEVERITY_COLOR[event.severity] ?? "868E96",
    summary: truncate(event.title, 120),
    sections: [
      {
        activityTitle: event.title,
        activitySubtitle: `DFIR Companion · ${event.kind.replace(/_/g, " ")} · ${event.at}`,
        ...(textLines.length ? { text: textLines.join("\n\n") } : {}),
        facts,
        markdown: true,
      },
    ],
  };

  if (event.url) {
    card.potentialAction = [
      { "@type": "OpenUri", name: "Open case", targets: [{ os: "default", uri: event.url }] },
    ];
  }
  return card;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
