// Pure helpers for importing a generic log file (.log / .txt / etc.) as evidence.
// Logs are line-oriented (firewall logs, syslog, sshd/auth.log, Apache/IIS/nginx
// access, Windows event-log exports, application logs), so we split on newlines,
// drop blanks, and batch the surviving lines for the model. The CSV path is the
// right shape for tabular tool exports; this one is for free-form rows.

export interface ParsedLog {
  lines: string[];
}

// Split a log file into trimmed, non-empty lines. Handles LF / CRLF / CR endings
// and ignores BOM at the start of the file. Lines are NOT deduplicated — the
// same line can recur (e.g. firewall heartbeat) and each occurrence is evidence.
export function parseLogLines(text: string): ParsedLog {
  const cleaned = text.replace(/^﻿/, "");
  const lines = cleaned
    .split(/\r\n|\r|\n/)
    .map((l) => l.trimEnd()) // keep leading whitespace (indented stack traces, etc.)
    .filter((l) => l.trim().length > 0);
  return { lines };
}

// Re-serialize a batch of lines for the model prompt. We keep them as-is, one
// per line — the model sees the exact characters that appeared in the file.
export function linesToText(lines: readonly string[]): string {
  return lines.join("\n");
}
