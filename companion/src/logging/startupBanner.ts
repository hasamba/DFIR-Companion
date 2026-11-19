/**
 * The "server is fully loaded" banner, printed once the HTTP(S) listener is bound.
 *
 * Returned as separate lines so the caller logs each one through the normal logger: every line
 * then gets the same timestamp/level prefix and the art stays aligned on the console and in the
 * session log file. Plain ASCII only — log files and legacy Windows consoles render it as-is.
 */
const LOGO: readonly string[] = [
  "  ____  _____ ___ ____  ",
  " |  _ \\|  ___|_ _|  _ \\ ",
  " | | | | |_   | || |_) |",
  " | |_| |  _|  | ||  _ < ",
  " |____/|_|   |___|_| \\_\\",
  "",
  "   ____   ___   __  __  ____      _     _   _  ___   ___   _   _",
  "  / ___| / _ \\ |  \\/  ||  _ \\    / \\   | \\ | ||_ _| / _ \\ | \\ | |",
  " | |    | | | || |\\/| || |_) |  / _ \\  |  \\| | | | | | | ||  \\| |",
  " | |___ | |_| || |  | ||  __/  / ___ \\ | |\\  | | | | |_| || |\\  |",
  "  \\____| \\___/ |_|  |_||_|    /_/   \\_\\|_| \\_||___| \\___/ |_| \\_|",
];

const HEADLINE = "Server fully loaded and ready";
const BOX_INDENT = " ";
const BOX_PADDING = 2;

function boxRow(text: string, innerWidth: number): string {
  return `${BOX_INDENT}|${" ".repeat(BOX_PADDING)}${text.padEnd(innerWidth - BOX_PADDING)}|`;
}

export function buildStartupBanner(dashboardUrl: string): readonly string[] {
  const innerWidth = Math.max(HEADLINE.length, dashboardUrl.length) + BOX_PADDING * 2;
  const edge = `${BOX_INDENT}+${"-".repeat(innerWidth)}+`;
  return ["", ...LOGO, edge, boxRow(HEADLINE, innerWidth), boxRow(dashboardUrl, innerWidth), edge, ""];
}
