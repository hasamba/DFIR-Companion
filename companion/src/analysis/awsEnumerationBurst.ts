// The enumeration burst, stated on the credential-lineage row (#2542, user decision Q4).
//
// The lineage's enumeration SHAPE is judged on a fixed list of discovery calls across three
// services; the burst an analyst wants to read is wider — every read-only call the key made in that
// window, including the IAM `Get*` / `List*` sweep a tool runs in one second and the denied probes
// around it. So the lineage keeps every read-only use (bounded, earliest by time) and this module
// words the window: how many reads, across how many services, over what span, and which were
// denied. It adds no row and changes no grade — the lineage row already carries the key's grade.

const BURST_WINDOW_MS = 10 * 60_000;
/** Read calls kept per key, the earliest by time. */
const READS_MAX = 512;
const DENIED_NAMED_MAX = 4;
// An authorisation failure, not a "not found" answer (awsServiceGrade.ts).
const DENIAL = /denied|unauthori[sz]ed|forbidden|notauthorized/i;

export interface ReadCall {
  time: number;
  /** `<service> <eventName>`. */
  call: string;
  denied: boolean;
}

/** True when a record's error code is an authorisation failure. */
export const isDenial = (errorCode: string): boolean => DENIAL.test(errorCode);

/** Insert a read into a bounded earliest-by-time buffer. */
export function trackRead(buf: ReadCall[], hit: ReadCall): void {
  if (buf.length >= READS_MAX && hit.time >= buf[buf.length - 1].time) return;
  let i = buf.length;
  while (i > 0 && buf[i - 1].time > hit.time) i -= 1;
  buf.splice(i, 0, hit);
  if (buf.length > READS_MAX) buf.pop();
}

const hms = (t: number): string => new Date(t).toISOString().slice(11, 19);
const plural = (n: number, word: string): string => `${n} ${word}${n === 1 ? "" : "s"}`;

/**
 * The burst sentence for the reads inside the 10-minute window that starts at `start` (the
 * enumeration shape's first call), or "" when the window holds none.
 */
export function burstWords(reads: readonly ReadCall[], start: number): string {
  const inWindow = reads.filter((r) => r.time >= start && r.time - start <= BURST_WINDOW_MS);
  if (!inWindow.length) return "";
  const services = new Set(inWindow.map((r) => r.call.split(" ")[0]));
  const first = inWindow[0].time;
  const last = inWindow[inWindow.length - 1].time;
  const minutes = Math.max(1, Math.round((last - first) / 60_000));
  const denied = inWindow.filter((r) => r.denied);
  const named = [...new Set(denied.map((r) => r.call))];
  const deniedWords = denied.length
    ? `, ${plural(denied.length, "denied probe")} (${named.slice(0, DENIED_NAMED_MAX).join(", ")}${named.length > DENIED_NAMED_MAX ? `, +${named.length - DENIED_NAMED_MAX} more` : ""})`
    : ", no denied probes";
  return `enumeration burst: ${plural(inWindow.length, "read call")} across ${plural(services.size, "service")} in ${minutes} min (${hms(first)} → ${hms(last)} UTC)${deniedWords}`;
}
