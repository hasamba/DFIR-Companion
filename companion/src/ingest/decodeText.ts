// Decode an imported file's BYTES to text, honouring a byte-order mark.
//
// Every server-side import path called `.toString("utf8")` on the raw buffer. That is right for the
// JSON, CSV and log formats the Companion started with, and wrong for the Windows artifacts it now
// reads: a Report.wer is written UTF-16LE with a BOM, and decoding it as UTF-8 yields
// NUL-interleaved mojibake. The file then fails detection, or detects and parses to nothing — and
// neither failure says anything to the analyst.
//
// The browser upload path never had this problem: FileReader.readAsText honours the BOM per the
// File API. So the same file imported through the dashboard worked while the same file dropped in
// the watched folder did not, which is the kind of inconsistency nobody thinks to test for.
//
// Only a BOM is honoured. Guessing an encoding from byte statistics is how text corruption gets
// introduced silently; a file with no BOM is UTF-8, as it always was.

/** Decode a buffer to text, honouring a UTF-8, UTF-16LE or UTF-16BE byte-order mark. */
export function decodeImportedText(buf: Buffer): string {
  if (buf.length >= 2) {
    // UTF-16LE: FF FE. Guard against the UTF-32LE BOM (FF FE 00 00), which starts the same way.
    if (buf[0] === 0xff && buf[1] === 0xfe && !(buf.length >= 4 && buf[2] === 0x00 && buf[3] === 0x00)) {
      return buf.subarray(2).toString("utf16le");
    }
    // UTF-16BE: FE FF. Node has no utf16be decoder, so the byte pairs are swapped first.
    if (buf[0] === 0xfe && buf[1] === 0xff) {
      const body = buf.subarray(2);
      const swapped = Buffer.from(body);
      // swap16 needs an even length; an odd trailing byte is truncation, not content.
      if (swapped.length % 2 === 1)
        return swapped
          .subarray(0, swapped.length - 1)
          .swap16()
          .toString("utf16le");
      return swapped.swap16().toString("utf16le");
    }
  }
  // UTF-8 BOM: EF BB BF. Node keeps it as U+FEFF, which then shows up inside the first field.
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return buf.subarray(3).toString("utf8");
  }
  return buf.toString("utf8");
}
