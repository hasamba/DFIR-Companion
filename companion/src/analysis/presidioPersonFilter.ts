// Structural rejects for Presidio PERSON hits (#1799).
//
// Presidio's PERSON detector is spaCy NER, and on DFIR text it tags tool names, malware families,
// timestamps, CLI flags, file names and ATT&CK ids as PERSON — at 0.85, the SAME fixed score it
// gives a real name ("John Smith" scores 0.85 too). A higher threshold therefore cannot separate
// them; only the shape of the value can. Each reject below is a shape no person's name takes.
//
// Every reject errs toward KEEPING a value: a false reject leaks a name to the AI, while a false
// keep only asks the analyst one more question. So the vocabulary rule drops a value only when
// EVERY word is a known term ("Cobalt Strike Beacon" goes, "John Beacon" stays), the file rule
// needs a known extension and a stem with no capitalized word in it ("Jane.Doe" and
// "Jane_Doe.docx" stay), and the flag rule needs a flag shape ("- Jane Doe", a bulleted name, stays).

/**
 * Words that are DFIR tools, platforms, malware families, Windows folders or ATT&CK technique
 * words — never a person on their own. Lower-case, one word per entry; a multi-word term such as
 * "Cobalt Strike" is covered by its words. Common English words that are also plausible surnames
 * (Play, Royal, Hive, Link, Empire, Falcon, Havoc …) and family or tool names that are also
 * people's names (Conti, Akira, Mirai, Vidar, Thor) are deliberately absent — a bare surname in a
 * log line is exactly what the gate is for.
 */
export const DFIR_NON_PERSON_TERMS: ReadonlySet<string> = new Set([
  // Detection, triage and forensic tools
  "suricata",
  "zeek",
  "snort",
  "sysmon",
  "chainsaw",
  "hayabusa",
  "velociraptor",
  "kape",
  "plaso",
  "timesketch",
  "volatility",
  "yara",
  "sigma",
  "autoruns",
  "procmon",
  "wireshark",
  "tshark",
  "splunk",
  "osquery",
  "evtx",
  "evtxecmd",
  "mftecmd",
  "regripper",
  "sleuthkit",
  "autopsy",
  // Attacker tooling and admin tools abused by attackers
  "cobalt",
  "strike",
  "beacon",
  "psexec",
  "mimikatz",
  "rubeus",
  "bloodhound",
  "sharphound",
  "impacket",
  "metasploit",
  "meterpreter",
  "sliver",
  "anydesk",
  "teamviewer",
  "ngrok",
  "rclone",
  "certutil",
  "rundll32",
  "regsvr32",
  "mshta",
  "wmic",
  "powershell",
  "cmd",
  "procdump",
  "nltest",
  "adfind",
  "netscan",
  "winrm",
  // Platforms and operating systems
  "linux",
  "windows",
  "macos",
  "ubuntu",
  "debian",
  "centos",
  "android",
  "ios",
  "sharepoint",
  "onedrive",
  "exchange",
  "entra",
  "azure",
  // Malware and ransomware families
  "lockbit",
  "blackcat",
  "alphv",
  "ryuk",
  "revil",
  "emotet",
  "trickbot",
  "qakbot",
  "qbot",
  "icedid",
  "bumblebee",
  "asyncrat",
  "remcos",
  "njrat",
  "redline",
  "agenttesla",
  "formbook",
  "blackbasta",
  "clop",
  "wannacry",
  "notpetya",
  // Windows folder names
  "documents",
  "desktop",
  "downloads",
  "appdata",
  "programdata",
  "system32",
  "syswow64",
  "temp",
  // ATT&CK technique words
  "spearphishing",
  "attachment",
  "phishing",
  "persistence",
  "exfiltration",
  "lateral",
  "movement",
  "credential",
  "dumping",
  "discovery",
]);

// Words that carry no identity of their own and may stand in front of a term ("the Cobalt Strike").
const FILLER_WORDS: ReadonlySet<string> = new Set(["the", "a", "an"]);

// Extensions of files an investigation actually names. A closed list on purpose: "anything with a
// dot" would also reject a dotted username such as "jane.doe", which is exactly what should be
// hidden.
const FILE_EXTENSIONS: ReadonlySet<string> = new Set([
  "sh",
  "ps1",
  "psm1",
  "bat",
  "cmd",
  "vbs",
  "js",
  "hta",
  "py",
  "pl",
  "exe",
  "dll",
  "sys",
  "scr",
  "msi",
  "lnk",
  "jar",
  "elf",
  "so",
  "bin",
  "dat",
  "tmp",
  "log",
  "txt",
  "csv",
  "json",
  "xml",
  "html",
  "evtx",
  "pf",
  "zip",
  "rar",
  "7z",
  "iso",
  "img",
  "vhd",
  "vhdx",
  "doc",
  "docx",
  "docm",
  "xls",
  "xlsx",
  "xlsm",
  "pdf",
]);

// A list marker in front of the value — "h. Sysmon", "1) Linux", "- Suricata" — and trailing
// sentence punctuation after it. Only a marker followed by whitespace, so "-s" stays a flag.
const LIST_MARKER = /^(?:[a-z0-9]{1,2}[.)]|[-*•])\s+/i;
const TRAILING_PUNCTUATION = /[\s,;:.!?]+$/;

const ATTACK_ID = /^(?:T\d{4}(?:\.\d{3})?|TA\d{4})$/i;
// A command-line flag: one token, "-x" or "--name", optionally "=value".
const CLI_FLAG = /^--?[a-z0-9][\w-]*(?:=\S*)?$/i;
// Only digits, clock and date separators, and the ISO "T"/"Z" — with at least one digit.
const TIMESTAMP_SHAPED = /^[\d\sTZ:./+-]+$/i;
const FILE_NAME = /^([^\s\\/]+)\.([a-z0-9]{1,5})$/i;
// A name-shaped word inside a file stem: "Jane" in "Jane_Doe.docx". Such a stem goes to the analyst.
const CAPITALIZED_WORD = /(?:^|[^\p{L}])\p{Lu}\p{Ll}/u;

function normalize(value: string): string {
  return value.trim().replace(LIST_MARKER, "").replace(TRAILING_PUNCTUATION, "").trim();
}

function isVocabularyOnly(value: string): boolean {
  const words = value
    .toLowerCase()
    .split(/[\s,;:'"()]+/)
    .filter(Boolean);
  const meaningful = words.filter((word) => !FILLER_WORDS.has(word));
  return meaningful.length > 0 && meaningful.every((word) => DFIR_NON_PERSON_TERMS.has(word));
}

/**
 * True when a Presidio PERSON hit cannot be a person's name by its shape: no letters, a timestamp,
 * an ATT&CK id, a CLI flag, a file name with a known extension, or only DFIR vocabulary.
 */
export function isStructuralNonPerson(raw: string): boolean {
  const value = normalize(raw);
  if (!value) return true;
  if (!/\p{L}/u.test(value)) return true;
  if (/\d/.test(value) && TIMESTAMP_SHAPED.test(value)) return true;
  if (ATTACK_ID.test(value)) return true;
  if (CLI_FLAG.test(value)) return true;
  const file = FILE_NAME.exec(value);
  if (file && FILE_EXTENSIONS.has(file[2].toLowerCase()) && !CAPITALIZED_WORD.test(file[1])) return true;
  return isVocabularyOnly(value);
}
