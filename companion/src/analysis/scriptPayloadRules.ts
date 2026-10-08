// In-script tradecraft that has no command-line spelling (#2025). scriptBlockSignal grades a logged
// script block (4104) or pipeline record (4103) with the command-line tables, but some payloads only
// ever exist INSIDE PowerShell: a P/Invoke shellcode loader compiled with Add-Type, an in-memory
// assembly load, an AMSI bypass, an alias naming a C2 implant. On the APT29 dataset the loader and
// the `SetBeacon` alias reached Medium only because the record's ContextInfo repeated an encoded
// launch command; the tagger rule that matched that line no longer reads it, so the payload itself
// has to carry the grade.
//
// Script-only on purpose: a process command line never contains `[DllImport(` or a ParameterBinding,
// and keeping these out of TRADECRAFT_RULES keeps the process grader unchanged. Every `re` is built
// from literal tokens with bounded runs (no nested quantifiers). Pure — no I/O.

export interface ScriptPayloadRule {
  re: RegExp;
  weight: "strong" | "weak";
  ids: string[];
}

export const SCRIPT_PAYLOAD_RULES: readonly ScriptPayloadRule[] = [
  // Win32 memory APIs declared for P/Invoke: the shape of an in-memory shellcode loader.
  {
    re: /\bDllImport\b[\s\S]{0,400}?\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|CreateRemoteThread|RtlMoveMemory|NtAllocateVirtualMemory)\b/i,
    weight: "weak",
    ids: ["T1106", "T1620"],
  },
  // Any other Win32 P/Invoke declaration (Add-Type -MemberDefinition / -TypeDefinition): on APT29, the
  // implant's recon helpers (GetComputerNameEx, NetWkstaGetInfo, LsaEnumerateLogonSessions).
  // `Add-Type -AssemblyName System.Drawing` declares nothing and stays ungraded.
  { re: /\[\s*DllImport\s*\(/i, weight: "weak", ids: ["T1106"] },
  // An assembly loaded from bytes / a path at runtime.
  { re: /\[(?:system\.)?reflection\.assembly\]::load(?:file|from)?\s*\(/i, weight: "weak", ids: ["T1620"] },
  // A dynamic assembly built in memory (PSReflect-style delegates): `New-Object` of an AssemblyName,
  // typed or as a 4103 ParameterBinding — NOT `[Reflection.AssemblyName]::GetAssemblyName($path)`,
  // which installers use to read a DLL's version.
  {
    re: /(?:new-object|parameterbinding\(new-object\))[^\n]{0,60}?\breflection\.assemblyname\b|\bdefinedynamicassembly\b|\bgetdelegateforfunctionpointer\b/i,
    weight: "weak",
    ids: ["T1620"],
  },
  // AMSI bypass: the field/function names every public bypass touches.
  {
    re: /\bamsiInitFailed\b|\bAmsiUtils\b|\bAmsiScanBuffer\b|\bamsiContext\b/i,
    weight: "strong",
    ids: ["T1562.001"],
  },
  // An implant's own AMSI-unhook command, invoked or named in its output.
  { re: /\b(?:unhook|bypass|disable)-amsi\b|\binvoke-amsibypass\b/i, weight: "weak", ids: ["T1562.001"] },
  // An alias (Set-Alias / New-Alias, as typed or as a 4103 ParameterBinding) naming C2 vocabulary.
  {
    re: /\b(?:set|new)-alias\b[^\n]{0,120}?(?:beacon|implant|shellcode)|parameterbinding\((?:set|new)-alias\)[^\n]{0,80}?value="[^"\n]{0,60}?(?:beacon|implant|shellcode)/i,
    weight: "weak",
    ids: [],
  },
];

/** The strongest weight and the union of techniques the script payload rules give `script`, or null. */
export function scriptPayloadSignal(script: string): { weight: "strong" | "weak"; mitre: string[] } | null {
  let weight: "strong" | "weak" | null = null;
  const mitre = new Set<string>();
  for (const rule of SCRIPT_PAYLOAD_RULES) {
    if (!rule.re.test(script)) continue;
    if (rule.weight === "strong" || !weight) weight = rule.weight;
    for (const id of rule.ids) mitre.add(id);
  }
  return weight ? { weight, mitre: [...mitre] } : null;
}
