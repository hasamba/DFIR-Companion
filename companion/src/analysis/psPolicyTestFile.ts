// PowerShell's AppLocker / WDAC probe file (#2025). Every PowerShell start writes
// `__PSScriptPolicyTest_<random 8.3>.ps1` (and a `.psm1` twin) into %TEMP% or C:\Windows\Temp and
// deletes it again a moment later, to ask the policy engine whether scripts may run. The name comes
// from Path.GetRandomFileName(), hence the fixed 8.3 shape. A Sysmon 11 / 23 / 26 for one of these,
// written by PowerShell itself, is housekeeping: no attacker signal, no file-deletion technique.
//
// Both facts are required: the probe NAME and a PowerShell WRITER. The same name dropped by any
// other process is graded as usual — on purpose: the probe written by rundll32.exe means a PowerShell
// runspace was loaded into a process that is not PowerShell (unmanaged PowerShell). Pure — no I/O.

const POLICY_TEST_NAME = /^__PSScriptPolicyTest_[a-z0-9]{8}\.[a-z0-9]{3}\.psm?1$/i;
// wsmprovhost.exe is the PowerShell remoting host: the same engine, so the same probe on every session.
const POWERSHELL_IMAGE = /(?:^|[\\/])(?:powershell(?:_ise)?|pwsh|wsmprovhost)\.exe$/i;

function baseNameOf(path: string): string {
  return path.trim().split(/[\\/]/).pop() ?? "";
}

/** Is this file event PowerShell's own policy-test probe (written or deleted by PowerShell)? */
export function isPsPolicyTestFile(image: string, targetFilename: string): boolean {
  return POWERSHELL_IMAGE.test(image.trim()) && POLICY_TEST_NAME.test(baseNameOf(targetFilename));
}
