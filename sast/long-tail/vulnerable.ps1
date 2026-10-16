# File:    vulnerable.ps1
# Purpose: SAST fixture (PowerShell). Expression invocation, remote download and
#          execute, plaintext SecureString, runtime type compilation.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
# Expected rules: ps-invoke-expression, ps-download-string, ps-securestring-plain,
#   ps-add-type, ps-start-process

param(
    [string]$UserInput,
    [string]$Url
)

# CWE-95: expression built from untrusted input
Invoke-Expression $UserInput
IEX ("ping -c 1 " + $UserInput)

# CWE-494: remote code downloaded and run without verification
$payload = (New-Object System.Net.WebClient).DownloadString($Url)
Invoke-Expression $payload

# CWE-798 / CWE-522: plaintext credential promoted to a SecureString
$plainPassword = "Pr0dPassw0rd!"
$secure = ConvertTo-SecureString $plainPassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("svc_admin", $secure)

# CWE-470: type compiled at runtime from source text
Add-Type -TypeDefinition @"
public class Loader { public static void Run(string c) { System.Diagnostics.Process.Start("cmd.exe", "/c " + c); } }
"@

# CWE-78: process launched with untrusted arguments
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $UserInput"
