# File:    vulnerable.nim
# Purpose: SAST fixture (Nim). Shell execution at runtime and compile time,
#          tainted file read.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
# Expected rules: nim-exec-shell, nim-exec-process, nim-static-exec, nim-read-file

import osproc

# CWE-78: command injection
proc ping*(host: string): int =
  discard execShellCmd("ping -c 1 " & host)
  discard execProcess("sh", args = ["-c", "nslookup " & host], options = {poUsePath})
  result = 0

# CWE-78: command executed by the compiler
const buildStamp = staticExec("git rev-parse HEAD")

# CWE-22: path traversal
proc readReport*(name: string): string =
  readFile("/srv/files/" & name)
