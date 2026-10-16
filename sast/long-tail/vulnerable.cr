# File:    vulnerable.cr
# Purpose: SAST fixture (Crystal). Shell execution, tainted file read, SSRF.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
# Expected rules: crystal-system, crystal-process-run, crystal-file-read, crystal-http-get

require "http/client"

def ping(host : String)
  # CWE-78: command injection
  system("ping -c 1 #{host}")
  Process.run("sh", ["-c", "nslookup #{host}"])
end

def read_report(name : String)
  # CWE-22: path traversal
  File.read("/srv/files/#{name}")
end

def proxy(url : String)
  # CWE-918: SSRF
  HTTP::Client.get(url).body
end
