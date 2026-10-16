// File:    vulnerable.gleam
// Purpose: SAST fixture (Gleam). Tainted file read, shell execution, SSRF.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
// Expected rules: gleam-file-read, gleam-os-cmd, gleam-httpc

import gleam/erlang/charlist
import simplifile

// CWE-22: path traversal
pub fn read_report(name: String) {
  simplifile.read("/srv/files/" <> name)
}

// CWE-78: command injection
pub fn ping(host: String) {
  :os.cmd(charlist.from_string("ping -c 1 " <> host))
}

// CWE-918: SSRF
pub fn proxy(url: String) {
  :httpc.request(charlist.from_string(url))
}
