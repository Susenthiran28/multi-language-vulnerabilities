// File:    vulnerable.v
// Purpose: SAST fixture (V). Shell execution and tainted file read.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
// Expected rules: v-os-execute, v-os-read-file

module vulnerable

import os

// CWE-78: command injection
pub fn ping(host string) string {
	result := os.execute('ping -c 1 ${host}')
	os.system('nslookup ${host}')
	return result.output
}

// CWE-22: path traversal
pub fn read_report(name string) !string {
	return os.read_file('/srv/files/${name}')
}
