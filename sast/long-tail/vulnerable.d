// File:    vulnerable.d
// Purpose: SAST fixture (D). Shell execution, weak hash, tainted file read.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16
// Expected rules: d-execute-shell, d-md5, d-std-file

import std.digest.md;
import std.file;
import std.process;

string ping(string host)
{
    // CWE-78: command injection
    auto result = executeShell("ping -c 1 " ~ host);
    return result.output;
}

string hashPassword(string password)
{
    // CWE-327: broken hash
    return toHexString(md5Of(password)).idup;
}

void[] readReport(string name)
{
    // CWE-22: path traversal
    return std.file.read("/srv/files/" ~ name);
}
