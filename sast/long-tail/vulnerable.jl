# File:    vulnerable.jl
# Purpose: SAST fixture (Julia). Dynamic evaluation, unsafe deserialization,
#          command construction from untrusted input.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
# Expected rules: julia-eval, julia-meta-parse, julia-deserialize, julia-cmd

using Serialization

# CWE-95: evaluating untrusted source
function evaluate(src::String)
    expr = Meta.parse(src)
    return eval(expr)
end

# CWE-502: deserializing attacker-controlled bytes
function load_state(io)
    return deserialize(io)
end

# CWE-78: command injection
function ping(host::String)
    cmd = Cmd(["sh", "-c", "ping -c 1 $host"])
    return read(cmd, String)
end
