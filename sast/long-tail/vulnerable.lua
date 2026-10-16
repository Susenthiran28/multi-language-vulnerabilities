-- File:    vulnerable.lua
-- Purpose: SAST fixture (Lua). Shell execution, dynamic chunk loading,
--          tainted file open.
-- Author:  Vigilnz Security Engineering
-- Date:    2026-10-16
-- Expected rules: lua-os-execute, lua-io-popen, lua-loadstring, lua-io-open

local M = {}

-- CWE-78: command injection
function M.ping(host)
  os.execute("ping -c 1 " .. host)
  local pipe = io.popen("nslookup " .. host)
  local out = pipe:read("*a")
  pipe:close()
  return out
end

-- CWE-95: compiling untrusted source
function M.evaluate(source)
  local chunk = loadstring(source)
  return chunk()
end

function M.evaluate53(source)
  return load(source)()
end

-- CWE-22: path traversal
function M.read_report(name)
  local f = io.open("/srv/files/" .. name, "rb")
  local data = f:read("*a")
  f:close()
  return data
end

return M
