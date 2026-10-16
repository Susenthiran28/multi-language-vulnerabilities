# File:    vulnerable.ex
# Purpose: SAST fixture (Elixir). Dynamic code eval, shell execution, unsafe
#          term deserialization, weak hash, tainted file read, SSRF.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
# Expected rules: elixir-code-eval, elixir-system-cmd, elixir-binary-to-term,
#   elixir-md5, elixir-file-read, elixir-httpoison-get

defmodule Vulnerable do
  # CWE-95: evaluating untrusted source
  def evaluate(source), do: Code.eval_string(source)

  # CWE-78: command injection
  def ping(host) do
    System.cmd("sh", ["-c", "ping -c 1 #{host}"])
    :os.cmd(~c"nslookup #{host}")
  end

  # CWE-502: deserializing an attacker-controlled term
  def load_state(blob), do: :erlang.binary_to_term(blob)

  # CWE-327: broken hash
  def hash_password(password), do: :crypto.hash(:md5, password)

  # CWE-22: path traversal
  def read_report(name), do: File.read!("/srv/files/#{name}")

  # CWE-918: SSRF
  def proxy(url), do: HTTPoison.get(url)
end
