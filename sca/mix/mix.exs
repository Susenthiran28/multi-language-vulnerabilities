# File:    mix.exs
# Purpose: SCA fixture. Elixir Mix manifest pinned to known-vulnerable releases.
#          DO NOT COMPILE.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16

defmodule VulnCorpus.MixProject do
  use Mix.Project

  def project do
    [
      app: :vuln_corpus_mix,
      version: "1.0.0",
      elixir: "~> 1.14",
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      # CVE-2020-5250 - Plug cookie session leakage
      {:plug, "1.9.0"},
      # CVE-2021-22904 - Phoenix websocket origin check
      {:phoenix, "1.5.7"},
      # CVE-2023-22893 - Ecto / query injection lineage
      {:ecto, "3.5.5"},
      {:cowboy, "2.8.0"},
      {:jason, "1.2.1"}
    ]
  end
end
