# Multi-language vulnerability corpus

Deliberately vulnerable fixtures for exercising the Vigilnz scanners: **SCA**,
**SAST**, **secret** and **IaC**.

> **Nothing here is meant to run.** Every manifest pins known-vulnerable
> releases, every source file carries real defect patterns, and every credential
> is synthetic and non-functional. Do not install, build, apply or deploy
> anything in this tree, and do not copy fragments of it into real code.

---

## Why it exists

Scanner regressions are easy to ship and hard to notice: a rule pack can stop
matching and the only symptom is a quieter report. This corpus gives each rule
pack something it is supposed to find, so "zero findings" becomes a failure
signal rather than a pass.

---

## Layout

```
multi-language-vulnerabilities/
├── sca/        20 ecosystems - manifests + lockfiles on known-vulnerable versions
├── sast/       12 tier-1 languages + 25 long-tail languages
├── secret/     credential shapes in config, code, key files and git history
└── iac/        terraform (aws/azure/gcp), cloudformation, kubernetes,
                dockerfile, docker-compose, github-actions, helm
```

`EXPECTED-FINDINGS.md` is the index: what each file is supposed to trigger.

### SCA

One directory per ecosystem, each holding the manifest **and** the lockfile where
the parser needs one, since several parsers only read the lockfile:

`npm` · `pnpm` · `yarn` · `bun` · `maven` · `gradle` (Groovy and Kotlin DSL) ·
`pip` · `pipenv` · `poetry` · `uv` · `go` · `cargo` · `composer` · `rubygems` ·
`nuget` · `pub` · `mix` · `conan` · `swiftpm` · `cpan`

Versions were chosen for well-known advisories — Log4Shell, Text4Shell,
SnakeYAML RCE, lodash prototype pollution, PyYAML `full_load`, jwt-go audience
bypass, and so on. Hashes and integrity digests in the lockfiles are filler, not
real digests; they are there so the parser sees a well-formed file.

### SAST

**Tier 1** (`sast/<lang>/`) — rich, multi-CWE files for the languages with deep
rule coverage: javascript, typescript, python, go, php, ruby, java, csharp,
rust, kotlin, swift, cpp.

**Long tail** (`sast/long-tail/`) — one minimal file per remaining language, so
every rule pack has at least a smoke-test case: ada, assembly, bash, crystal, d,
dart, elixir, elm, erlang, fortran, gleam, haskell, julia, lisp, lua, nim,
ocaml, pascal, perl, powershell, r, solidity, sql, v, zig.

The AI/LLM rule packs are covered inside the javascript and python directories.

### Secret

- `config/` — provider credential shapes in `.env` and YAML
- `code/` — the same shapes embedded in js, py, go, java and rs source
- `keys/` — PEM/OpenSSH armour and credential-bearing dotfile formats
- `history/` — a generator script, because history scanning needs a secret in an
  *older* commit; see `secret/history/README.md` for why that is not checked in

Credential values are placeholders with valid *shape* only. Where a provider
publishes a documentation placeholder (`AKIAIOSFODNN7EXAMPLE`), that is what is
used.

### IaC

Terraform for all three clouds, plus CloudFormation, Kubernetes, Dockerfile,
Docker Compose, GitHub Actions and Helm.

The GitHub Actions fixture deliberately lives at
`iac/github-actions/workflow.yml`, **not** under `.github/workflows/`, so GitHub
will never schedule it. Leave it there.

---

## Running a scan against it

```bash
CLI=./sdlc-cli/sdlc-vigilnz.exe

$CLI sast   multi-language-vulnerabilities/sast
$CLI secret multi-language-vulnerabilities/secret
$CLI iac    multi-language-vulnerabilities/iac

# SCA: drive it per ecosystem. Scanning sca/ as one root currently
# collapses to a single ecosystem — see EXPECTED-FINDINGS.md, gap 3.
for eco in multi-language-vulnerabilities/sca/*/; do
  echo "== $eco"
  $CLI sca "$eco"
done
```

Scans write results into `<path>/.vigilnz/<stamp>/`, which is already covered by
the root `.gitignore`. Delete those directories if you scan in place.

`EXPECTED-FINDINGS.md` carries a measured baseline and a list of engine gaps the
corpus currently exposes — read it before concluding a fixture is broken.

---

## CI exclusions

The corpus is excluded from the repository's own pipelines:

| File | Effect |
|---|---|
| `/.vigilnzignore` | repo-wide Vigilnz self-scans skip the corpus |
| `/.semgrepignore` | Semgrep skips the corpus |
| `/eslint.config.mjs` | ESLint ignores the corpus |

`.vigilnzignore` is read from the repository root only, so scanning the corpus
directory *directly* still reports everything — which is the behaviour you want.
`lint-staged` is already scoped to specific module paths and needs no change.

---

## Adding to the corpus

1. Put the file under the right scan type and language.
2. Give it a header: file, purpose, author, date, and the rules or CWEs it should
   trigger.
3. Add a row to `EXPECTED-FINDINGS.md`.
4. Confirm a scan actually reports it — a fixture that triggers nothing is worse
   than no fixture, because it reads like coverage.

**Author:** Vigilnz Security Engineering
**Last updated:** 2026-10-16
