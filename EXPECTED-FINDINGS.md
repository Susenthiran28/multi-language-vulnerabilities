# Expected findings

What each fixture is supposed to trigger. Use this as the oracle when checking a
scanner run against the corpus.

Counts are deliberately omitted from the per-file tables below — rule packs
change, and a hardcoded count turns every rule addition into a false failure.
Assert on *presence per file*, not on totals.

---

## Verified baseline — 2026-10-16

Measured with `sdlc-cli/sdlc-vigilnz.exe` (rebuilt from `sdlc-cli/` at the time;
the checked-in binary was byte-identical), OSV db built 2026-10-13 with cursors
for all 13 catalogued ecosystems.

| Scan | Command | Result |
|---|---|---|
| SAST | `sast multi-language-vulnerabilities/sast` | 110 findings across **11 of 41** files |
| Secret | `secret multi-language-vulnerabilities/secret` | 89 findings across **11 of 11** files |
| IaC | `iac multi-language-vulnerabilities/iac` | 163 findings across **8 of 9** areas |
| SCA | per-ecosystem, e.g. `sca .../sca/maven` | maven 102, pip 140, go 85, cargo 26 |

### Known engine gaps this corpus exposes

These are scanner behaviours, not defects in the fixtures. Each was confirmed by
reducing to a minimal file that matches a rule verbatim.

1. **SAST fires for 7 languages only** — go, python, javascript, typescript,
   java, ruby, php. Fixtures for **rust, csharp, kotlin, swift, cpp** return
   zero despite those rule packs loading (rust 46 rules, csharp 48, kotlin 46,
   swift 39, cpp 37) and their extensions being present in `extToLang`
   (`sdlc/scan/sast/lang.go`). A file containing nothing but the rust
   `unsafe-block` rule's literal pattern also returns zero.

2. **20 rule packs have no extension mapping at all** — ada, assembly, crystal,
   d, dart, erlang, fortran, gleam, haskell, julia, lisp, nim, pascal, perl,
   powershell, r, solidity, v, zig (and `.sh`/`.lua`/`.sql`/`.ml`/`.ex`/`.elm`
   are mapped but still return zero, as in gap 1). Their YAML loads into
   `rulesByLang` but no file ever reaches them.

3. **Whole-tree SCA collapses to one ecosystem** — scanning `sca/` as a single
   root reported 96 findings, all from `npm/package-lock.json`, even though the
   cataloger correctly produced 173 packages across 13 ecosystems with clean
   version strings (e.g. `org.apache.logging.log4j:log4j-core 2.14.1`). Scanning
   each ecosystem directory separately matches correctly. Until this is
   resolved, drive SCA per ecosystem.

4. **GitHub Actions rules appear path-bound** — `iac/github-actions/workflow.yml`
   returned zero. The fixture is deliberately kept outside `.github/workflows/`
   so GitHub never schedules it, so the rules likely key on that path. Verify
   before treating the file as broken.

Re-measure this table whenever the rule packs or the language mapping change.

---

## SCA

Each directory holds a manifest and, where the parser needs one, a lockfile.

| Ecosystem | Files | Representative advisories |
|---|---|---|
| npm | `package.json`, `package-lock.json` | lodash 4.17.15, minimist 1.2.0, axios 0.21.0, ejs 3.1.6, handlebars 4.0.11, tar 4.4.8 |
| pnpm | `package.json`, `pnpm-lock.yaml` | node-forge 0.10.0, ua-parser-js 0.7.28, decode-uri-component 0.2.0 |
| yarn | `package.json`, `yarn.lock` | marked 2.0.0, glob-parent 5.1.1, hosted-git-info 2.8.8, ansi-regex 4.1.0 |
| bun | `package.json`, `bun.lock` | express 4.17.1, qs 6.5.2, path-to-regexp 0.1.7 |
| maven | `pom.xml` | log4j-core 2.14.1 (CVE-2021-44228), commons-text 1.9 (CVE-2022-42889), snakeyaml 1.30 (CVE-2022-1471) |
| gradle | `build.gradle`, `build.gradle.kts` | same JVM set across both DSLs |
| pip | `requirements.txt` | PyYAML 5.1 (CVE-2020-1747), Jinja2 2.10 (CVE-2019-10906), Django 2.2.0 |
| pipenv | `Pipfile`, `Pipfile.lock` | Django 2.2.0, requests 2.19.1, urllib3 1.24.1 |
| poetry | `pyproject.toml`, `poetry.lock` | lxml 4.6.2, Pillow 8.1.0, PyYAML 5.1 |
| uv | `pyproject.toml`, `uv.lock` | cryptography 3.2, Jinja2 2.10 |
| go | `go.mod`, `go.sum` | jwt-go v3.2.0 (CVE-2020-26160), x/text v0.3.0 (CVE-2020-14040), yaml.v2 v2.2.2 |
| cargo | `Cargo.toml`, `Cargo.lock` | regex 1.5.4 (CVE-2022-24713), time 0.1.44, smallvec 1.6.0 |
| composer | `composer.json`, `composer.lock` | guzzle 6.5.2 (CVE-2022-31090), phpmailer 6.1.5 (CVE-2020-36326) |
| rubygems | `Gemfile`, `Gemfile.lock` | nokogiri 1.10.4 (CVE-2019-5477), rack 2.0.6, puma 4.3.1 |
| nuget | `VulnCorpus.csproj`, `packages.lock.json` | Newtonsoft.Json 12.0.2, log4net 2.0.8 (CVE-2018-1285) |
| pub | `pubspec.yaml`, `pubspec.lock` | http 0.13.0, archive 3.1.2, dio 4.0.0 |
| mix | `mix.exs`, `mix.lock` | plug 1.9.0, phoenix 1.5.7 |
| conan | `conanfile.txt`, `conan.lock` | openssl 1.0.2u, zlib 1.2.11 (CVE-2018-25032) |
| swiftpm | `Package.swift`, `Package.resolved` | vapor 4.0.0, swift-nio 2.29.0 |
| cpan | `cpanfile` | Archive::Tar 2.32, LWP::UserAgent 6.36 |

**Check:** every ecosystem reports at least one vulnerable component, and the
component name/version in the report matches the manifest.

---

## SAST — tier 1

| File | Expected classes |
|---|---|
| `javascript/express-injection.js` | eval/Function on request data, command injection, SQLi, NoSQLi, path traversal, SSRF, open redirect |
| `javascript/crypto-session-config.js` | JWT `alg: none`, DES/MD5/SHA1, `Math.random` tokens, hardcoded secrets, insecure session cookie, plaintext HTTP listener |
| `javascript/ai-llm-handling.js` | prompt injection, `eval`/`new Function` on model output, `innerHTML`/`dangerouslySetInnerHTML` on model output, unconstrained ShellTool |
| `typescript/api-handlers.ts` | same injection set as JS — confirms `.ts` is catalogued, not just `.js` |
| `python/injection_views.py` | eval/exec/compile, `os.system`, `shell=True`, `os.popen`, SQLi (`%`-format and f-string), Django raw SQL, pickle/yaml/marshal, Flask `debug=True` |
| `python/crypto_and_ai.py` | MD5/SHA1/DES/AES-ECB, prompt injection, exec of model output, subprocess on model output, MCP over plaintext `0.0.0.0` |
| `go/handlers.go` | SQLi (concat and `Sprintf`), `exec.Command("sh","-c",…)`, reflected XSS, open redirect, path traversal, header injection, SSRF, wildcard CORS, debug mode, plaintext `ListenAndServe` |
| `go/crypto.go` | `math/rand`, MD5/SHA1, `InsecureSkipVerify`, `strings.Compare` on a secret, gob decode, embedded API key / password / RSA key |
| `php/vulnerable_app.php` | SQLi, command injection (`system`/`shell_exec`/`passthru`/`exec`), `eval`, LFI/RFI, `unserialize`, XSS, traversal, SSRF with `VERIFYPEER=false`, MD5/SHA1, open redirect, unrestricted upload |
| `ruby/vulnerable_controller.rb` | SQLi, backtick/`system` command injection, `eval`/ERB, `YAML.load`/`Marshal.load`, mass assignment, SSRF, traversal, MD5/SHA1, open redirect, `html_safe` |
| `java/VulnerableServlet.java` | SQLi, `Runtime.exec`, LDAP injection, XXE, `ObjectInputStream`, SSRF, traversal, MD5, `java.util.Random`, XSS, open redirect |
| `csharp/VulnerableController.cs` | SQLi, `Process.Start`, XXE via `XmlUrlResolver`, `BinaryFormatter` + `TypeNameHandling.All`, cert validation bypass, traversal, MD5, `Random`, XSS, open redirect |
| `rust/vulnerable.rs` | `sh -c` command injection, SQLi via `format!`, traversal, MD5/SHA1, `danger_accept_invalid_certs`, raw-pointer `unsafe`, null deref, `unwrap`/slice panics |
| `kotlin/VulnerableService.kt` | SQLi, `Runtime.exec`/`ProcessBuilder`, `ObjectInputStream`, SSRF, traversal, MD5, `Random`, XSS, open redirect |
| `swift/VulnerableService.swift` | `Process` with `sh -c`, SQLi via interpolation, cleartext HTTP, CommonCrypto MD5, `arc4random_uniform`, secrets in `UserDefaults`, cert validation bypass |
| `cpp/vulnerable.cpp` | `strcpy`/`strcat`/`gets` overflow, format string, use-after-free, double free, integer overflow, `system()` injection, SQLi, MD5, unchecked `malloc` |

---

## SAST — long tail

One file each in `sast/long-tail/`. Expected rule ids are in each file's header.

| File | Language | Rules |
|---|---|---|
| `vulnerable.adb` | Ada | `ada-gnat-spawn`, `ada-md5`, `ada-file-open` |
| `vulnerable.s` | Assembly | `asm-syscall` |
| `vulnerable.sh` | Bash | `bash-eval`, `bash-sh-c`, `bash-chmod-777`, `bash-curl-pipe-shell` |
| `vulnerable.cr` | Crystal | `crystal-system`, `crystal-process-run`, `crystal-file-read`, `crystal-http-get` |
| `vulnerable.d` | D | `d-execute-shell`, `d-md5`, `d-std-file` |
| `vulnerable.dart` | Dart | `dart-process-run`, `dart-weak-hash`, `dart-raw-sql`, `dart-http-client`, `dart-isolate-spawn-uri` |
| `vulnerable.ex` | Elixir | `elixir-code-eval`, `elixir-system-cmd`, `elixir-binary-to-term`, `elixir-md5`, `elixir-file-read`, `elixir-httpoison-get` |
| `Vulnerable.elm` | Elm | `elm-debug-todo`, `elm-debug-log`, `elm-http-get` |
| `vulnerable.erl` | Erlang | `erlang-os-cmd`, `erlang-binary-to-term`, `erlang-open-port`, `erlang-file-read` |
| `vulnerable.f90` | Fortran | `fortran-execute-command`, `fortran-open` |
| `vulnerable.gleam` | Gleam | `gleam-file-read`, `gleam-os-cmd`, `gleam-httpc` |
| `Vulnerable.hs` | Haskell | `haskell-unsafe-perform-io`, `haskell-unsafe-coerce`, `haskell-create-process`, `haskell-read-process` |
| `vulnerable.jl` | Julia | `julia-eval`, `julia-meta-parse`, `julia-deserialize`, `julia-cmd` |
| `vulnerable.lisp` | Lisp | `lisp-eval`, `lisp-read-from-string`, `lisp-run-program`, `lisp-launch-program` |
| `vulnerable.lua` | Lua | `lua-os-execute`, `lua-io-popen`, `lua-loadstring`, `lua-io-open` |
| `vulnerable.nim` | Nim | `nim-exec-shell`, `nim-exec-process`, `nim-static-exec`, `nim-read-file` |
| `vulnerable.ml` | OCaml | `ocaml-sys-command`, `ocaml-marshal`, `ocaml-unix-open-process` |
| `vulnerable.pas` | Pascal | `pascal-shell-execute` |
| `vulnerable.pl` | Perl | `perl-system`, `perl-eval-string`, `perl-storable-thaw`, `perl-md5`, `perl-lwp` |
| `vulnerable.ps1` | PowerShell | `ps-invoke-expression`, `ps-download-string`, `ps-securestring-plain`, `ps-add-type`, `ps-start-process` |
| `vulnerable.R` | R | `r-system`, `r-eval-parse`, `r-source`, `r-readrds`, `r-download-file`, `r-unserialize` |
| `Vulnerable.sol` | Solidity | `solidity-delegatecall`, `solidity-selfdestruct`, `solidity-tx-origin`, `solidity-block-timestamp` |
| `vulnerable.sql` | SQL | `sql-xp-cmdshell`, `sql-openrowset`, `sql-grant-all`, `sql-trustworthy`, `sql-exec`, `sql-sp-executesql` |
| `vulnerable.v` | V | `v-os-execute`, `v-os-read-file` |
| `vulnerable.zig` | Zig | `zig-process-child`, `zig-c-import`, `zig-http-client` |

---

## Secret

| File | Expected rule families |
|---|---|
| `config/cloud-providers.env` | AWS (access/secret/session/account), GCP, Firebase, Azure (client secret, storage key, connection string, DevOps PAT), DigitalOcean, Heroku, Vercel, Netlify, Cloudflare |
| `config/saas-and-vcs.env` | GitHub (PAT, fine-grained, OAuth, app), GitLab, Bitbucket, Docker Hub, npm, PyPI, Stripe, Razorpay, PayPal, Slack, Telegram, Twilio, SendGrid, OpenAI, Anthropic, Google AI, Groq, Hugging Face, Datadog, Sentry, Grafana, Vault, Doppler, Supabase, PlanetScale, Shopify, Notion, Linear, Jira, Airtable |
| `config/datastores.yaml` | MongoDB / PostgreSQL / MySQL / Redis / Kafka / RabbitMQ connection strings, password-in-URL, weak / short / empty / admin passwords, generic secret, session secret, encryption key |
| `keys/private-keys.txt` | RSA, generic, DSA, EC, OpenSSH, PGP, PKCS#8, encrypted PKCS#8, PuTTY, age, x509 |
| `keys/dotfiles-credentials.txt` | `.aws/credentials`, `.s3cfg`, `.netrc`, `.pgpass`, `.git-credentials`, `.htpasswd`, shadow, bcrypt, proftpd, FileZilla, esmtprc, JetBrains, Rails `secret_key_base`, Django `SECRET_KEY`, wp-config, PHP db password, Basic/Bearer headers |
| `code/hardcoded.{js,py,go,java,rs}` | the same shapes embedded in source — confirms detection is not limited to config files |
| `history/make-history-fixture.sh` | generates a repo where a working-tree scan finds **0** and a history scan finds **4** |

---

## IaC

| File | Expected rule families |
|---|---|
| `terraform/aws/main.tf` | `TF-AWS-S3-*`, `TF-AWS-SG-*`, `TF-AWS-EC2-*`, `TF-AWS-RDS-*`, `TF-AWS-IAM-*`, `TF-AWS-CLOUDTRAIL-*`, `TF-AWS-ECR-*`, `TF-AWS-KMS-001`, `TF-AWS-SQS-001`, `TF-AWS-VPC-001` |
| `terraform/azure/main.tf` | `TF-AZURE-STORAGE-*`, `TF-AZURE-NSG-*`, `TF-AZURE-VM-*`, `TF-AZURE-SQL-*`, `TF-AZURE-KV-*`, `TF-AZURE-AKS-*` |
| `terraform/gcp/main.tf` | `TF-GCP-GCS-*`, `TF-GCP-FIREWALL-*`, `TF-GCP-COMPUTE-*`, `TF-GCP-SQL-*`, `TF-GCP-IAM-*`, `TF-GCP-KMS-001`, `TF-GCP-GKE-*` |
| `cloudformation/stack.yaml` | `CF-AWS-S3-*`, `CF-AWS-EC2-*`, `CF-AWS-RDS-*`, `CF-AWS-LAMBDA-*`, `CF-AWS-CLOUDTRAIL-*`, `CF-AWS-DYNAMODB-*`, `CF-AWS-KMS-001`, `CF-AWS-ELB-001` |
| `kubernetes/workloads.yaml` | `K8S-SEC-*`, `K8S-RES-*`, `K8S-CAP-*`, `K8S-IMG-*`, `K8S-NET-*`, `K8S-RBAC-*`, `K8S-SECRET-001`, `K8S-INGRESS-001`, `K8S-PROBE-*` |
| `dockerfile/Dockerfile` | `DOCKER-001` … `DOCKER-020` (latest tag, root user, no healthcheck, layer count, ENV secrets, ADD, cache, SSH/DB/RDP ports, no WORKDIR, apt upgrade, sudo, `/bin/sh`, curl/wget piped to shell) |
| `docker-compose/docker-compose.yml` | `COMPOSE-SEC-001` … `COMPOSE-SEC-007` (privileged, host network/PID/IPC, docker socket mount, host root mount, exposed DB ports, plaintext credentials) |
| `github-actions/workflow.yml` | `pull_request_target` with untrusted checkout, `${{ github.event.* }}` script injection, unpinned actions, `permissions: write-all`, hardcoded secrets |
| `helm/` | plaintext secrets in `values.yaml`, privileged security context, `latest` tag, no resource limits, hostPath mount |

---

**Author:** Vigilnz Security Engineering
**Last updated:** 2026-10-16
