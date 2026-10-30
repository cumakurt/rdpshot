# rdpshot

`rdpshot` is a single-binary RDP security-audit platform for authorized
penetration tests and internal audits. It discovers Remote Desktop services,
fingerprinting the RDP negotiation, TLS and certificate posture of every
endpoint, runs a catalog of configuration and vulnerability checks (including a
safe BlueKeep detection probe), and — only with explicit authorization — audits
credentials and captures session screenshots. Results are stored in SQLite and
rendered as HTML, CSV or PDF reports, either from the CLI or from the bundled
web UI.

> ## ⚠️ Legal / authorized-use warning
>
> `rdpshot` is dual-use security tooling. **Only scan systems you are
> explicitly authorized to test.** Unauthorized scanning and credential testing
> is illegal in most jurisdictions.
>
> * Vulnerability scanning is the default. Credential checks
>   (`--enable-auth`) and screenshot capture (`--enable-screens`) are
>   **disabled by default** and refuse to run without `--ack-authorized`,
>   which confirms you are permitted to test the targets.
> * The BlueKeep check is a **safe detection probe**. The tool never
>   generates or runs exploit code, payloads or shellcode.
> * Credential checks are bounded: a per-host failure limit
>   (`--max-auth-failures`, default 5; `0` disables the limit), a global connection rate limit
>   (`--rate`, default 10/s) and lockout detection stop the audit before
>   accounts are locked out.
> * Verified credentials are stored with restrictive file permissions and are
>   always masked in reports and in the UI.

## Features

* **Target handling** — IP, CIDR, hostname, `host:port` and `@file` target
  specifications, port lists and ranges, blacklist, hard expansion limits.
* **Reconnaissance** — TCP connect with RDP negotiation analysis (X.224 /
  RDP_NEG), NLA detection, TLS version and cipher capture, certificate
  analysis (chain, self-signed, expiry, SHA-256 fingerprint), server-side
  encryption level/method and MCS details.
* **Vulnerability checks** — BlueKeep (CVE-2019-0708) safe probe, NLA
  enforcement, weak encryption, obsolete TLS, self-signed and expired
  certificates, exposed RDP service. Findings are confirmation-first: only
  positively observed `vulnerable` or ruled-out `not_vulnerable` results are
  reported (no speculative Critical/potential noise).
* **Credential audit (opt-in)** — NLA/CredSSP + NTLMv2 dictionary checks with
  worker pool, jittered pacing, per-host failure budget and lockout
  detection. TLS/RDP-only hosts are skipped (aligned with `nla-not-required`);
  attempt timelines and stop reasons are persisted without secrets. OCR
  login-tile usernames are quality-gated and prepended into the same-scan
  wordlist for NLA hosts.
* **Session screenshots** — when login fails or is skipped, rdpshot tries a
  pre-auth **login-screen** capture over TLS (`xfreerdp /sec:tls` under Xvfb).
  If Winlogon is unreachable (NLA/HYBRID required), no synthetic detection PNG
  is stored — the gallery only shows real frames. Optional `tesseract` OCR
  extracts Winlogon account tiles into `login_users`. Live desktop capture
  remains opt-in / post-login: FreeRDP when available, else pure-Go NLA bitmap
  framebuffer, else a verified-login evidence card. Drawing Orders / RDPGFX are
  not implemented in the Go path.
* **Hardening score** — 0–100 compliance score (NLA, TLS, cert, crypto, criticals).
* **Executive one-pager** — HTML/PDF summary includes NLA coverage %, auth audit
  outcomes, and open finding counts; compare shows remediated burn-down and
  hardening score delta.
* **Estate map** — `/estate` risk graph of hosts and findings per engagement.
* **Client-trust checks** — certificate hostname/SAN mismatch and cipher posture.
* **RD Web / Gateway / UDP discovery** — optional detection-only alternate paths.
* **Smart credential audit** — high-risk host priority and verified-credential reuse.
* **Delta retest** — `base_scan_id` limits work to new/changed/open-triage hosts.
* **Policy-as-code** — declarative pass/fail gate (`GET/PUT /api/v1/policy`) and CI CLI (`rdpshot policy check`).
* **Engagement workspace** — `/engagements` portal for scope freeze, host notes, and evidence shortcuts.
* **Remediation playbooks** — static `check_id` guides via `/api/v1/playbooks`.
* **Scan queue** — `--max-concurrent-scans` (default 2) keeps excess jobs pending; optional `max_runtime_sec`.
* **Alert rules / SLA** — critical, high, NLA regression, credential-reuse, open-triage
  critical, and minimum hardening-score floor webhooks on scan finish.
* **Path posture** — label scans `internal`/`external` for dual-homed compare.
* **Framebuffer deepen** — Fast-Path updates plus PATBLT/SCRBLT/MEMBLT orders (best-effort).
* **Kerberos offer** — CredSSP advertises Kerberos when a usable ccache/keytab is present.
* **SIEM streaming** — JSON or CEF webhook on scan completion.
* **Engagement packs** — evidence ZIP includes `manifest.json` with SHA-256 hashes.
* **Scan compare** — diff hosts and findings between two audits.
* **Finding triage** — open / confirmed / false positive / remediated workflow.
* **Engagements & tags** — label scans for client/scope filtering and trends.
* **Schedules** — interval or five-field cron cadence with optional webhooks.
* **Evidence pack v2** — ZIP export of HTML/CSV/PDF, hosts/findings/auth_attempts
  JSON, masked credentials, screenshots (no synthetic rdp-open), PACK_README, and
  SHA-256 `manifest.json`.
* **Kerberos discovery** — when a usable ccache/keytab is present, CredSSP offers
  Kerberos and records kind/source evidence (no ticket construction / no PIN UI).
* **Trend / baseline** — posture time series across completed scans.
* **Local users & audit log** — optional portal accounts with role-aware sessions.
* **Named wordlist sets** and report branding metadata.
* **Persistence** — SQLite (pure Go, no CGO) for scans, hosts, findings,
  credentials and screenshot metadata.
* **Reporting** — self-contained HTML report, SIEM-friendly CSV, management
  PDF with branding fields.
* **Web UI + REST API** — dashboard, live scan progress (SSE), scan history,
  findings, screenshot gallery, report center, bearer-token protection.

## Architecture

| Package | Responsibility |
|---|---|
| `cmd/rdpshot` | CLI entrypoint: `scan`, `serve`, `report`, `targets`, `version` |
| `internal/about` | Product identity and developer credits shared by CLI, UI and reports |
| `internal/cronexpr` | Five-field cron parser for schedule cadence |
| `internal/notify` | Outbound webhook notifications for scheduled scans |
| `internal/model` | Shared domain types (Scan, Host, Finding, Credential, Screenshot, Event, ...) |
| `internal/config` | Configuration resolution: defaults, JSON file, `RDSHOT_*` env, flags |
| `internal/target` | Target spec parsing and expansion (IP, CIDR, hostname, `@file`, blacklist) |
| `internal/rdp` | RDP protocol stack: TPKT/COTP, X.224 + RDP_NEG, MCS/GCC, TLS info, safe probes |
| `internal/vuln` | Vulnerability check catalog and finding evaluation |
| `internal/scanner` | Scan engine: worker pool, rate limiter, stage orchestration |
| `internal/brute` | Bounded, fail-safe credential-audit engine and wordlist handling |
| `internal/ntlm` | NTLMv2 message construction and parsing |
| `internal/credssp` | CredSSP/SPNEGO/TSRequest encoding for NLA authentication |
| `internal/auth` | RDP NLA authentication with classified error outcomes |
| `internal/screenshot` | Auto grabber: FreeRDP → Go bitmap framebuffer → evidence card |
| `internal/score` | Hardening / compliance scoring |
| `internal/estate` | Attack-surface graph builder |
| `internal/policy` | Declarative hardening policy evaluation |
| `internal/siem` | JSON/CEF event formatting and delivery |
| `internal/discovery` | RD Web / Gateway / UDP detection probes |
| `internal/engagement` | Evidence manifest hashing and scope freeze |
| `internal/store` | SQLite persistence and aggregate queries |
| `internal/events` | Bounded publish/subscribe hub for live events (SSE) |
| `internal/reporter` | HTML, CSV and PDF report rendering |
| `internal/server` | REST API and web UI (`web/templates`, `web/static`) |

## Install

### Automated installer (Linux)

`install.sh` detects the distribution (apt/dnf/yum/pacman/apk/zypper), installs
any missing build tooling including a Go toolchain, builds the project and
installs it under `/usr/local/rdpshot` with a symlink at `/usr/local/bin/rdpshot`.
Already installed packages are never downloaded again and the project is only
rebuilt when the sources changed.

```sh
sudo ./install.sh                 # install (progress bar, quiet output)
sudo ./install.sh --force         # rebuild even when nothing changed
sudo ./install.sh --dry-run       # show what would happen
sudo ./install.sh --uninstall     # remove the installation
```

### From source

Requires Go 1.27+.

```sh
git clone https://github.com/cumakurt/rdpshot.git && cd rdpshot
make build            # builds bin/rdpshot
# or
go build -trimpath -ldflags "-X main.version=$(git describe --always)" -o bin/rdpshot ./cmd/rdpshot
```

Cross-compiled binaries for linux/windows/darwin (amd64 + arm64):

```sh
make cross
```

### Docker

```sh
docker build -t rdpshot .              # slim runtime (default): web UI + scanning
docker build --target full -t rdpshot:full .   # adds FreeRDP/Xvfb/ImageMagick for screenshots
docker run --rm -p 8722:8722 -v rdpshot-data:/data rdpshot
# or
docker compose up -d
```

The slim image is distroless and runs as a non-root user; the `full` image
adds the screenshot capture toolchain (`xfreerdp`, `xvfb-run`, ImageMagick).
Both images write results to `/data` and ship the default wordlists under
`/usr/share/rdpshot/wordlists/`, with `RDSHOT_USER_WORDLIST` and
`RDSHOT_PASSWORD_WORDLIST` pointing at them.

## Quick start

Scan a subnet in the foreground:

```sh
rdpshot scan 10.0.0.0/24
```

Serve the web UI on <http://127.0.0.1:8722/>:

```sh
rdpshot serve
```

Run an authorized credential audit and capture screenshots (both require the
explicit acknowledgement):

```sh
rdpshot scan --enable-auth --enable-screens --ack-authorized \
  --user-wordlist wordlists/default_users.txt \
  --password-wordlist wordlists/default_passwords.txt \
  10.0.0.0/24
```

Single credential or pass-the-hash (also require `--ack-authorized`; these modes
imply `--enable-auth` and auto-enable screenshots):

```sh
rdpshot scan --ack-authorized --auth-mode=single \
  --auth-user alice --auth-domain CORP --auth-password '...' \
  10.0.0.10

rdpshot scan --ack-authorized --auth-mode=pth \
  --auth-user bob --auth-nthash a4f49c406510bdcab6824ee7c30fd852 \
  10.0.0.10
```

On a successful single/PTH login the tool captures a screenshot and
**disconnects immediately** (no lingering interactive session).

`--auth-domain` sets the default domain for wordlist, single, and PTH modes.
Wordlist lines may still embed `DOMAIN\user` or `user@domain` (those win).
`--auth-nthash` accepts a 32-character hex NT hash or an `LM:NT` pair. PTH
session screenshots use the Go framebuffer path only (FreeRDP is skipped).

Generate a PDF report for a finished scan:

```sh
rdpshot report --scan <scan-id> --format pdf
```

## CLI reference

```
rdpshot <command> [flags] [targets...]
```

Flags must come before the target specifications. Targets are one or more of:
`192.168.1.10`, `10.0.0.0/24`, `host.example.com`, `10.0.0.5:3389`,
`@targets.txt` (one specification per line).

| Command | Purpose | Key flags |
|---|---|---|
| `scan` | Run a scan in the foreground | `--name`, `--ports` (default `3389`), `--blacklist`, `--concurrency`, `--rate`, `--timeout`, `--max-targets`, `--max-auth-failures`, `--enable-vuln` (default on), `--enable-auth`, `--enable-screens`, `--ack-authorized`, `--user-wordlist`, `--password-wordlist`, `--auth-mode wordlist\|single\|pth`, `--auth-user`, `--auth-domain` (all modes), `--auth-password`, `--auth-nthash`, `--report none\|html\|csv\|pdf`, `--report-dir`, `--db`, `--outputs`, `--config`, `--log-level`, `--log-format` |
| `serve` | Start the web UI and REST API | `--addr` (default `127.0.0.1:8722`), `--token`, `--db`, `--outputs`, `--config`, `--log-level`, `--log-format`, `--user-wordlist`, `--password-wordlist`, `--max-auth-failures`, `--max-targets`, `--max-concurrent-scans` (default `2`) |
| `report` | Render a stored scan into a report | `--scan <id>` (required), `--format html\|csv\|pdf`, `-o/--output`, `--db` |
| `policy check` | CI gate against a stored scan | `--scan <id>` (required), `--db`, `--policy path.json` (optional) |
| `targets` | Resolve targets and print `address:port` lines | `--ports`, `--blacklist`, `--max-targets` |
| `version` | Print `rdpshot <version>` | — |

Progress and diagnostics go to stderr; results go to stdout. Exit codes:
`0` success, `1` runtime error (including a cancelled scan or policy fail), `2` usage or
validation error. In particular, `--enable-auth`/`--enable-screens` without
`--ack-authorized` exits with code 2 and does not touch the network.

### Policy CI gate

```sh
rdpshot policy check --db outputs/rdpshot.db --scan <scan-id>
# exit 0 = pass, exit 1 = fail, exit 2 = error
```

Example GitHub Actions step:

```yaml
- name: Policy gate
  run: rdpshot policy check --db outputs/rdpshot.db --scan "$SCAN_ID"
```

## Configuration

Values are resolved with the following precedence (highest first):

1. command line flags
2. environment variables (`RDSHOT_*`)
3. JSON config file (`--config`)
4. built-in defaults

| Setting | Env | Flag | Default |
|---|---|---|---|
| database path | `RDSHOT_DB` | `--db` | `outputs/rdpshot.db` |
| outputs directory | `RDSHOT_OUTPUTS` | `--outputs` | `outputs` |
| concurrency | `RDSHOT_CONCURRENCY` | `--concurrency` | `64` |
| rate (conn/s) | `RDSHOT_RATE` | `--rate` | `10` |
| dial timeout | `RDSHOT_TIMEOUT` | `--timeout` | `5s` |
| max targets | `RDSHOT_MAX_TARGETS` | `--max-targets` | `0` (unlimited; set a positive value to cap) |
| max auth failures per host | `RDSHOT_MAX_AUTH_FAILURES` | `--max-auth-failures` | `5` (`0` = unlimited / no lockout fail-safe) |
| server addr | `RDSHOT_ADDR` | `--addr` | `127.0.0.1:8722` |
| auth token | `RDSHOT_TOKEN` | `--token` | empty (localhost only) |
| log level | `RDSHOT_LOG_LEVEL` | `--log-level` | `info` |
| log format | `RDSHOT_LOG_FORMAT` | `--log-format` | `text` |
| user wordlist | `RDSHOT_USER_WORDLIST` | `--user-wordlist` | `wordlists/default_users.txt` |
| password wordlist | `RDSHOT_PASSWORD_WORDLIST` | `--password-wordlist` | `wordlists/default_passwords.txt` |

The JSON config file uses the same names as the settings above in snake_case
(`db_path`, `outputs_dir`, `concurrency`, `rate`, `timeout`, `max_targets`,
`max_auth_failures`, `addr`, `token`, `log_level`, `log_format`,
`user_wordlist`, `password_wordlist`). `timeout` is a Go duration encoded in
nanoseconds (e.g. `5000000000` for 5s); prefer `RDSHOT_TIMEOUT=5s` when in
doubt.

Scans started from the CLI or the web form carry their own per-scan options
(targets, ports, blacklist, enable flags, wordlists) which override the
resolved defaults.

## Web UI and REST API

`rdpshot serve` listens on `127.0.0.1:8722` by default. When the listener is
reachable beyond localhost, set `--token` (or `RDSHOT_TOKEN`): every route then
requires `Authorization: Bearer <token>` or `?token=`.

Web pages: `/` command-center dashboard, `/scans` scans dashboard (KPIs + inventory), `/scans/{id}` live scan detail,
`/compare` scan diff, `/engagements` workspace, `/schedules` recurring audits,
`/gallery` screenshot gallery, `/reports` report center, `/about` developer
credits. Screenshot images are served read-only under `/files/`. Every page
footer shows the build version and developer attribution.

| Method | Route | Description |
|---|---|---|
| `POST` | `/api/v1/scans` | Start a new scan (multipart wordlist uploads supported) |
| `GET` | `/api/v1/scans` | List past scans |
| `GET` | `/api/v1/scans/{id}` | Scan detail and progress |
| `PATCH` | `/api/v1/scans/{id}` | Rename a scan |
| `DELETE` | `/api/v1/scans/{id}` | Delete a finished scan and its artifacts |
| `POST` | `/api/v1/scans/{id}/cancel` | Cancel a running or paused scan |
| `POST` | `/api/v1/scans/{id}/pause` | Pause a running scan (queued work is kept) |
| `POST` | `/api/v1/scans/{id}/resume` | Resume a paused scan |
| `POST` | `/api/v1/scans/{id}/brute` | Credential-only re-audit of discovered hosts |
| `GET` | `/api/v1/scans/{id}/diff?against={id}` | Diff hosts/findings against another scan |
| `GET` | `/api/v1/scans/{id}/findings` | Findings of a scan |
| `GET` | `/api/v1/scans/{id}/hosts` | Hosts of a scan |
| `GET` | `/api/v1/scans/{id}/screenshots` | Screenshot metadata of a scan |
| `GET` | `/api/v1/scans/{id}/credentials` | Verified credentials (masked) |
| `GET` | `/api/v1/scans/{id}/report?format=html\|csv\|pdf` | Download a report for one scan |
| `GET` | `/api/v1/reports/export?format=html\|csv\|pdf&scan={id}\|all` | Download a report for one scan or all scans (embeds screenshots) |
| `GET` | `/api/v1/schedules` | List recurring schedules |
| `POST` | `/api/v1/schedules` | Create a recurring schedule |
| `GET` | `/api/v1/schedules/{id}` | Schedule detail |
| `PATCH` | `/api/v1/schedules/{id}` | Enable/disable, retune or run-now |
| `DELETE` | `/api/v1/schedules/{id}` | Delete a schedule |
| `GET` | `/api/v1/settings/wordlists` | Current default wordlist paths |
| `PATCH` | `/api/v1/settings/wordlists` | Update runtime default wordlist paths |
| `GET` | `/api/v1/summary` | Dashboard summary |
| `GET` | `/api/v1/about` | Product version and developer credits |
| `GET` | `/api/v1/analytics` | Cross-scan posture analytics |
| `GET` | `/api/v1/trend` | Posture trend/baseline series |
| `PATCH` | `/api/v1/findings/{fid}/triage` | Update finding triage status/note |
| `POST` | `/api/v1/findings/bulk-triage` | Bulk update finding triage |
| `PATCH` | `/api/v1/scans/{id}/meta` | Update engagement/tags |
| `GET` | `/api/v1/scans/{id}/evidence-pack` | Download evidence ZIP (includes `manifest.json`) |
| `GET` | `/api/v1/scans/{id}/score` | Hardening / compliance score |
| `GET` | `/api/v1/scans/{id}/policy` | Evaluate scan against stored policy |
| `GET` | `/api/v1/scans/{id}/reuse` | Credential reuse across hosts |
| `GET` | `/api/v1/estate` | Estate risk graph (`engagement`, `scan_id`) |
| `GET/PUT` | `/api/v1/policy` | Hardening policy document |
| `GET` | `/api/v1/playbooks` | Remediation playbook catalog |
| `GET` | `/api/v1/playbooks/{check_id}` | One remediation playbook |
| `GET/PUT` | `/api/v1/host-notes` | Host notes (PUT upsert) |
| `DELETE` | `/api/v1/host-notes/{id}` | Delete a host note |
| `GET/PUT` | `/api/v1/settings/siem` | SIEM webhook sink (JSON/CEF) |
| `GET/PUT` | `/api/v1/settings/alerts` | Post-scan alert rules |
| `GET` | `/api/v1/engagements` | List engagement labels |
| `POST` | `/api/v1/engagements/freeze` | Freeze engagement scope snapshot |
| `GET` | `/api/v1/engagements/scope` | Load frozen engagement scope |
| `GET/PUT` | `/api/v1/settings/branding` | Report branding metadata (incl. logo data URI) |
| `GET/POST` | `/api/v1/wordlist-sets` | Named wordlist sets |
| `DELETE` | `/api/v1/wordlist-sets/{id}` | Delete a wordlist set |
| `POST` | `/api/v1/login` | Local user login (session token) |
| `GET/POST` | `/api/v1/users` | List/create local users |
| `DELETE` | `/api/v1/users/{id}` | Delete a local user |
| `GET` | `/api/v1/audit` | Recent audit log entries |
| `GET` | `/api/v1/events` | Live event stream (SSE, `?scan=` filters) |

## Vulnerability checks

| Check ID | CVE | Severity | Method |
|---|---|---|---|
| `rdp-service-exposed` | — | info | RDP listener reachable |
| `nla-not-required` | — | high | Negotiation selected RDP or TLS-only without CredSSP/NLA |
| `rdp-security-without-tls` | — | medium | Legacy RDP security layer negotiated without TLS |
| `bluekeep-cve-2019-0708` | CVE-2019-0708 | critical | Confirmed MCS Disconnect Provider Ultimatum after safe `MS_T120` probe |
| `weak-encryption` | — | high | Encryption level `none/low` or exclusively 40/56-bit RC4 methods |
| `weak-tls` | — | medium | TLS 1.0/1.1/SSL3 or weak cipher (RC4/3DES/NULL) |
| `self-signed-cert` | — | medium | Self-signed certificate chain |
| `expired-cert` | — | medium | Certificate `NotAfter` in the past |
| `rdp-negotiation-failure` | — | low | Server returned `RDP_NEG_FAILURE` |
| `cert-hostname-mismatch` | — | medium | DNS SANs present and do not match scanned hostname |
| `rd-web-exposed` / `rd-gateway-exposed` | — | info | Confirmed discovery markers |
| `udp-3389-open` | — | low | UDP/3389 returned a response payload |

## Limitations

* **BlueKeep detection is a safe probe only.** Two benign `MS_T120` channel
  messages are sent and the server's reaction is observed; no exploit code,
  payload or shellcode is generated or executed. `vulnerable` is reported only
  when an MCS Disconnect Provider Ultimatum follows a complete check pair.
* **NLA-enforced (HYBRID / HYBRID_EX) sessions are not probed for BlueKeep.**
  The virtual-channel layer needed by the probe is unavailable there, so no
  BlueKeep finding is emitted (avoids Critical false positives).
* **DejaBlue is not reported remotely.** CVE-2019-1181/1182 cannot be confirmed
  without local patch evidence; the scanner does not invent Critical findings.
* **Screenshots require external tooling**: FreeRDP (`xfreerdp`), Xvfb
  (`xvfb-run`) and ImageMagick (`import`) or `ffmpeg` on the host, or the
  `full` Docker target. The slim image reports the missing tooling and skips
  captures. Capture is implemented for Linux-style hosts with those tools;
  there is no native Windows or macOS capture path.
* **No exploitation, dumping or lateral movement.** Credential hashes, ticket
  extraction and post-exploitation are out of scope by design.
* The web UI has a single shared bearer token, not per-user accounts; keep it
  on localhost or behind a reverse proxy with proper authentication.

## Development

| Command | Description |
|---|---|
| `make build` | Build `bin/rdpshot` (version stampable via `VERSION=`) |
| `make test` | `go test ./...` |
| `make vet` | `go vet ./...` |
| `make fmt` | `gofmt -w .` |
| `make lint` | Fail when `gofmt -l .` is non-empty, then `go vet ./...` |
| `make cross` | Cross-compile linux/windows/darwin (amd64 + arm64) into `bin/` |
| `make docker` | Build the `slim` and `full` images |
| `make clean` | Remove `bin/` |

Tests live next to the code as `*_test.go` in each `internal/*` package and
cover target parsing, config precedence, byte-level protocol encode/decode,
the rate limiter, the store and report rendering.

Default wordlists for authorized audits live in `wordlists/`. They contain
well-known weak accounts and passwords and exist to prove that defaults are
still in use on the target — change them on real systems.

## Author

| | |
|---|---|
| Developer | Cuma KURT |
| Email | [cumakurt@gmail.com](mailto:cumakurt@gmail.com) |
| GitHub | [github.com/cumakurt/rdpshot](https://github.com/cumakurt/rdpshot) |
| LinkedIn | [linkedin.com/in/cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/) |

## License

rdpshot is released under the [GNU General Public License v3.0](LICENSE)
(GPL-3.0). See the `LICENSE` file for the full terms.

Copyright (C) 2026 Cuma KURT <cumakurt@gmail.com>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.