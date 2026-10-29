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
>   (`--max-auth-failures`, default 5), a global connection rate limit
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
* **Vulnerability checks** — BlueKeep (CVE-2019-0708) safe probe, DejaBlue
  heuristic, NLA enforcement, weak encryption, obsolete TLS, self-signed and
  expired certificates, exposed RDP service. Every finding carries evidence,
  a confidence status (`vulnerable | potential | not_vulnerable |
  inconclusive`) and remediation guidance.
* **Credential audit (opt-in)** — NLA/CredSSP + NTLMv2 dictionary checks with
  worker pool, jittered pacing, per-host failure budget and lockout
  detection.
* **Session screenshots (opt-in)** — after a verified login, a session image
  is captured via FreeRDP under a headless X server.
* **Persistence** — SQLite (pure Go, no CGO) for scans, hosts, findings,
  credentials and screenshot metadata.
* **Reporting** — self-contained HTML report, SIEM-friendly CSV, management
  PDF.
* **Web UI + REST API** — dashboard, live scan progress (SSE), scan history,
  findings, screenshot gallery, report center, bearer-token protection.

## Architecture

| Package | Responsibility |
|---|---|
| `cmd/rdpshot` | CLI entrypoint: `scan`, `serve`, `report`, `targets`, `version` |
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
| `internal/screenshot` | `xfreerdp`-based session screenshot grabber |
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
| `scan` | Run a scan in the foreground | `--name`, `--ports` (default `3389`), `--blacklist`, `--concurrency`, `--rate`, `--timeout`, `--max-targets`, `--max-auth-failures`, `--enable-vuln` (default on), `--enable-auth`, `--enable-screens`, `--ack-authorized`, `--user-wordlist`, `--password-wordlist`, `--report none\|html\|csv\|pdf`, `--report-dir`, `--db`, `--outputs`, `--config`, `--log-level`, `--log-format` |
| `serve` | Start the web UI and REST API | `--addr` (default `127.0.0.1:8722`), `--token`, `--db`, `--outputs`, `--config`, `--log-level`, `--log-format`, `--user-wordlist`, `--password-wordlist`, `--max-auth-failures` |
| `report` | Render a stored scan into a report | `--scan <id>` (required), `--format html\|csv\|pdf`, `-o/--output`, `--db` |
| `targets` | Resolve targets and print `address:port` lines | `--ports`, `--blacklist`, `--max-targets` |
| `version` | Print `rdpshot <version>` | — |

Progress and diagnostics go to stderr; results go to stdout. Exit codes:
`0` success, `1` runtime error (including a cancelled scan), `2` usage or
validation error. In particular, `--enable-auth`/`--enable-screens` without
`--ack-authorized` exits with code 2 and does not touch the network.

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
| max targets | `RDSHOT_MAX_TARGETS` | `--max-targets` | `65536` |
| max auth failures per host | `RDSHOT_MAX_AUTH_FAILURES` | `--max-auth-failures` | `5` |
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

Web pages: `/` dashboard, `/scans` history, `/scans/{id}` live scan detail,
`/gallery` screenshot gallery, `/reports` report center. Screenshot images are
served read-only under `/files/`.

| Method | Route | Description |
|---|---|---|
| `POST` | `/api/v1/scans` | Start a new scan |
| `GET` | `/api/v1/scans` | List past scans |
| `GET` | `/api/v1/scans/{id}` | Scan detail and progress |
| `POST` | `/api/v1/scans/{id}/cancel` | Cancel a running scan |
| `GET` | `/api/v1/scans/{id}/findings` | Findings of a scan |
| `GET` | `/api/v1/scans/{id}/hosts` | Hosts of a scan |
| `GET` | `/api/v1/scans/{id}/screenshots` | Screenshot metadata of a scan |
| `GET` | `/api/v1/scans/{id}/credentials` | Verified credentials (masked) |
| `GET` | `/api/v1/scans/{id}/report?format=html\|csv\|pdf` | Download a report |
| `GET` | `/api/v1/summary` | Dashboard summary |
| `GET` | `/api/v1/events` | Live event stream (SSE, `?scan=` filters) |

## Vulnerability checks

| Check ID | CVE | Severity | Method |
|---|---|---|---|
| `rdp-service-exposed` | — | info | RDP listener reachable |
| `nla-not-required` | — | high | RDP negotiation completed without NLA (HYBRID) |
| `rdp-security-without-tls` | — | medium | Legacy RDP security layer negotiated without TLS |
| `bluekeep-cve-2019-0708` | CVE-2019-0708 | critical | Safe `MS_T120` channel-join probe (no exploit code) |
| `dejablue-cve-2019-1181-1182` | CVE-2019-1181/1182 | critical | Heuristic (NLA off + old build); reported as `potential` |
| `weak-encryption` | — | high | Encryption level `none/low` or 40/56-bit methods |
| `weak-tls` | — | medium | TLS 1.0/1.1 or weak cipher (RC4/3DES/NULL) |
| `self-signed-cert` | — | medium | Self-signed certificate chain |
| `expired-cert` | — | medium | Certificate `NotAfter` in the past |

## Limitations

* **BlueKeep detection is a safe probe only.** Two benign `MS_T120` channel
  messages are sent and the server's reaction is observed; no exploit code,
  payload or shellcode is generated or executed. `vulnerable` means the probe
  condition was observed; verify patch state locally before acting.
* **NLA-enforced and legacy RDP-encrypted sessions are not probed for
  BlueKeep.** The virtual-channel layer needed by the probe is unavailable
  there; findings fall back to `potential` or `inconclusive`.
* **DejaBlue results are heuristic.** Remote confirmation of
  CVE-2019-1181/1182 is not possible; results are reported as `potential`,
  never as confirmed.
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