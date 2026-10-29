# rdpshot — allowed feature expansion

## Goal

Ship every previously recommended **audit-safe** capability. Explicitly out of
scope and not implemented: exploit/payload generation, LSASS/ticket/hash dump,
lateral movement, C2, file exfiltration.

## Checklist

- [x] Schema v3: triage, engagement/tags, notifications, cron, wordlist sets, users, audit, branding
- [x] Finding triage API + scan detail UI
- [x] Engagement / tags on scans + list display
- [x] Schedule webhook notifications
- [x] Cron expression schedules
- [x] Evidence pack ZIP export
- [x] Trend / baseline API + Reports chart
- [x] Additional RDP posture checks (detection-only)
- [x] Report branding in HTML/PDF + settings UI
- [x] Local users/roles + session login + audit log
- [x] Named wordlist sets CRUD in About page
- [x] Tests, docs, README

## Deferred (honest)

- Full pure-Go RDP framebuffer client (evidence card remains the slim fallback)
- Multi-tenant remote database

## Validation

* `go test ./...` — pass (re-run after UI)
* `go build -o bin/rdpshot ./cmd/rdpshot`
