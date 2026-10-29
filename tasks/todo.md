# rdpshot — differentiating features

## Goal

Ship the audit-safe advanced capabilities that differentiate the product.
Out of scope: exploit/payload, LSASS/hash dump, lateral movement, C2, exfil.

## Checklist

- [x] Hardening / compliance score (API + reports UI)
- [x] Estate graph / risk map (`/estate`)
- [x] Client-trust / MitM posture checks
- [x] RD Gateway / RD Web / UDP 3389 discovery (detection)
- [x] Smart credential audit (priority + reuse)
- [x] Delta-driven retest
- [x] Policy-as-code
- [x] SIEM streaming (JSON/CEF)
- [x] Engagement workspace + evidence manifest hash
- [x] Pure-Go framebuffer (NLA + slow-path bitmap capture)
- [x] Tests, docs, README

## Next-wave (this pack)

- [x] Schema v4: host_notes, path/runtime options, MaxConcurrentScans, alerts
- [x] Fast-Path + PATBLT/SCRBLT/MEMBLT orders + fixture tests
- [x] CredSSP Kerberos offer when ccache present + findings
- [x] `/engagements` UI + nav wiring
- [x] `rdpshot policy check` CLI exit codes + README CI
- [x] Playbook catalog API + scan detail links
- [x] Concurrent scan queue + max runtime
- [x] Bulk triage API/UI + host notes
- [x] Logo/executive export, RBAC enforce, alert rules
- [x] Cert expiry panel, path posture, RD Gateway auth fingerprint

## Review

- CredSSP `HandshakeSession` sends TSCredentials; verify-only `Handshake` unchanged.
- `rdp.Capture` runs MCS → Client Info → License → Confirm Active → bitmap/orders (slow + fast path).
- AutoGrabber: FreeRDP → Go framebuffer → evidence card.
- Kerberos without a usable ccache stays NTLM; smart-card is discovery-only (no PIN UI).
- Default `--max-concurrent-scans=2`; excess scans remain `pending` until a slot frees.
