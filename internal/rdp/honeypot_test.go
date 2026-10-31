package rdp

import (
	"testing"

	"rdpshot/internal/model"
)

func TestDetectHoneypot(t *testing.T) {
	cases := []struct {
		name       string
		svc        *model.ServiceInfo
		wantHoney  bool
		wantSig    HoneypotKind
		confidence string
	}{
		{
			name:      "clean modern windows",
			svc:       &model.ServiceInfo{NegotiatedProtocol: ProtocolHybrid, NLARequired: true, OSGuess: "Windows 11 / Server 2022"},
			wantHoney: false,
		},
		{
			name: "rdpy certificate",
			svc: &model.ServiceInfo{
				Certificate: &model.CertificateInfo{
					Subject: "CN=rdpy-honeypot, O=Test",
					Issuer:  "CN=rdpy-honeypot",
				},
			},
			wantHoney:  true,
			wantSig:    HoneypotRDPY,
			confidence: "high",
		},
		{
			name: "dionaea banner",
			svc: &model.ServiceInfo{
				Banner: "dionaea.rdp.emu 0.1",
			},
			wantHoney:  true,
			wantSig:    HoneypotDionaea,
			confidence: "high",
		},
		{
			name: "pyrdp trap certificate",
			svc: &model.ServiceInfo{
				Certificate: &model.CertificateInfo{
					Subject: "CN=pyrdp-mitm",
				},
			},
			wantHoney:  true,
			wantSig:    HoneypotPyRDP,
			confidence: "high",
		},
		{
			name: "protocol anomaly no mcs channels",
			svc: &model.ServiceInfo{
				NegotiatedProtocol: ProtocolRDP,
				ServerVersion:      0,
				EncryptionLevel:    "none",
			},
			wantHoney:  true,
			wantSig:    HoneypotGeneric,
			confidence: "medium",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := DetectHoneypot(tc.svc)
			if res.IsHoneypot != tc.wantHoney {
				t.Fatalf("IsHoneypot = %v, want %v", res.IsHoneypot, tc.wantHoney)
			}
			if tc.wantHoney {
				if res.Signature != tc.wantSig {
					t.Errorf("Signature = %q, want %q", res.Signature, tc.wantSig)
				}
				if res.Confidence != tc.confidence {
					t.Errorf("Confidence = %q, want %q", res.Confidence, tc.confidence)
				}
			}
		})
	}
}
