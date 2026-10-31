package rdp

import (
	"strings"

	"rdpshot/internal/model"
)

// HoneypotKind identifies the detected honeypot or deception framework.
type HoneypotKind string

const (
	HoneypotNone    HoneypotKind = ""
	HoneypotRDPY    HoneypotKind = "RDPY / Cowrie RDP Honeypot"
	HoneypotDionaea HoneypotKind = "Dionaea Malware Honeypot"
	HoneypotPyRDP   HoneypotKind = "PyRDP MitM / Decoy Trap"
	HoneypotGeneric HoneypotKind = "Generic Emulated RDP Decoy"
)

// HoneypotDetection contains the outcome of the deception heuristics analysis.
type HoneypotDetection struct {
	IsHoneypot bool         `json:"is_honeypot"`
	Signature  HoneypotKind `json:"signature,omitempty"`
	Confidence string       `json:"confidence"` // "high", "medium", "low"
	Reason     string       `json:"reason,omitempty"`
	Evidence   string       `json:"evidence,omitempty"`
}

// DetectHoneypot analyzes certificate details, protocol quirks, banner strings,
// and MCS channel negotiations to discover whether an endpoint is an RDP honeypot.
func DetectHoneypot(svc *model.ServiceInfo) HoneypotDetection {
	if svc == nil {
		return HoneypotDetection{}
	}

	// 1. Certificate signatures (subject, issuer, SANs)
	if svc.Certificate != nil {
		certText := strings.ToLower(svc.Certificate.Subject + " " + svc.Certificate.Issuer)
		for _, name := range svc.Certificate.DNSNames {
			certText += " " + strings.ToLower(name)
		}

		if strings.Contains(certText, "rdpy") || strings.Contains(certText, "cowrie") {
			return HoneypotDetection{
				IsHoneypot: true,
				Signature:  HoneypotRDPY,
				Confidence: "high",
				Reason:     "Certificate subject/issuer explicitly matches RDPY/Cowrie signature",
				Evidence:   "Certificate Subject: " + svc.Certificate.Subject,
			}
		}

		if strings.Contains(certText, "dionaea") {
			return HoneypotDetection{
				IsHoneypot: true,
				Signature:  HoneypotDionaea,
				Confidence: "high",
				Reason:     "Certificate subject/issuer matches Dionaea malware trap",
				Evidence:   "Certificate Subject: " + svc.Certificate.Subject,
			}
		}

		if strings.Contains(certText, "pyrdp") {
			return HoneypotDetection{
				IsHoneypot: true,
				Signature:  HoneypotPyRDP,
				Confidence: "high",
				Reason:     "Certificate matches PyRDP MitM/honeypot tool",
				Evidence:   "Certificate Subject: " + svc.Certificate.Subject,
			}
		}

		if strings.Contains(certText, "honeypot") || strings.Contains(certText, "honeytrap") || strings.Contains(certText, "conpot") {
			return HoneypotDetection{
				IsHoneypot: true,
				Signature:  HoneypotGeneric,
				Confidence: "high",
				Reason:     "Deception/honeypot keyword in TLS certificate",
				Evidence:   "Certificate Subject: " + svc.Certificate.Subject,
			}
		}

		// Suspicious test/fake default certificates on port 3389
		if (svc.Certificate.Subject == "CN=localhost" || svc.Certificate.Subject == "CN=test") && svc.Certificate.SelfSigned {
			if svc.NegotiatedProtocol == ProtocolRDP {
				return HoneypotDetection{
					IsHoneypot: true,
					Signature:  HoneypotGeneric,
					Confidence: "medium",
					Reason:     "Generic dummy self-signed certificate on standard RDP security",
					Evidence:   "Self-signed " + svc.Certificate.Subject,
				}
			}
		}
	}

	// 2. Banner and OS guess heuristics
	bannerLower := strings.ToLower(svc.Banner + " " + svc.OSGuess)
	if strings.Contains(bannerLower, "rdpy") || strings.Contains(bannerLower, "twisted") {
		return HoneypotDetection{
			IsHoneypot: true,
			Signature:  HoneypotRDPY,
			Confidence: "high",
			Reason:     "RDP banner exhibits Twisted / Python RDP stack signature",
			Evidence:   "Banner: " + svc.Banner,
		}
	}

	if strings.Contains(bannerLower, "dionaea") {
		return HoneypotDetection{
			IsHoneypot: true,
			Signature:  HoneypotDionaea,
			Confidence: "high",
			Reason:     "Banner explicitly identifies Dionaea trap",
			Evidence:   "Banner: " + svc.Banner,
		}
	}

	// 3. Protocol anomalies: claims RDP standard security (0) but no MCS channels or server core version
	if svc.NegotiatedProtocol == ProtocolRDP && svc.ServerVersion == 0 && len(svc.MCSChannelIDs) == 0 && svc.EncryptionLevel == "none" {
		return HoneypotDetection{
			IsHoneypot: true,
			Signature:  HoneypotGeneric,
			Confidence: "medium",
			Reason:     "Server returned RDP Standard Security but failed to offer standard MCS core channels",
			Evidence:   "Protocol 0 with 0 MCS channels and no encryption",
		}
	}

	return HoneypotDetection{}
}
