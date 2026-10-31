package rdp

import (
	"strings"

	"rdpshot/internal/model"
)

// SecurityLayerKind identifies a detected MFA or PAM solution.
type SecurityLayerKind string

const (
	LayerNone        SecurityLayerKind = ""
	LayerDuoMFA      SecurityLayerKind = "Duo Security MFA"
	LayerCyberArkPSM SecurityLayerKind = "CyberArk PSM"
	LayerEntraID     SecurityLayerKind = "Microsoft Entra ID (Azure AD)"
	LayerBeyondTrust SecurityLayerKind = "BeyondTrust PAM"
	LayerGuacamole   SecurityLayerKind = "Apache Guacamole Gateway"
	LayerSmartCard   SecurityLayerKind = "Smart Card / PIV MFA"
)

// MFAPAMDetection contains the result of the heuristics analysis.
type MFAPAMDetection struct {
	MFAEnforced      bool              `json:"mfa_enforced"`
	PAMProxyDetected bool              `json:"pam_proxy_detected"`
	Provider         SecurityLayerKind `json:"provider,omitempty"`
	Confidence       string            `json:"confidence"` // "high", "medium", "low"
	Evidence         string            `json:"evidence"`
}

// DetectMFAPAM applies heuristics across certificates, pre-auth messages,
// OCR login tiles, and banner evidence to discover MFA and PAM gateways.
func DetectMFAPAM(svc *model.ServiceInfo) MFAPAMDetection {
	if svc == nil {
		return MFAPAMDetection{}
	}

	// 1. Smart-card enforcement indicates hardware MFA
	if svc.SmartCardRequired {
		return MFAPAMDetection{
			MFAEnforced: true,
			Provider:    LayerSmartCard,
			Confidence:  "high",
			Evidence:    "CredSSP/NLA reported smart-card requirement",
		}
	}

	// 2. Certificate analysis
	if svc.Certificate != nil {
		certText := strings.ToLower(svc.Certificate.Subject + " " + svc.Certificate.Issuer)
		for _, san := range svc.Certificate.DNSNames {
			certText += " " + strings.ToLower(san)
		}

		if strings.Contains(certText, "cyberark") || strings.Contains(certText, "psm-") {
			return MFAPAMDetection{
				MFAEnforced:      true,
				PAMProxyDetected: true,
				Provider:         LayerCyberArkPSM,
				Confidence:       "high",
				Evidence:         "CyberArk PSM certificate markers: " + svc.Certificate.Subject,
			}
		}

		if strings.Contains(certText, "duo") {
			return MFAPAMDetection{
				MFAEnforced: true,
				Provider:    LayerDuoMFA,
				Confidence:  "high",
				Evidence:    "Duo Security certificate markers: " + svc.Certificate.Subject,
			}
		}

		if strings.Contains(certText, "azuread") || strings.Contains(certText, "ms-organization-access") ||
			strings.Contains(certText, "microsoft azure rsa tls") {
			return MFAPAMDetection{
				MFAEnforced: true,
				Provider:    LayerEntraID,
				Confidence:  "high",
				Evidence:    "Microsoft Entra ID / Azure AD certificate: " + svc.Certificate.Subject,
			}
		}

		if strings.Contains(certText, "beyondtrust") || strings.Contains(certText, "bomgar") {
			return MFAPAMDetection{
				PAMProxyDetected: true,
				Provider:         LayerBeyondTrust,
				Confidence:       "high",
				Evidence:         "BeyondTrust PAM certificate markers: " + svc.Certificate.Subject,
			}
		}
	}

	// 3. Evidence / Banner / RD Gateway / RD Web analysis
	var evidenceBlobs []string
	if svc.Banner != "" {
		evidenceBlobs = append(evidenceBlobs, svc.Banner)
	}
	if svc.RDGatewayAuth != "" {
		evidenceBlobs = append(evidenceBlobs, svc.RDGatewayAuth)
	}
	for _, ev := range svc.Evidence {
		evidenceBlobs = append(evidenceBlobs, ev)
	}

	allEvidence := strings.ToLower(strings.Join(evidenceBlobs, " "))
	if strings.Contains(allEvidence, "cyberark") || strings.Contains(allEvidence, "privileged session manager") {
		return MFAPAMDetection{
			MFAEnforced:      true,
			PAMProxyDetected: true,
			Provider:         LayerCyberArkPSM,
			Confidence:       "high",
			Evidence:         "CyberArk PSM gateway text observed in connection evidence",
		}
	}
	if strings.Contains(allEvidence, "duo security") || strings.Contains(allEvidence, "duo push") {
		return MFAPAMDetection{
			MFAEnforced: true,
			Provider:    LayerDuoMFA,
			Confidence:  "high",
			Evidence:    "Duo Security markers observed in pre-auth evidence",
		}
	}
	if strings.Contains(allEvidence, "guacamole") {
		return MFAPAMDetection{
			PAMProxyDetected: true,
			Provider:         LayerGuacamole,
			Confidence:       "high",
			Evidence:         "Apache Guacamole RDP proxy gateway detected",
		}
	}

	// 4. Pre-auth Login Users / OCR Tiles analysis
	for _, user := range svc.LoginUsers {
		u := strings.ToLower(user)
		if strings.Contains(u, "duo") {
			return MFAPAMDetection{
				MFAEnforced: true,
				Provider:    LayerDuoMFA,
				Confidence:  "medium",
				Evidence:    "Duo 2FA tile observed on pre-auth Winlogon UI: " + user,
			}
		}
		if strings.Contains(u, "azuread\\") || strings.Contains(u, "work or school account") {
			return MFAPAMDetection{
				MFAEnforced: true,
				Provider:    LayerEntraID,
				Confidence:  "medium",
				Evidence:    "Entra ID / Azure AD account tile observed: " + user,
			}
		}
		if strings.Contains(u, "cyberark") || strings.Contains(u, "psm") {
			return MFAPAMDetection{
				MFAEnforced:      true,
				PAMProxyDetected: true,
				Provider:         LayerCyberArkPSM,
				Confidence:       "medium",
				Evidence:         "CyberArk PSM tile observed on Winlogon UI: " + user,
			}
		}
	}

	return MFAPAMDetection{}
}
