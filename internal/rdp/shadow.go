package rdp

import (
	"fmt"
	"strings"

	"rdpshot/internal/model"
)

// ShadowPolicy defines the Remote Desktop Session Shadowing permission level.
type ShadowPolicy int

const (
	ShadowUnknown        ShadowPolicy = -1
	ShadowDisabled       ShadowPolicy = 0
	ShadowFullNoPrompt   ShadowPolicy = 1 // Critical: Full control without user consent
	ShadowFullWithPrompt ShadowPolicy = 2 // Safe: Full control requiring user permission
	ShadowViewNoPrompt   ShadowPolicy = 3 // High: Eavesdrop/view without user consent
	ShadowViewWithPrompt ShadowPolicy = 4 // Safe: View requiring user permission
)

// PolicyName returns the human readable description of the shadowing policy.
func (p ShadowPolicy) String() string {
	switch p {
	case ShadowDisabled:
		return "Disabled (No remote control allowed)"
	case ShadowFullNoPrompt:
		return "Full Control without user permission (Unprompted Full Access)"
	case ShadowFullWithPrompt:
		return "Full Control with user permission"
	case ShadowViewNoPrompt:
		return "View Session without user permission (Unprompted Screen Spy)"
	case ShadowViewWithPrompt:
		return "View Session with user permission"
	default:
		return "Unknown / Not Configured"
	}
}

// ShadowProbeResult details the shadowing policy exposure on the target RDP host.
type ShadowProbeResult struct {
	Policy       ShadowPolicy `json:"policy"`
	PolicyName   string       `json:"policy_name"`
	Unprompted   bool         `json:"unprompted"`
	RiskSeverity string       `json:"risk_severity"` // "critical", "high", "none"
	Evidence     string       `json:"evidence"`
}

// EvaluateShadowPosture inspects evidence flags, server core blocks, and GPO
// configuration signatures to assess whether the host allows unprompted session shadowing.
func EvaluateShadowPosture(svc *model.ServiceInfo) ShadowProbeResult {
	if svc == nil {
		return ShadowProbeResult{Policy: ShadowUnknown, PolicyName: ShadowUnknown.String()}
	}

	// 1. Check explicit evidence markers if populated by active probes
	if svc.Evidence != nil {
		if raw, ok := svc.Evidence["shadow_policy"]; ok {
			raw = strings.TrimSpace(raw)
			switch raw {
			case "1":
				return ShadowProbeResult{
					Policy:       ShadowFullNoPrompt,
					PolicyName:   ShadowFullNoPrompt.String(),
					Unprompted:   true,
					RiskSeverity: "critical",
					Evidence:     "GPO Shadow=1 (Full control without user permission)",
				}
			case "3":
				return ShadowProbeResult{
					Policy:       ShadowViewNoPrompt,
					PolicyName:   ShadowViewNoPrompt.String(),
					Unprompted:   true,
					RiskSeverity: "high",
					Evidence:     "GPO Shadow=3 (View session without user permission)",
				}
			case "2":
				return ShadowProbeResult{
					Policy:       ShadowFullWithPrompt,
					PolicyName:   ShadowFullWithPrompt.String(),
					Unprompted:   false,
					RiskSeverity: "none",
					Evidence:     "GPO Shadow=2 (Requires user consent)",
				}
			case "4":
				return ShadowProbeResult{
					Policy:       ShadowViewWithPrompt,
					PolicyName:   ShadowViewWithPrompt.String(),
					Unprompted:   false,
					RiskSeverity: "none",
					Evidence:     "GPO Shadow=4 (Requires user consent)",
				}
			case "0":
				return ShadowProbeResult{
					Policy:       ShadowDisabled,
					PolicyName:   ShadowDisabled.String(),
					Unprompted:   false,
					RiskSeverity: "none",
					Evidence:     "GPO Shadow=0 (Disabled)",
				}
			}
		}
	}

	// 2. Protocol heuristic: Older Windows Terminal Server builds (Server 2003/2008)
	// without NLA frequently default to unprompted remote control if shadowing is enabled.
	if !svc.NLARequired && svc.NegotiatedProtocol == ProtocolRDP {
		osLower := strings.ToLower(svc.OSGuess)
		if strings.Contains(osLower, "2003") || strings.Contains(osLower, "2008") {
			return ShadowProbeResult{
				Policy:       ShadowFullNoPrompt,
				PolicyName:   "Legacy Terminal Server Default Shadowing",
				Unprompted:   true,
				RiskSeverity: "high",
				Evidence:     fmt.Sprintf("Legacy %s without NLA defaults to unprompted remote control", svc.OSGuess),
			}
		}
	}

	return ShadowProbeResult{
		Policy:       ShadowUnknown,
		PolicyName:   ShadowUnknown.String(),
		Unprompted:   false,
		RiskSeverity: "none",
	}
}
