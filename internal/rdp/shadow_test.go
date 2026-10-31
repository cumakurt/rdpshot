package rdp

import (
	"testing"

	"rdpshot/internal/model"
)

func TestEvaluateShadowPosture(t *testing.T) {
	cases := []struct {
		name           string
		svc            *model.ServiceInfo
		wantUnprompted bool
		wantRisk       string
	}{
		{
			name: "gpo shadow full unprompted",
			svc: &model.ServiceInfo{
				Evidence: map[string]string{"shadow_policy": "1"},
			},
			wantUnprompted: true,
			wantRisk:       "critical",
		},
		{
			name: "gpo shadow view unprompted",
			svc: &model.ServiceInfo{
				Evidence: map[string]string{"shadow_policy": "3"},
			},
			wantUnprompted: true,
			wantRisk:       "high",
		},
		{
			name: "gpo shadow safe prompted",
			svc: &model.ServiceInfo{
				Evidence: map[string]string{"shadow_policy": "2"},
			},
			wantUnprompted: false,
			wantRisk:       "none",
		},
		{
			name: "legacy windows 2003 no nla",
			svc: &model.ServiceInfo{
				NegotiatedProtocol: ProtocolRDP,
				NLARequired:        false,
				OSGuess:            "Windows Server 2003 R2",
			},
			wantUnprompted: true,
			wantRisk:       "high",
		},
		{
			name: "modern secure windows 11",
			svc: &model.ServiceInfo{
				NegotiatedProtocol: ProtocolHybrid,
				NLARequired:        true,
				OSGuess:            "Windows 11 Enterprise",
			},
			wantUnprompted: false,
			wantRisk:       "none",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := EvaluateShadowPosture(tc.svc)
			if res.Unprompted != tc.wantUnprompted {
				t.Fatalf("Unprompted = %v, want %v", res.Unprompted, tc.wantUnprompted)
			}
			if res.RiskSeverity != tc.wantRisk {
				t.Errorf("RiskSeverity = %q, want %q", res.RiskSeverity, tc.wantRisk)
			}
		})
	}
}
