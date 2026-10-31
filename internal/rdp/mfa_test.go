package rdp

import (
	"testing"

	"rdpshot/internal/model"
)

func TestDetectMFAPAMSmartCard(t *testing.T) {
	svc := &model.ServiceInfo{
		SmartCardRequired: true,
	}
	det := DetectMFAPAM(svc)
	if !det.MFAEnforced || det.Provider != LayerSmartCard {
		t.Fatalf("expected smart card MFA, got %+v", det)
	}
}

func TestDetectMFAPAMCyberArkCert(t *testing.T) {
	svc := &model.ServiceInfo{
		Certificate: &model.CertificateInfo{
			Subject: "CN=PSM-Gateway.cyberark.local, O=CyberArk",
			Issuer:  "CN=CyberArk Root CA",
		},
	}
	det := DetectMFAPAM(svc)
	if !det.MFAEnforced || !det.PAMProxyDetected || det.Provider != LayerCyberArkPSM {
		t.Fatalf("expected CyberArk PSM, got %+v", det)
	}
}

func TestDetectMFAPAMDuoOCR(t *testing.T) {
	svc := &model.ServiceInfo{
		LoginUsers: []string{"Duo Security 2FA", "Administrator"},
	}
	det := DetectMFAPAM(svc)
	if !det.MFAEnforced || det.Provider != LayerDuoMFA {
		t.Fatalf("expected Duo MFA, got %+v", det)
	}
}

func TestDetectMFAPAMEntraIDCert(t *testing.T) {
	svc := &model.ServiceInfo{
		Certificate: &model.CertificateInfo{
			Subject: "CN=aad-device-1234.corp",
			Issuer:  "CN=Microsoft Azure RSA TLS Issuing CA",
		},
	}
	det := DetectMFAPAM(svc)
	if !det.MFAEnforced || det.Provider != LayerEntraID {
		t.Fatalf("expected Entra ID, got %+v", det)
	}
}
