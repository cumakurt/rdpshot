package rdp

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"rdpshot/internal/model"
)

// TLSVersionName maps a TLS version identifier to its display name.
func TLSVersionName(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("unknown(0x%04x)", version)
}

// DescribeTLS fills the TLS related fields of a service description.
func DescribeTLS(svc *model.ServiceInfo, state *tls.ConnectionState) {
	if state == nil {
		return
	}
	svc.TLSVersion = TLSVersionName(state.Version)
	svc.TLSCipherSuite = tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		svc.Certificate = DescribeCertificate(state.PeerCertificates[0])
	}
}

// DescribeCertificate converts an x509 certificate into report metadata.
func DescribeCertificate(cert *x509.Certificate) *model.CertificateInfo {
	if cert == nil {
		return nil
	}
	sum := sha256.Sum256(cert.Raw)
	return &model.CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SelfSigned:   isSelfSigned(cert),
		Fingerprint:  hex.EncodeToString(sum[:]),
		DNSNames:     cert.DNSNames,
	}
}

// isSelfSigned reports whether the certificate vouches for itself. Both the
// subject/issuer match and the signature check must hold to avoid flagging
// cross-signed certificates.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}
