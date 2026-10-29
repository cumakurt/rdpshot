package rdp

import "encoding/binary"

// License message types (MS-RDPBCGR 2.2.1.12).
const (
	licenseRequest            byte = 0x01
	licensePlatformChallenge  byte = 0x02
	licenseNewLicense         byte = 0x03
	licenseUpgradeLicense     byte = 0x04
	licenseInfo               byte = 0x12
	licenseNewLicenseRequest  byte = 0x13
	licenseChallengeResp      byte = 0x15
	licenseErrorAlert         byte = 0xFF
)

const (
	licenseErrValidClient     uint32 = 0x00000007
	licenseStateNoTransition  uint32 = 0x00000002
	licensePreambleVersion30  byte   = 0x03
)

// buildLicenseErrorValidClient builds a LICENSE_ERROR_MESSAGE claiming the
// client already has a valid license (STATUS_VALID_CLIENT), which is the
// usual way open-source clients complete the licensing phase.
func buildLicenseErrorValidClient() []byte {
	out := make([]byte, 0, 16)
	out = append(out, licenseErrorAlert, licensePreambleVersion30)
	out = binary.LittleEndian.AppendUint16(out, 16) // wMsgSize including preamble
	out = binary.LittleEndian.AppendUint32(out, licenseErrValidClient)
	out = binary.LittleEndian.AppendUint32(out, licenseStateNoTransition)
	out = binary.LittleEndian.AppendUint32(out, 0) // bbErrorInfo (empty BLOB)
	return out
}

func isLicensePDU(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	switch payload[0] {
	case licenseRequest, licensePlatformChallenge, licenseNewLicense,
		licenseUpgradeLicense, licenseInfo, licenseErrorAlert:
		return true
	}
	return false
}
