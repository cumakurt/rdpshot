package rdp

import (
	"encoding/binary"
	"unicode/utf16"
)

// Client Info Packet flags (MS-RDPBCGR 2.2.1.11.1.1).
const (
	infoMouse              uint32 = 0x00000001
	infoDisableCtrlAltDel  uint32 = 0x00000002
	infoAutoLogon          uint32 = 0x00000008
	infoUnicode            uint32 = 0x00000010
	infoMaximizeShell      uint32 = 0x00000020
	infoLogonNotify        uint32 = 0x00000040
	infoEnableWindowsKey   uint32 = 0x00000100
	infoLogonErrors        uint32 = 0x00010000
	infoMouseHasWheel      uint32 = 0x00020000
	infoForceEncryptedCSPDU uint32 = 0x00040000
	infoNoAudioPlayback    uint32 = 0x00080000
)

// buildClientInfoPDU builds the MCS user-data payload for the Client Info
// Packet with INFO_AUTOLOGON (MS-RDPBCGR 2.2.1.11). Used after CredSSP so the
// shell session can start; secrets stay on the wire only inside the TLS tunnel.
func buildClientInfoPDU(domain, user, password string) []byte {
	dom := utf16z(domain)
	usr := utf16z(user)
	pwd := utf16z(password)
	shell := utf16z("")
	dir := utf16z("")

	flags := infoMouse | infoDisableCtrlAltDel | infoAutoLogon | infoUnicode |
		infoMaximizeShell | infoEnableWindowsKey | infoLogonNotify | infoLogonErrors |
		infoMouseHasWheel | infoNoAudioPlayback

	body := make([]byte, 0, 64+len(dom)+len(usr)+len(pwd))
	body = binary.LittleEndian.AppendUint32(body, 0) // CodePage
	body = binary.LittleEndian.AppendUint32(body, flags)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(dom)-2)) // cbDomain excludes NUL
	body = binary.LittleEndian.AppendUint16(body, uint16(len(usr)-2))
	body = binary.LittleEndian.AppendUint16(body, uint16(len(pwd)-2))
	body = binary.LittleEndian.AppendUint16(body, uint16(len(shell)-2))
	body = binary.LittleEndian.AppendUint16(body, uint16(len(dir)-2))
	body = append(body, dom...)
	body = append(body, usr...)
	body = append(body, pwd...)
	body = append(body, shell...)
	body = append(body, dir...)

	// Extended info (RDP 5.0+): clientAddressFamily + cbClientAddress + address + …
	ext := make([]byte, 0, 128)
	ext = binary.LittleEndian.AppendUint16(ext, 2) // AF_INET
	addr := utf16z("127.0.0.1")
	ext = binary.LittleEndian.AppendUint16(ext, uint16(len(addr)))
	ext = append(ext, addr...)
	dirName := utf16z("C:\\")
	ext = binary.LittleEndian.AppendUint16(ext, uint16(len(dirName)))
	ext = append(ext, dirName...)
	ext = append(ext, make([]byte, 64)...)                          // clientTimeZone (SYSTEMTIME*2 + bias)
	ext = binary.LittleEndian.AppendUint32(ext, 0)                   // clientSessionId
	ext = binary.LittleEndian.AppendUint32(ext, 0)                   // performanceFlags
	ext = binary.LittleEndian.AppendUint16(ext, 0)                   // cbAutoReconnectCookie
	body = append(body, ext...)
	return body
}

func utf16z(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2*(len(u)+1))
	for i, r := range u {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}
