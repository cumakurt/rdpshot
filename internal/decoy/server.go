// server.go implements the server-side CredSSP/NTLM handshake and (optional)
// full RDP MCS session for the decoy honeypot listener.
//
// Credential capture sequence:
//  1. Client sends TSRequest{negoTokens: SPNEGO(NTLM Type 1 Negotiate)}
//  2. Server replies TSRequest{negoTokens: SPNEGO(NTLM Type 2 Challenge)}  ← fake
//  3. Client sends TSRequest{negoTokens: SPNEGO(NTLM Type 3 Authenticate)}
//     → parse AuthenticateMessage to extract User, Domain, Workstation, NTHash
//  4. Server replies with error TSRequest{errorCode: 0xC000006D}  ← access denied
//
// The MCS/bitmap interactive mode (EnableFullHandshake=true) adds:
//  5. MCS Connect Initial / Response
//  6. Channel setup
//  7. License skip
//  8. Capability exchange
//  9. Fake Windows login screen bitmap
// 10. Read client input (username/password typed in fake screen)
package decoy

import (
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"strings"
	"time"

	"rdpshot/internal/ntlm"
)

// ─────────────────────────────────────────────────────────────────────────────
// CredSSP NTLM credential capture
// ─────────────────────────────────────────────────────────────────────────────

// captureCredSSP drives the server side of a CredSSP/NTLM handshake, populating
// ev with whatever credential material it can extract before disconnecting.
func captureCredSSP(conn net.Conn, serverDomain string, ev *DecoyEvent, log *slog.Logger) {
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	// ── Round 1: read client TSRequest with NTLM Type 1 ──────────────────────
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	data := buf[:n]

	// Try to parse as TSRequest to extract NTLM Type 1 from negoTokens.
	neg1 := extractNTLMToken(data)
	if len(neg1) > 0 {
		domain, ws, user, flags := parseNTLMNegotiateFull(neg1)
		ev.NTLMDomain = domain
		ev.NTLMWorkstation = ws
		ev.NTLMUsername = user
		ev.NTLMFlags = flags
		ev.Stage = "ntlm"
	} else {
		// Not a CredSSP TSRequest — maybe raw RDP; check for NTLM directly.
		domain, ws, user, flags := parseNTLMNegotiateFull(data)
		ev.NTLMDomain = domain
		ev.NTLMWorkstation = ws
		ev.NTLMUsername = user
		ev.NTLMFlags = flags
		if user != "" || domain != "" {
			ev.Stage = "ntlm"
		}
		return
	}

	// ── Round 2: send fake NTLM Type 2 Challenge ──────────────────────────────
	challenge := buildNTLMType2Challenge(serverDomain)
	spnegoChal := wrapInSPNEGO(challenge)
	tsChallenge := buildTSRequest(2, [][]byte{spnegoChal}, nil)
	if _, err := conn.Write(tsChallenge); err != nil {
		return
	}

	// ── Round 3: read client TSRequest with NTLM Type 3 Authenticate ─────────
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	n2, err := conn.Read(buf)
	if err != nil || n2 == 0 {
		return
	}
	data3 := buf[:n2]

	auth3Token := extractNTLMToken(data3)
	if len(auth3Token) < 64 {
		return
	}

	authMsg, err := ntlm.ParseAuthenticate(auth3Token)
	if err != nil {
		if log != nil {
			log.Debug("decoy: failed to parse NTLM Type 3", "err", err)
		}
		return
	}

	ev.CapturedUsername = authMsg.User
	ev.CapturedDomain = authMsg.Domain
	ev.NTLMWorkstation = authMsg.Workstation
	ev.FullAuthAttempt = true
	ev.Stage = "credssp_auth"

	// Extract NT response (first 16 bytes are the NT hash response for hash-cat).
	if len(authMsg.NTChallengeResponse) >= 24 {
		ev.NTHash = hex.EncodeToString(authMsg.NTChallengeResponse[:24])
	}

	// ── Round 4: send access-denied TSRequest to appear real ─────────────────
	// NTSTATUS 0xC000006D = STATUS_LOGON_FAILURE
	accessDenied := buildTSRequestError(0xC000006D)
	_, _ = conn.Write(accessDenied)
}

// ─────────────────────────────────────────────────────────────────────────────
// TSRequest helpers
// ─────────────────────────────────────────────────────────────────────────────

// extractNTLMToken searches buf for a TSRequest and extracts the first
// negoToken payload, then strips the SPNEGO wrapper to return the raw NTLM
// message bytes.
func extractNTLMToken(buf []byte) []byte {
	// Look for NTLMSSP signature directly — handles both wrapped and unwrapped cases.
	sig := []byte("NTLMSSP\x00")
	idx := bytes.Index(buf, sig)
	if idx >= 0 {
		return buf[idx:]
	}

	// Try to parse as TSRequest DER.
	var top asn1.RawValue
	rest := buf
	for len(rest) > 0 {
		var err error
		rest, err = asn1.Unmarshal(rest, &top)
		if err != nil {
			break
		}
		if top.Class == asn1.ClassUniversal && top.Tag == asn1.TagSequence {
			// Search within the DER structure for NTLMSSP.
			idx2 := bytes.Index(top.Bytes, sig)
			if idx2 >= 0 {
				return top.Bytes[idx2:]
			}
			// Recurse one level.
			idx3 := bytes.Index(top.FullBytes, sig)
			if idx3 >= 0 {
				return top.FullBytes[idx3:]
			}
		}
	}
	return nil
}

// buildNTLMType2Challenge builds a minimal NTLM Type 2 CHALLENGE_MESSAGE.
// The challenge bytes are random; we don't need to verify them.
func buildNTLMType2Challenge(targetName string) []byte {
	var serverChallenge [8]byte
	rand.Read(serverChallenge[:])

	// Encode target name as UTF-16LE.
	tn := utf16LEBytes(targetName)

	// Flags for a typical Windows Server NTLMv2 challenge.
	flags := ntlm.NEGOTIATE_UNICODE |
		ntlm.REQUEST_TARGET |
		ntlm.NEGOTIATE_NTLM |
		ntlm.NEGOTIATE_EXTENDED_SESSIONSECURITY |
		ntlm.NEGOTIATE_TARGET_TYPE_DOMAIN |
		ntlm.NEGOTIATE_TARGET_INFO |
		ntlm.NEGOTIATE_VERSION

	// Build minimal TargetInfo (MsvAvNbDomainName + MsvAvEOL).
	targetInfo := buildTargetInfo(targetName)

	// Version: Windows 10 / Server 2019 (10.0.17763).
	version := [8]byte{0x0a, 0x00, 0x3f, 0x0f, 0x00, 0x00, 0x00, 0x0f}

	ch := ntlm.ChallengeMessage{
		Flags:           flags,
		ServerChallenge: serverChallenge,
		TargetName:      encodeTargetName(tn, targetName, flags),
		TargetInfo:      targetInfo,
		Version:         &version,
	}
	b, err := ch.Marshal()
	if err != nil {
		// Fallback: minimal hardcoded challenge.
		b = buildMinimalChallenge(serverChallenge[:])
	}
	return b
}

// buildTargetInfo builds minimal MsvAv pairs for the challenge.
// MsvAvNbDomainName=1, MsvAvNbComputerName=2, MsvAvDnsDomainName=3, MsvAvEOL=0
func buildTargetInfo(domain string) []byte {
	var buf []byte
	domainUTF16 := utf16LEBytes(domain)
	// MsvAvNbDomainName
	buf = append(buf, avPairHeader(1, len(domainUTF16))...)
	buf = append(buf, domainUTF16...)
	// MsvAvNbComputerName
	computerUTF16 := utf16LEBytes("WIN-SERVER01")
	buf = append(buf, avPairHeader(2, len(computerUTF16))...)
	buf = append(buf, computerUTF16...)
	// MsvAvEOL
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	return buf
}

func avPairHeader(avID, avLen int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b[0:2], uint16(avID))
	binary.LittleEndian.PutUint16(b[2:4], uint16(avLen))
	return b
}

func encodeTargetName(utf16 []byte, ascii string, flags uint32) string {
	if flags&ntlm.NEGOTIATE_UNICODE != 0 {
		return string(utf16)
	}
	return ascii
}

// buildMinimalChallenge is an emergency fallback if ntlm.ChallengeMessage.Marshal() fails.
func buildMinimalChallenge(serverChallenge []byte) []byte {
	// NTLMSSP\0 + type(4) + TargetName fields(8) + flags(4) + challenge(8) + reserved(8) + targetInfo(8) = 56 bytes fixed header
	out := make([]byte, 56)
	copy(out[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(out[8:12], 2) // type 2
	// flags
	binary.LittleEndian.PutUint32(out[20:24], 0x00000201)
	// server challenge
	copy(out[24:32], serverChallenge[:8])
	return out
}

// buildTSRequest encodes a TSRequest DER with the given version and negoTokens.
func buildTSRequest(version int, negoTokens [][]byte, errorCode *uint32) []byte {
	// TSRequest ::= SEQUENCE {
	//   version    [0] INTEGER,
	//   negoTokens [1] NegoData OPTIONAL,
	//   errorCode  [4] INTEGER OPTIONAL }
	fields := make([]byte, 0, 256)

	// [0] version
	verDER, _ := asn1.Marshal(version)
	fields = append(fields, derExplicit(0, verDER)...)

	// [1] negoTokens
	if len(negoTokens) > 0 {
		var items []byte
		for _, tok := range negoTokens {
			tokDER, _ := asn1.Marshal(tok)
			itemSeq := asn1.RawValue{
				Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
				Bytes: derExplicit(0, tokDER),
			}
			itemDER, _ := asn1.Marshal(itemSeq)
			items = append(items, itemDER...)
		}
		listSeq := asn1.RawValue{
			Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
			Bytes: items,
		}
		listDER, _ := asn1.Marshal(listSeq)
		fields = append(fields, derExplicit(1, listDER)...)
	}

	// [4] errorCode
	if errorCode != nil {
		codeDER, _ := asn1.Marshal(int64(*errorCode))
		fields = append(fields, derExplicit(4, codeDER)...)
	}

	top := asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: fields,
	}
	out, _ := asn1.Marshal(top)
	return out
}

// buildTSRequestError builds a TSRequest carrying only an errorCode.
func buildTSRequestError(ntstatus uint32) []byte {
	return buildTSRequest(6, nil, &ntstatus)
}

// wrapInSPNEGO wraps an NTLM token in a minimal SPNEGO negTokenResp envelope.
// This is the same encoding used by Windows Server.
func wrapInSPNEGO(ntlmToken []byte) []byte {
	// negTokenResp ::= SEQUENCE { responseToken [2] OCTET STRING OPTIONAL }
	// OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
	tokenDER, _ := asn1.Marshal(ntlmToken)
	respToken := derExplicit(2, tokenDER)

	negTokenResp := asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: respToken,
	}
	respDER, _ := asn1.Marshal(negTokenResp)

	// [1] negTokenResp context
	negState := derExplicit(1, respDER)

	// SPNEGO OID wrapper: [APPLICATION 0] IMPLICIT SEQUENCE
	spnegoOID := []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02} // 1.3.6.1.5.5.2
	appSeq := asn1.RawValue{
		Class: asn1.ClassApplication, Tag: 0, IsCompound: true,
		Bytes: append(spnegoOID, negState...),
	}
	out, _ := asn1.Marshal(appSeq)
	return out
}

func derExplicit(tag int, inner []byte) []byte {
	return asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true,
		Bytes: inner,
	}.FullBytes
}

// ─────────────────────────────────────────────────────────────────────────────
// Full MCS/RDP interactive session (EnableFullHandshake mode)
// ─────────────────────────────────────────────────────────────────────────────

// runInteractiveSession drives the full RDP server handshake after CredSSP
// completes.  It sends a fake Windows login screen bitmap, waits for client
// input events, and records any typed credentials.
func runInteractiveSession(conn net.Conn, profile DecoyProfile, ev *DecoyEvent, log *slog.Logger) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)

	w := profile.DesktopWidth
	h := profile.DesktopHeight
	if w == 0 {
		w = 1024
	}
	if h == 0 {
		h = 768
	}

	// MCS Connect Initial / Response
	if err := doMCSHandshake(conn, br, w, h); err != nil {
		if log != nil {
			log.Debug("decoy: MCS handshake failed", "err", err)
		}
		return
	}
	ev.Stage = "mcs_active"

	// License skip
	licenseMsg := buildServerLicenseRequest()
	if err := writeDataTPDU(conn, buildSendDataIndication(1003, licenseMsg)); err != nil {
		return
	}

	// Capability exchange: Demand Active
	shareID := uint32(0x000103ea)
	demandActive := buildDemandActivePDU(shareID, 1003, w, h)
	if err := writeDataTPDU(conn, buildSendDataIndication(1003, demandActive)); err != nil {
		return
	}

	// Wait for client Confirm Active + synchronize sequence
	_ = drainClientSequence(br, 5)

	// Send server synchronize sequence
	src := uint16(1003)
	for _, pdu := range [][]byte{
		buildSynchronizePDU(shareID, src),
		buildControlGrantedPDU(shareID, src),
		buildFontMapPDU(shareID, src),
	} {
		if err := writeDataTPDU(conn, buildSendDataIndication(1003, pdu)); err != nil {
			return
		}
	}

	// Send fake login screen bitmap
	bgColor := parseHexColor(profile.WallpaperColor)
	if bgColor == nil {
		bgColor = &color.RGBA{R: 0x1a, G: 0x3a, B: 0x5c, A: 0xff}
	}
	bitmapPDU := buildFakeLoginScreenBitmap(shareID, src, int(w), int(h), bgColor, profile.LoginMessage, profile.HostName)
	if bitmapPDU != nil {
		if err := writeDataTPDU(conn, buildSendDataIndication(1003, bitmapPDU)); err != nil {
			return
		}
	}

	// Listen for client input (keyboard events) for up to 10 seconds.
	typed := readKeyboardInput(br, log)
	if typed != "" && ev.CapturedPassword == "" {
		ev.CapturedPassword = typed
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// MCS server PDU builders
// ─────────────────────────────────────────────────────────────────────────────

// doMCSHandshake completes the MCS Connect Initial / Response exchange
// and channel setup.
func doMCSHandshake(conn net.Conn, br *bufio.Reader, w, h uint16) error {
	// Read MCS Connect Initial.
	payload, err := readDataTPDU(br)
	if err != nil {
		return fmt.Errorf("mcs: read connect initial: %w", err)
	}
	_ = payload // we accept any valid connect initial

	// Send MCS Connect Response.
	resp := buildConnectResponse(w, h)
	if err := writeDataTPDU(conn, resp); err != nil {
		return fmt.Errorf("mcs: write connect response: %w", err)
	}

	// Read Erect Domain.
	if _, err := readDataTPDU(br); err != nil {
		return nil // tolerate missing erect domain
	}
	// Read Attach User Request.
	if _, err := readDataTPDU(br); err != nil {
		return nil
	}
	// Send Attach User Confirm (assign userID=1007).
	attachConfirm := buildAttachUserConfirm(0, 1007-1001)
	if err := writeDataTPDU(conn, attachConfirm); err != nil {
		return err
	}

	// Read and confirm channel joins for up to 5 channels.
	for i := 0; i < 5; i++ {
		pdu, err := readDataTPDU(br)
		if err != nil {
			break
		}
		mcs, err := parseMCSPDUMinimal(pdu)
		if err != nil || mcs.pduType != 14 { // mcsChannelJoinRequest
			break
		}
		confirm := buildChannelJoinConfirm(0, mcs.userID, mcs.channelID)
		if err := writeDataTPDU(conn, confirm); err != nil {
			break
		}
	}
	return nil
}

// buildConnectResponse builds a minimal MCS Connect Response.
func buildConnectResponse(w, h uint16) []byte {
	// Server GCC data: core + security + net blocks.
	core := buildServerCoreData()
	security := buildServerSecurityData()
	net := buildServerNetData()
	blocks := append(append(core, security...), net...)

	// T.124 ConferenceCreateResponse envelope (fixed 21-byte prefix).
	ccResp := []byte{
		0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01,
	}
	ccResp = binary.BigEndian.AppendUint16(ccResp, uint16(len(blocks)+14)|0x8000)
	ccResp = append(ccResp, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00)
	ccResp = append(ccResp, []byte("McDn")...)
	ccResp = binary.BigEndian.AppendUint16(ccResp, uint16(len(blocks))|0x8000)
	ccResp = append(ccResp, blocks...)

	// Wrap in BER MCS Connect Response.
	content := make([]byte, 0, 64+len(ccResp))
	content = berAppendHeader(content, 0x30, 3) // result
	content = append(content, 0x0a, 0x01, 0x00) // success
	content = berAppendHeader(content, 0x30, 3) // called domain
	content = append(content, 0x02, 0x01, 0x00)
	content = berAppendHeader(content, 0x02, 1) // connect id
	content = append(content, 0x00)
	content = berAppendHeader(content, 0x04, len(ccResp))
	content = append(content, ccResp...)
	out := berAppendHeader(nil, 0x7f66, len(content))
	return append(out, content...)
}

func buildServerCoreData() []byte {
	body := make([]byte, 0, 12)
	body = binary.LittleEndian.AppendUint32(body, 0x00080008) // RDP 8.0
	body = binary.LittleEndian.AppendUint32(body, 0x00000003) // clientRequestedProtocols echo (HYBRID)
	body = binary.LittleEndian.AppendUint32(body, 0x00000000) // earlyCapabilityFlags
	return appendServerBlock(nil, 0x0C00, body)               // scCore
}

func buildServerSecurityData() []byte {
	body := make([]byte, 8)
	// EncryptionMethod=0 (no encryption for NLA), EncryptionLevel=0
	return appendServerBlock(nil, 0x0C02, body)
}

func buildServerNetData() []byte {
	// MCSChannelID=1003, 4 static channels: 1004,1005,1006,1007
	body := make([]byte, 0, 12)
	body = binary.LittleEndian.AppendUint16(body, 1003) // MCSChannelID
	body = binary.LittleEndian.AppendUint16(body, 4)    // channelCount
	for _, id := range []uint16{1004, 1005, 1006, 1007} {
		body = binary.LittleEndian.AppendUint16(body, id)
	}
	return appendServerBlock(nil, 0x0C01, body)
}

func appendServerBlock(dst []byte, blockType uint16, body []byte) []byte {
	blockLen := uint16(4 + len(body))
	dst = binary.LittleEndian.AppendUint16(dst, blockType)
	dst = binary.LittleEndian.AppendUint16(dst, blockLen)
	return append(dst, body...)
}

// buildAttachUserConfirm builds an MCS Attach User Confirm PDU.
// result=0 success; userID is relative (userID + MCSUserChannelBase).
func buildAttachUserConfirm(result byte, relativeUserID uint16) []byte {
	// mcsAttachUserConfirm=11, bit 0x02 set means userID is included
	out := []byte{(11 << 2) | 0x02, result}
	return binary.BigEndian.AppendUint16(out, relativeUserID)
}

// buildChannelJoinConfirm builds an MCS Channel Join Confirm PDU.
func buildChannelJoinConfirm(result byte, userID, channelID uint16) []byte {
	// mcsChannelJoinConfirm=15
	out := []byte{15 << 2, result}
	out = binary.BigEndian.AppendUint16(out, userID)
	out = binary.BigEndian.AppendUint16(out, channelID)
	return binary.BigEndian.AppendUint16(out, channelID)
}

// buildSendDataIndication builds MCS Send Data Indication (server→client).
func buildSendDataIndication(channelID uint16, payload []byte) []byte {
	userID := uint16(1003) // server user id
	out := []byte{26 << 2} // mcsSendDataIndication
	out = binary.BigEndian.AppendUint16(out, userID)
	out = binary.BigEndian.AppendUint16(out, channelID)
	out = append(out, 0x70) // priority+segmentation
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload))|0x8000)
	return append(out, payload...)
}

// buildServerLicenseRequest builds a Server License Request PDU that the
// client should respond to with a No-License error, effectively skipping
// licensing.
func buildServerLicenseRequest() []byte {
	// Use the same "valid client" error but from server direction.
	// Windows server sends an actual license request; many clients respond with
	// the valid_client error. For simplicity, we send the valid_client message
	// ourselves so the client skips the entire licensing phase.
	out := []byte{0xFF, 0x03}                          // licenseErrorAlert + version 3
	out = binary.LittleEndian.AppendUint16(out, 16)    // wMsgSize
	out = binary.LittleEndian.AppendUint32(out, 7)     // STATUS_VALID_CLIENT
	out = binary.LittleEndian.AppendUint32(out, 2)     // ST_NO_TRANSITION
	out = binary.LittleEndian.AppendUint32(out, 0)     // bbErrorInfo (empty)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Demand Active PDU (server capabilities)
// ─────────────────────────────────────────────────────────────────────────────

func buildDemandActivePDU(shareID uint32, source uint16, w, h uint16) []byte {
	// Build the same capability sets as buildConfirmActivePDU but for server→client.
	// We advertise minimal capabilities to keep the client in a basic bitmap mode.
	caps := buildServerCapabilitySets(w, h)
	sourceDesc := []byte("rdpshot\x00")

	numberCaps := uint16(4)
	combinedLen := uint16(4 + len(caps))

	body := make([]byte, 0, 32+len(sourceDesc)+len(caps))
	body = binary.LittleEndian.AppendUint32(body, shareID)
	body = binary.LittleEndian.AppendUint16(body, uint16(len(sourceDesc)))
	body = binary.LittleEndian.AppendUint16(body, combinedLen)
	body = append(body, sourceDesc...)
	body = binary.LittleEndian.AppendUint16(body, numberCaps)
	body = binary.LittleEndian.AppendUint16(body, 0) // pad
	body = append(body, caps...)

	total := uint16(6 + len(body))
	header := shareControlHeaderServer(total, 1, source) // pduTypeDemandActive=1
	return append(header, body...)
}

func buildServerCapabilitySets(w, h uint16) []byte {
	var caps []byte
	// General
	genBody := make([]byte, 20)
	binary.LittleEndian.PutUint16(genBody[0:2], 1)      // osMajorType = Windows
	binary.LittleEndian.PutUint16(genBody[2:4], 3)      // osMinorType = NT
	binary.LittleEndian.PutUint16(genBody[4:6], 0x0200) // protocolVersion
	binary.LittleEndian.PutUint16(genBody[10:12], 0x0401)
	caps = appendCapSet(caps, 0x0001, genBody) // capGeneral

	// Bitmap
	bmpBody := make([]byte, 24)
	binary.LittleEndian.PutUint16(bmpBody[0:2], 24) // preferredBitsPerPixel
	binary.LittleEndian.PutUint16(bmpBody[2:4], 1)
	binary.LittleEndian.PutUint16(bmpBody[4:6], 1)
	binary.LittleEndian.PutUint16(bmpBody[6:8], 1)
	binary.LittleEndian.PutUint16(bmpBody[8:10], w)
	binary.LittleEndian.PutUint16(bmpBody[10:12], h)
	caps = appendCapSet(caps, 0x0002, bmpBody)

	// Order
	ordBody := make([]byte, 88)
	binary.LittleEndian.PutUint16(ordBody[4:6], 1) // desktopSaveSize
	caps = appendCapSet(caps, 0x0003, ordBody)

	// Input
	inpBody := make([]byte, 88)
	binary.LittleEndian.PutUint16(inpBody[0:2], 0x0001) // INPUT_FLAG_SCANCODES
	caps = appendCapSet(caps, 0x000D, inpBody)

	return caps
}

func appendCapSet(dst []byte, capType uint16, body []byte) []byte {
	dst = binary.LittleEndian.AppendUint16(dst, capType)
	dst = binary.LittleEndian.AppendUint16(dst, uint16(4+len(body)))
	return append(dst, body...)
}

func shareControlHeaderServer(totalLen, pduType uint16, source uint16) []byte {
	out := make([]byte, 6)
	binary.LittleEndian.PutUint16(out[0:2], totalLen)
	binary.LittleEndian.PutUint16(out[2:4], pduType|0x10) // version 1
	binary.LittleEndian.PutUint16(out[4:6], source)
	return out
}

// buildControlGrantedPDU sends the Control Granted (action=2) PDU.
func buildControlGrantedPDU(shareID uint32, source uint16) []byte {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], 2) // CTRLACTION_GRANTED_CONTROL
	binary.LittleEndian.PutUint16(payload[2:4], source)
	binary.LittleEndian.PutUint32(payload[4:8], 0)
	return buildShareDataPDU2(shareID, source, 0x14, payload) // pduType2Control
}

// buildFontMapPDU sends the Font Map PDU to signal session activation.
func buildFontMapPDU(shareID uint32, source uint16) []byte {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], 0)
	binary.LittleEndian.PutUint16(payload[2:4], 0)
	binary.LittleEndian.PutUint16(payload[4:6], 3)      // FONTLIST_FIRST | FONTLIST_LAST
	binary.LittleEndian.PutUint16(payload[6:8], 0x0032) // entrySize
	return buildShareDataPDU2(shareID, source, 0x28, payload) // pduType2FontMap
}

// buildShareDataPDU2 wraps payload in Share Control Header + Share Data Header.
func buildShareDataPDU2(shareID uint32, source uint16, pduType2 byte, payload []byte) []byte {
	// Share Data header (12 bytes) prepended to payload.
	dataHeader := make([]byte, 12)
	binary.LittleEndian.PutUint32(dataHeader[0:4], shareID)
	dataHeader[4] = 0    // pad1Octet
	dataHeader[5] = pduType2
	dataHeader[6] = 0    // compressionType
	dataHeader[7] = 0    // compressedType
	binary.LittleEndian.PutUint16(dataHeader[8:10], 0)
	binary.LittleEndian.PutUint16(dataHeader[10:12], uint16(len(payload)))

	body := append(dataHeader, payload...)
	total := uint16(6 + len(body))
	header := shareControlHeaderServer(total, 7, source) // pduTypeData=7
	return append(header, body...)
}

// buildSynchronizePDU is re-exported here for the interactive session.
func buildSynchronizePDU(shareID uint32, source uint16) []byte {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint16(payload[0:2], 1) // SYNCMSGTYPE_SYNC
	binary.LittleEndian.PutUint16(payload[2:4], source)
	return buildShareDataPDU2(shareID, source, 0x1F, payload) // pduType2Sync
}

// ─────────────────────────────────────────────────────────────────────────────
// Fake login screen bitmap
// ─────────────────────────────────────────────────────────────────────────────

// buildFakeLoginScreenBitmap renders a simple fake Windows login screen using
// the Go image library and encodes it as a Bitmap Update PDU.
func buildFakeLoginScreenBitmap(shareID uint32, source uint16, w, h int, bg *color.RGBA, message, hostname string) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))

	// Fill background.
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, *bg)
		}
	}

	// Draw a centered white rectangle as a "login box" (simple visual cue).
	boxW, boxH := 400, 280
	boxX, boxY := (w-boxW)/2, (h-boxH)/2
	white := color.RGBA{R: 0xf5, G: 0xf5, B: 0xf5, A: 0xff}
	shadow := color.RGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x40}
	for y := boxY + 4; y < boxY+boxH+4; y++ {
		for x := boxX + 4; x < boxX+boxW+4; x++ {
			img.SetRGBA(x, y, shadow)
		}
	}
	for y := boxY; y < boxY+boxH; y++ {
		for x := boxX; x < boxX+boxW; x++ {
			img.SetRGBA(x, y, white)
		}
	}

	// Encode as PNG and put it in a Bitmap Update PDU.
	// Real RDP clients expect raw RGB/RLE but for our purposes we use PNG
	// and wrap it as an opaque "compressed" bitmap. Many RDP clients will
	// display the box outline even if they can't decompress.
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		return nil
	}
	pngBytes := pngBuf.Bytes()

	// Build Bitmap Update PDU payload (pduType2Update with updateTypeBitmap).
	// One rectangle covering the entire desktop.
	rectPayload := make([]byte, 0, 32+len(pngBytes))
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, 1) // updateTypeBitmap
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, 1) // numberRectangles

	// BITMAP_DATA header.
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, 0)         // destLeft
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, 0)         // destTop
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, uint16(w)) // destRight
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, uint16(h)) // destBottom
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, uint16(w)) // width
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, uint16(h)) // height
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, 24)        // bitsPerPixel
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, 0x0001)    // flags: BITMAP_COMPRESSION
	rectPayload = binary.LittleEndian.AppendUint16(rectPayload, uint16(len(pngBytes)))
	rectPayload = append(rectPayload, pngBytes...)

	return buildShareDataPDU2(shareID, source, 0x02, rectPayload) // pduType2Update
}

// ─────────────────────────────────────────────────────────────────────────────
// Client input reader (keyboard scancode → typed text)
// ─────────────────────────────────────────────────────────────────────────────

// readKeyboardInput reads RDP input PDUs for up to 8 seconds and reconstructs
// typed text from keyboard scancode events.  This is best-effort: it only
// captures ASCII printable characters; VK_RETURN terminates the read.
func readKeyboardInput(br *bufio.Reader, log *slog.Logger) string {
	var typed []byte
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		// Read a TPKT + X.224 DT frame.
		pdu, err := readDataTPDU(br)
		if err != nil {
			break
		}
		// Fast-path input: first byte & 0x03 == 1 (FP_INPUT_EVENT)
		if len(pdu) > 0 && (pdu[0]&0x03) == 1 {
			typed = append(typed, parseFPKeyscan(pdu)...)
			if len(typed) > 0 && typed[len(typed)-1] == '\n' {
				break
			}
			continue
		}
		// Slow-path input PDU.
		mcs, err := parseMCSPDUMinimal(pdu)
		if err != nil || len(mcs.payload) == 0 {
			continue
		}
		typed = append(typed, parseSlowPathKeys(mcs.payload)...)
	}
	return string(typed)
}

// parseFPKeyscan extracts printable characters from a Fast-Path input PDU.
func parseFPKeyscan(data []byte) []byte {
	// Fast-Path input: header(1) + length(1-2) + events
	// Each event: eventHeader(1) + eventData
	// Keyboard event: eventHeader & 0xE0 == 0x00
	var result []byte
	offset := 1
	if offset >= len(data) {
		return nil
	}
	length := int(data[offset])
	offset++
	if length&0x80 != 0 && offset < len(data) {
		length = (length&0x7f)<<8 | int(data[offset])
		offset++
	}
	for offset+1 < len(data) {
		eventHeader := data[offset]
		offset++
		eventType := (eventHeader >> 5) & 0x03
		if eventType == 0 { // keyboard
			if offset >= len(data) {
				break
			}
			scancode := data[offset]
			offset++
			if eventHeader&0x08 == 0 { // key down
				if ch := scancodeToASCII(scancode); ch != 0 {
					result = append(result, ch)
				}
			}
		} else {
			// Skip other event types (2 bytes each typically)
			offset += 2
		}
	}
	return result
}

// parseSlowPathKeys extracts printable characters from a slow-path input PDU.
func parseSlowPathKeys(data []byte) []byte {
	// Share Data Header (12 bytes) + Input PDU Payload.
	if len(data) < 14 {
		return nil
	}
	// pduType2 at offset 5
	if data[5] != 0x1C { // pduType2Input = 0x1C
		return nil
	}
	// Input PDU: numEvents(2) + pad(2) + events[]
	if len(data) < 16 {
		return nil
	}
	numEvents := int(binary.LittleEndian.Uint16(data[12:14]))
	offset := 16
	var result []byte
	for i := 0; i < numEvents && offset+8 <= len(data); i++ {
		// RDP_INPUT_EVENT: eventTime(4) + messageType(2) + eventFlags(2) + eventData(varies)
		msgType := binary.LittleEndian.Uint16(data[offset+4 : offset+6])
		flags := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		if msgType == 0x0004 && (flags&0x8000 == 0) && offset+10 <= len(data) { // RDP_INPUT_EVENT_SCANCODE, key down
			scancode := byte(data[offset+8])
			if ch := scancodeToASCII(scancode); ch != 0 {
				result = append(result, ch)
			}
		}
		offset += 8 + 2 // eventTime(4)+msgType(2)+flags(2)+scancode(2)
	}
	return result
}

// scancodeToASCII converts common US-keyboard scan codes to ASCII printable chars.
var scancodeMap = map[byte]byte{
	0x02: '1', 0x03: '2', 0x04: '3', 0x05: '4', 0x06: '5',
	0x07: '6', 0x08: '7', 0x09: '8', 0x0a: '9', 0x0b: '0',
	0x10: 'q', 0x11: 'w', 0x12: 'e', 0x13: 'r', 0x14: 't',
	0x15: 'y', 0x16: 'u', 0x17: 'i', 0x18: 'o', 0x19: 'p',
	0x1e: 'a', 0x1f: 's', 0x20: 'd', 0x21: 'f', 0x22: 'g',
	0x23: 'h', 0x24: 'j', 0x25: 'k', 0x26: 'l',
	0x2c: 'z', 0x2d: 'x', 0x2e: 'c', 0x2f: 'v', 0x30: 'b',
	0x31: 'n', 0x32: 'm', 0x39: ' ', 0x1c: '\n',
}

func scancodeToASCII(sc byte) byte {
	return scancodeMap[sc]
}

// ─────────────────────────────────────────────────────────────────────────────
// Minimal helpers
// ─────────────────────────────────────────────────────────────────────────────

type minimalMCS struct {
	pduType   byte
	userID    uint16
	channelID uint16
	payload   []byte
}

func parseMCSPDUMinimal(data []byte) (minimalMCS, error) {
	var m minimalMCS
	if len(data) < 1 {
		return m, fmt.Errorf("empty")
	}
	m.pduType = data[0] >> 2
	switch m.pduType {
	case 14: // channelJoinRequest
		if len(data) >= 5 {
			m.userID = binary.BigEndian.Uint16(data[1:3])
			m.channelID = binary.BigEndian.Uint16(data[3:5])
		}
	case 25, 26: // sendData
		if len(data) >= 7 {
			m.userID = binary.BigEndian.Uint16(data[1:3])
			m.channelID = binary.BigEndian.Uint16(data[3:5])
			length := int(data[6])
			offset := 7
			if length&0x80 != 0 && len(data) >= 8 {
				length = (length&0x7f)<<8 | int(data[7])
				offset = 8
			}
			if len(data) >= offset+length {
				m.payload = data[offset : offset+length]
			}
		}
	}
	return m, nil
}

// drainClientSequence reads and discards up to n PDUs (e.g. Confirm Active +
// Sync + Control + Font List from the client).
func drainClientSequence(br *bufio.Reader, n int) int {
	read := 0
	for i := 0; i < n; i++ {
		if _, err := readDataTPDU(br); err != nil {
			break
		}
		read++
	}
	return read
}

// writeDataTPDU writes payload wrapped in an X.224 DT TPDU inside a TPKT frame.
func writeDataTPDU(w io.Writer, payload []byte) error {
	frame := make([]byte, 0, 3+len(payload))
	frame = append(frame, 0x02, 0xF0, 0x80) // X.224 DT TPDU: LI=2, DT, EOT
	frame = append(frame, payload...)
	return writeTPKT(w, frame)
}

// readDataTPDU reads one X.224 DT TPDU from br.
func readDataTPDU(br *bufio.Reader) ([]byte, error) {
	frame, err := readTPKT(br)
	if err != nil {
		return nil, err
	}
	if len(frame) < 3 {
		return nil, fmt.Errorf("x224: short frame")
	}
	return frame[3:], nil
}

func writeTPKT(w io.Writer, payload []byte) error {
	total := 4 + len(payload)
	header := make([]byte, 4)
	header[0] = 3
	header[1] = 0
	binary.BigEndian.PutUint16(header[2:4], uint16(total))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readTPKT(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if header[0] != 3 {
		return nil, fmt.Errorf("not TPKT")
	}
	total := int(binary.BigEndian.Uint16(header[2:4]))
	if total < 4 || total > 32768 {
		return nil, fmt.Errorf("tpkt length %d out of range", total)
	}
	payload := make([]byte, total-4)
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return payload, nil
}

// berAppendHeader appends a BER TLV header (tag + length) to dst.
func berAppendHeader(dst []byte, tag, length int) []byte {
	if tag > 0xff {
		dst = append(dst, byte(tag>>8), byte(tag))
	} else {
		dst = append(dst, byte(tag))
	}
	if length < 0x80 {
		dst = append(dst, byte(length))
	} else if length < 0x100 {
		dst = append(dst, 0x81, byte(length))
	} else {
		dst = append(dst, 0x82, byte(length>>8), byte(length))
	}
	return dst
}

// utf16LEBytes encodes a string as UTF-16 LE.
func utf16LEBytes(s string) []byte {
	b := make([]byte, len(s)*2)
	for i, r := range s {
		binary.LittleEndian.PutUint16(b[i*2:], uint16(r))
	}
	return b
}

// parseHexColor parses "#rrggbb" into *color.RGBA. Returns nil on error.
func parseHexColor(s string) *color.RGBA {
	s = strings.TrimPrefix(s, "#")
	if len(s) != 6 {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) < 3 {
		return nil
	}
	return &color.RGBA{R: b[0], G: b[1], B: b[2], A: 0xff}
}
