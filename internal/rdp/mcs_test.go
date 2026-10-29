package rdp

import (
	"encoding/hex"
	"testing"
)

func TestBuildGCCClientDataLayout(t *testing.T) {
	channels := []ChannelDef{{
		Name:    "MS_T120",
		Options: channelOptionInitialized | channelOptionCompressRDP,
		ID:      firstStaticChannelID,
	}}
	got := BuildGCCClientData(0x0000000B, channels)

	// Expected layout mirrors the wire format of common RDP clients:
	// T.124 ConferenceCreateRequest envelope, then the four client data blocks.
	prefix := "000500147c0001" + "8112" + "000800100001c000" + "44756361" + "8104"
	if hex.EncodeToString(got[:23]) != prefix {
		t.Fatalf("GCC envelope mismatch:\n got %s\nwant %s", hex.EncodeToString(got[:23]), prefix)
	}

	blocks := got[23:]
	core := blocks[:216]
	if hex.EncodeToString(core[:4]) != "01c0d800" {
		t.Fatalf("CS_CORE header mismatch: %s", hex.EncodeToString(core[:4]))
	}
	if hex.EncodeToString(core[4:8]) != "04000800" {
		t.Fatalf("CS_CORE version mismatch: %s", hex.EncodeToString(core[4:8]))
	}
	if hex.EncodeToString(core[212:216]) != "0b000000" {
		t.Fatalf("serverSelectedProtocol mismatch: %s", hex.EncodeToString(core[212:216]))
	}

	cluster := blocks[216:228]
	if hex.EncodeToString(cluster[:4]) != "04c00c00" {
		t.Fatalf("CS_CLUSTER header mismatch: %s", hex.EncodeToString(cluster[:4]))
	}
	security := blocks[228:240]
	if hex.EncodeToString(security[:4]) != "02c00c00" {
		t.Fatalf("CS_SECURITY header mismatch: %s", hex.EncodeToString(security[:4]))
	}
	network := blocks[240:]
	if hex.EncodeToString(network[:4]) != "03c01400" {
		t.Fatalf("CS_NET header mismatch: %s", hex.EncodeToString(network[:4]))
	}
	if hex.EncodeToString(network[8:16]) != "4d535f5431323000" {
		t.Fatalf("channel name mismatch: %s", hex.EncodeToString(network[8:16]))
	}
}

func TestBuildConnectInitialRoundTrip(t *testing.T) {
	gcc := BuildGCCClientData(RequestedProtocols(), nil)
	pdu := BuildConnectInitial(gcc)
	if pdu[0] != 0x7f || pdu[1] != 0x65 {
		t.Fatalf("connect initial tag mismatch: %x", pdu[:2])
	}
	content, rest, err := berReadHeader(pdu, mcsConnectInitial)
	if err != nil {
		t.Fatalf("parse connect initial: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after connect initial: %x", rest)
	}
	// calling + called + upward flag + 3 domain params + user data
	if _, content, err = berReadHeader(content, berTagOctetString); err != nil {
		t.Fatalf("calling selector: %v", err)
	}
	if _, content, err = berReadHeader(content, berTagOctetString); err != nil {
		t.Fatalf("called selector: %v", err)
	}
	if _, content, err = berReadHeader(content, berTagBoolean); err != nil {
		t.Fatalf("upward flag: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, content, err = berReadHeader(content, berTagDomainParams); err != nil {
			t.Fatalf("domain params %d: %v", i, err)
		}
	}
	userData, _, err := berReadHeader(content, berTagOctetString)
	if err != nil {
		t.Fatalf("user data: %v", err)
	}
	if hex.EncodeToString(userData) != hex.EncodeToString(gcc) {
		t.Fatal("user data mismatch after round trip")
	}
}

func sampleServerDataBlocks() []byte {
	// T.124 ConferenceCreateResponse envelope + PER length + SC_CORE/SC_NET/SC_SECURITY.
	out := make([]byte, 21)
	out = append(out, 0x81, 0x24) // PER length determinant

	core := make([]byte, 8)
	core[0], core[1] = 0x04, 0x00 // version 0x00080004
	core[2], core[3] = 0x08, 0x00
	out = appendBlock(out, scCore, core)

	netBody := make([]byte, 4+2*2)
	netBody[0], netBody[1] = 0xeb, 0x03 // MCSChannelId 1003
	netBody[2] = 2                      // channel count
	netBody[4], netBody[5] = 0xec, 0x03 // 1004
	netBody[6], netBody[7] = 0xed, 0x03 // 1005
	out = appendBlock(out, scNet, netBody)

	secBody := make([]byte, 8)
	secBody[0] = 0x02 // encryptionMethod 0x00000002 (128-bit RC4)
	secBody[4] = 0x03 // encryptionLevel 3 (high)
	out = appendBlock(out, scSecurity, secBody)
	return out
}

func TestParseServerDataBlocks(t *testing.T) {
	server, err := parseServerDataBlocks(sampleServerDataBlocks())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if server.Version != 0x00080004 {
		t.Fatalf("version = %#x", server.Version)
	}
	if server.MCSChannelID != 1003 {
		t.Fatalf("mcs channel id = %d", server.MCSChannelID)
	}
	if len(server.ChannelIDs) != 2 || server.ChannelIDs[0] != 1004 || server.ChannelIDs[1] != 1005 {
		t.Fatalf("channel ids = %v", server.ChannelIDs)
	}
	if server.EncryptionMethod != 2 || server.EncryptionLevel != 3 {
		t.Fatalf("encryption = %#x/%#x", server.EncryptionMethod, server.EncryptionLevel)
	}
}

func TestParseConnectResponse(t *testing.T) {
	userData := sampleServerDataBlocks()
	content := make([]byte, 0, len(userData)+64)
	content = berAppendHeader(content, berTagEnumerated, 1)
	content = append(content, 0x00)
	content = berAppendInteger(content, 1)
	content = berAppendDomainParams(content, 34, 2, 0, 0xffff)
	content = berAppendHeader(content, berTagOctetString, len(userData))
	content = append(content, userData...)
	pdu := berAppendHeader(nil, mcsConnectResponse, len(content))
	pdu = append(pdu, content...)

	server, err := ParseConnectResponse(pdu)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if server.Version != 0x00080004 {
		t.Fatalf("version = %#x", server.Version)
	}
}

func TestParseConnectResponseRejected(t *testing.T) {
	content := make([]byte, 0, 16)
	content = berAppendHeader(content, berTagEnumerated, 1)
	content = append(content, 0x02) // rejected
	pdu := berAppendHeader(nil, mcsConnectResponse, len(content))
	pdu = append(pdu, content...)
	if _, err := ParseConnectResponse(pdu); err == nil {
		t.Fatal("expected error for rejected connect response")
	}
}

func TestParseMCSPDUVariants(t *testing.T) {
	// Attach User Confirm with user id.
	pdu, err := ParseMCSPDU([]byte{0x2e, 0x00, 0x03, 0xea})
	if err != nil || pdu.Type != mcsAttachUserConfirm || pdu.UserID != 1002 {
		t.Fatalf("attach user confirm: %+v err=%v", pdu, err)
	}
	// Channel Join Confirm for channel 1004.
	pdu, err = ParseMCSPDU([]byte{0x3e, 0x00, 0x03, 0xea, 0x03, 0xec})
	if err != nil || pdu.Type != mcsChannelJoinConfirm || pdu.ChannelID != 1004 {
		t.Fatalf("channel join confirm: %+v err=%v", pdu, err)
	}
	// Disconnect Provider Ultimatum.
	pdu, err = ParseMCSPDU([]byte{0x20, 0x01})
	if err != nil || pdu.Type != mcsDisconnectProvider {
		t.Fatalf("disconnect provider: %+v err=%v", pdu, err)
	}
	// Send Data Indication with 2 byte length determinant.
	payload := buildSendDataRequest(1002, 1004, []byte{0xde, 0xad})
	payload[0] = mcsSendDataIndication << 2
	pdu, err = ParseMCSPDU(payload)
	if err != nil || pdu.Type != mcsSendDataIndication || pdu.ChannelID != 1004 {
		t.Fatalf("send data indication: %+v err=%v", pdu, err)
	}
	if len(pdu.Payload) != 2 || pdu.Payload[0] != 0xde {
		t.Fatalf("payload = %x", pdu.Payload)
	}
}

func TestParseMCSPDURejectsShortInput(t *testing.T) {
	for _, in := range [][]byte{nil, {0x2e}, {0x3e, 0x00}, {0x68, 0x00}} {
		if _, err := ParseMCSPDU(in); err == nil {
			t.Fatalf("expected error for %x", in)
		}
	}
}

func TestBerReadHeaderRejectsMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x04},                   // missing length
		{0x05, 0x01, 0x00},       // wrong tag
		{0x04, 0x82, 0x00},       // truncated length
		{0x04, 0x05, 0x01},       // content longer than buffer
		{0x04, 0x84, 0, 0, 0, 1}, // unsupported length octets
	}
	for i, in := range cases {
		if _, _, err := berReadHeader(in, berTagOctetString); err == nil {
			t.Fatalf("case %d: expected error for %x", i, in)
		}
	}
}

func TestMS_T120CheckPayloads(t *testing.T) {
	payloads := buildMS_T120CheckPayloads()
	if len(payloads) != 2 || len(payloads[0]) != 0x20 || len(payloads[1]) != 0x10 {
		t.Fatalf("unexpected check payloads: %x", payloads)
	}
	if payloads[0][8] != 2 || payloads[1][4] != 2 {
		t.Fatal("check payload markers missing")
	}
}
