package credssp

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// CCache represents a parsed MIT Kerberos Credentials Cache (version 4).
type CCache struct {
	Version          uint16
	DefaultPrincipal Principal
	Credentials      []CredentialEntry
}

// Principal represents a Kerberos principal (e.g. user@REALM or termsrv/host@REALM).
type Principal struct {
	NameType   uint32
	Realm      string
	Components []string
}

// String returns the formatted principal name.
func (p Principal) String() string {
	if len(p.Components) == 0 {
		return p.Realm
	}
	s := strings.Join(p.Components, "/")
	if p.Realm != "" {
		s += "@" + p.Realm
	}
	return s
}

// CredentialEntry is one cached Kerberos ticket and associated session key.
type CredentialEntry struct {
	Client    Principal
	Server    Principal
	KeyType   uint16
	KeyData   []byte
	AuthTime  time.Time
	StartTime time.Time
	EndTime   time.Time
	RenewTill time.Time
	Flags     uint32
	Ticket    []byte
}

// IsExpired reports whether the ticket has passed its end validity time.
func (c *CredentialEntry) IsExpired() bool {
	if c.EndTime.IsZero() {
		return false
	}
	return time.Now().After(c.EndTime)
}

// ReadCCache parses a binary MIT Kerberos Credentials Cache.
func ReadCCache(r io.Reader) (*CCache, error) {
	var ver uint16
	if err := binary.Read(r, binary.BigEndian, &ver); err != nil {
		return nil, fmt.Errorf("credssp: read ccache version: %w", err)
	}
	if ver != 0x0504 && ver != 0x0503 {
		return nil, fmt.Errorf("credssp: unsupported ccache version 0x%04x (want 0x0504 or 0x0503)", ver)
	}

	cc := &CCache{Version: ver}

	if ver == 0x0504 {
		var headerLen uint16
		if err := binary.Read(r, binary.BigEndian, &headerLen); err != nil {
			return nil, fmt.Errorf("credssp: read header len: %w", err)
		}
		headerBytes := make([]byte, headerLen)
		if _, err := io.ReadFull(r, headerBytes); err != nil {
			return nil, fmt.Errorf("credssp: read header tags: %w", err)
		}
	}

	defPrinc, err := readPrincipal(r)
	if err != nil {
		return nil, fmt.Errorf("credssp: read default principal: %w", err)
	}
	cc.DefaultPrincipal = defPrinc

	for {
		entry, err := readCredentialEntry(r)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("credssp: read credential entry: %w", err)
		}
		cc.Credentials = append(cc.Credentials, entry)
	}

	return cc, nil
}

// LoadCCacheFile reads a CCache from the filesystem.
func LoadCCacheFile(filePath string) (*CCache, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open ccache file: %w", err)
	}
	defer f.Close()
	return ReadCCache(f)
}

// FindTicket searches for a ticket matching the target server service name or krbtgt.
func (cc *CCache) FindTicket(targetHost string) (*CredentialEntry, error) {
	targetLower := strings.ToLower(targetHost)
	var fallback *CredentialEntry

	for i := range cc.Credentials {
		cred := &cc.Credentials[i]
		srv := strings.ToLower(cred.Server.String())

		// Look for termsrv/targetHost
		if strings.HasPrefix(srv, "termsrv/") && (strings.Contains(srv, targetLower) || targetLower == "") {
			if !cred.IsExpired() {
				return cred, nil
			}
		}
		// Or host/targetHost
		if strings.HasPrefix(srv, "host/") && strings.Contains(srv, targetLower) {
			if !cred.IsExpired() {
				return cred, nil
			}
		}
		// Fallback to any valid ticket in cache (e.g. krbtgt)
		if !cred.IsExpired() && fallback == nil {
			fallback = cred
		}
	}

	if fallback != nil {
		return fallback, nil
	}
	if len(cc.Credentials) > 0 {
		return &cc.Credentials[0], nil
	}
	return nil, fmt.Errorf("credssp: no tickets found in ccache")
}

// BuildKerberosAPReqWrap constructs a GSS-API / SPNEGO wrapped Kerberos ticket token.
func BuildKerberosAPReqWrap(ticketBytes []byte) ([]byte, error) {
	if len(ticketBytes) == 0 {
		return nil, fmt.Errorf("credssp: empty ticket bytes")
	}

	// In GSS-API Kerberos v5 (RFC 1964 / RFC 4121):
	// TokID = 0x0001 (KRB_AP_REQ)
	// Framing: GSS-API OID 1.2.840.113554.1.2.2 + 0x00, 0x01 + raw AP-REQ or Ticket
	tokHeader := []byte{0x00, 0x01}
	payload := append(tokHeader, ticketBytes...)

	mechBytes, err := asn1.Marshal(kerberosMechOID)
	if err != nil {
		return nil, err
	}

	content := append(mechBytes, payload...)
	// Application 0 GSS wrapper: 0x60 <len> <content>
	wrapped := wrapApplication0(content)

	// Wrap in SPNEGO NegTokenInit
	return WrapKerberosNegTokenInit(wrapped)
}

// WrapKerberosNegTokenInit wraps a Kerberos GSS token in NegTokenInit advertising kerberosMechOID.
func WrapKerberosNegTokenInit(gssKerberosToken []byte) ([]byte, error) {
	mechs := []asn1.ObjectIdentifier{kerberosMechOID, ntlmMechOID}
	mechTypes, err := asn1.Marshal(mechs)
	if err != nil {
		return nil, fmt.Errorf("credssp: marshal mechTypes: %w", err)
	}
	mechToken, err := asn1.Marshal(gssKerberosToken)
	if err != nil {
		return nil, fmt.Errorf("credssp: marshal mechToken: %w", err)
	}
	fields := append(derExplicit(0, mechTypes), derExplicit(2, mechToken)...)
	return wrapGSS(wrapChoice(0, fields))
}

func readPrincipal(r io.Reader) (Principal, error) {
	var p Principal
	if err := binary.Read(r, binary.BigEndian, &p.NameType); err != nil {
		return p, err
	}
	var numComponents uint32
	if err := binary.Read(r, binary.BigEndian, &numComponents); err != nil {
		return p, err
	}
	realm, err := readCountedString(r)
	if err != nil {
		return p, err
	}
	p.Realm = realm
	for i := uint32(0); i < numComponents; i++ {
		comp, err := readCountedString(r)
		if err != nil {
			return p, err
		}
		p.Components = append(p.Components, comp)
	}
	return p, nil
}

func readCredentialEntry(r io.Reader) (CredentialEntry, error) {
	var c CredentialEntry
	client, err := readPrincipal(r)
	if err != nil {
		return c, err
	}
	c.Client = client

	server, err := readPrincipal(r)
	if err != nil {
		return c, err
	}
	c.Server = server

	// Keyblock: enctype (uint16), keylen (uint16), key data
	if err := binary.Read(r, binary.BigEndian, &c.KeyType); err != nil {
		return c, err
	}
	keyBytes, err := readCountedBytes(r, 2)
	if err != nil {
		return c, err
	}
	c.KeyData = keyBytes

	// Times: authtime, starttime, endtime, renew_till (each uint32 seconds)
	var times [4]uint32
	if err := binary.Read(r, binary.BigEndian, &times); err != nil {
		return c, err
	}
	c.AuthTime = time.Unix(int64(times[0]), 0)
	c.StartTime = time.Unix(int64(times[1]), 0)
	c.EndTime = time.Unix(int64(times[2]), 0)
	c.RenewTill = time.Unix(int64(times[3]), 0)

	var isSkey uint8
	if err := binary.Read(r, binary.BigEndian, &isSkey); err != nil {
		return c, err
	}
	if err := binary.Read(r, binary.BigEndian, &c.Flags); err != nil {
		return c, err
	}

	// Addresses count
	var numAddrs uint32
	if err := binary.Read(r, binary.BigEndian, &numAddrs); err != nil {
		return c, err
	}
	for i := uint32(0); i < numAddrs; i++ {
		var addrType uint16
		_ = binary.Read(r, binary.BigEndian, &addrType)
		_, _ = readCountedBytes(r, 4)
	}

	// Authdata count
	var numAuthData uint32
	if err := binary.Read(r, binary.BigEndian, &numAuthData); err != nil {
		return c, err
	}
	for i := uint32(0); i < numAuthData; i++ {
		var adType uint16
		_ = binary.Read(r, binary.BigEndian, &adType)
		_, _ = readCountedBytes(r, 4)
	}

	// Ticket: counted bytes (4B length)
	ticket, err := readCountedBytes(r, 4)
	if err != nil {
		return c, err
	}
	c.Ticket = ticket

	// Second ticket (usually empty)
	_, _ = readCountedBytes(r, 4)

	return c, nil
}

func readCountedString(r io.Reader) (string, error) {
	bytes, err := readCountedBytes(r, 4)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func readCountedBytes(r io.Reader, lenSize int) ([]byte, error) {
	var length uint32
	if lenSize == 2 {
		var l16 uint16
		if err := binary.Read(r, binary.BigEndian, &l16); err != nil {
			return nil, err
		}
		length = uint32(l16)
	} else {
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return nil, err
		}
	}
	if length == 0 {
		return nil, nil
	}
	if length > 65536 {
		return nil, fmt.Errorf("credssp: length exceeds sanity limit (%d bytes)", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func wrapApplication0(content []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x60) // [APPLICATION 0]
	length := len(content)
	if length < 128 {
		buf.WriteByte(byte(length))
	} else if length < 256 {
		buf.WriteByte(0x81)
		buf.WriteByte(byte(length))
	} else {
		buf.WriteByte(0x82)
		buf.WriteByte(byte(length >> 8))
		buf.WriteByte(byte(length))
	}
	buf.Write(content)
	return buf.Bytes()
}
