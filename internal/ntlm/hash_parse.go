package ntlm

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// NTHashSize is the length of an NT hash in bytes (MD4 output).
const NTHashSize = 16

// ParseNTHash accepts a 32-character hex NT hash or an LM:NT pair
// (32 hex : 32 hex) and returns the 16-byte NT hash.
func ParseNTHash(input string) ([]byte, error) {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return nil, fmt.Errorf("ntlm: empty NT hash")
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		// LM:NT — use the NT half only.
		s = s[i+1:]
	}
	s = strings.ReplaceAll(s, " ", "")
	if len(s) != NTHashSize*2 {
		return nil, fmt.Errorf("ntlm: NT hash must be %d hex chars (or LM:NT), got %d", NTHashSize*2, len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ntlm: invalid NT hash hex: %w", err)
	}
	if len(raw) != NTHashSize {
		return nil, fmt.Errorf("ntlm: NT hash must be %d bytes, got %d", NTHashSize, len(raw))
	}
	return raw, nil
}

// FormatNTHash returns the lowercase hex encoding of a 16-byte NT hash.
func FormatNTHash(nt []byte) string {
	return hex.EncodeToString(nt)
}
