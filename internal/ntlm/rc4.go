package ntlm

// rc4 is a minimal RC4 keystream cipher used by the NTLM sealing routines.
// It is implemented locally instead of using the deprecated crypto/rc4
// package so the module keeps a clean dependency surface.
type rc4 struct {
	s    [256]byte
	i, j byte
}

func newRC4(key []byte) *rc4 {
	if len(key) == 0 || len(key) > 256 {
		panic("ntlm: RC4 key length out of range")
	}
	c := &rc4{}
	for i := 0; i < 256; i++ {
		c.s[i] = byte(i)
	}
	var j byte
	for i := 0; i < 256; i++ {
		j += c.s[i] + key[i%len(key)]
		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
	return c
}

// xorKeyStream XORs dst with the next len(dst) bytes of the keystream in
// place. dst and src may alias.
func (c *rc4) xorKeyStream(dst, src []byte) {
	for k := range src {
		c.i++
		c.j += c.s[c.i]
		c.s[c.i], c.s[c.j] = c.s[c.j], c.s[c.i]
		dst[k] = src[k] ^ c.s[c.s[c.i]+c.s[c.j]]
	}
}
