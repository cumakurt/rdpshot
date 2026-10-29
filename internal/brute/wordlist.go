package brute

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"rdpshot/internal/model"
	"rdpshot/internal/ntlm"
)

// MaxCandidateCount bounds the generated candidate list to keep accidental
// wordlist combinations from turning an audit into an outage.
const MaxCandidateCount = 1000000

// LoadWordlist reads one entry per line, skipping blanks and comments.
func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("brute: open wordlist %q: %w", path, err)
	}
	defer file.Close()

	var entries []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("brute: read wordlist %q: %w", path, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("brute: wordlist %q contains no entries", path)
	}
	return entries, nil
}

// BuildCandidates produces the user x password candidate list. defaultDomain
// is applied when a username entry does not already carry DOMAIN\user or
// user@domain form.
func BuildCandidates(users, passwords []string, defaultDomain string) ([]model.Credential, error) {
	if len(users) == 0 {
		return nil, fmt.Errorf("brute: no usernames to test")
	}
	if len(passwords) == 0 {
		return nil, fmt.Errorf("brute: no passwords to test")
	}
	total := len(users) * len(passwords)
	if total > MaxCandidateCount {
		return nil, fmt.Errorf("brute: candidate list too large (%d > %d); narrow the wordlists", total, MaxCandidateCount)
	}
	defaultDomain = strings.TrimSpace(defaultDomain)
	candidates := make([]model.Credential, 0, total)
	for _, user := range users {
		username, domain := ParseUserDomain(user, defaultDomain)
		if username == "" {
			continue
		}
		for _, password := range passwords {
			candidates = append(candidates, model.Credential{
				Username: username,
				Domain:   domain,
				Secret:   password,
				Method:   model.CredMethodPassword,
			})
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("brute: no usable usernames after domain parsing")
	}
	return candidates, nil
}

// ParseUserDomain splits DOMAIN\user or user@domain from entry. When the entry
// has no embedded domain, defaultDomain is returned.
func ParseUserDomain(entry, defaultDomain string) (username, domain string) {
	entry = strings.TrimSpace(entry)
	defaultDomain = strings.TrimSpace(defaultDomain)
	if entry == "" {
		return "", defaultDomain
	}
	if i := strings.IndexByte(entry, '\\'); i >= 0 {
		return strings.TrimSpace(entry[i+1:]), strings.TrimSpace(entry[:i])
	}
	if i := strings.LastIndexByte(entry, '@'); i > 0 {
		return strings.TrimSpace(entry[:i]), strings.TrimSpace(entry[i+1:])
	}
	return entry, defaultDomain
}

// BuildSingleCandidate builds one cleartext credential.
func BuildSingleCandidate(username, domain, password string) ([]model.Credential, error) {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if username == "" {
		return nil, fmt.Errorf("brute: username is required for single-credential mode")
	}
	if password == "" {
		return nil, fmt.Errorf("brute: password is required for single-credential mode")
	}
	user, dom := ParseUserDomain(username, domain)
	return []model.Credential{{
		Username: user,
		Domain:   dom,
		Secret:   password,
		Method:   model.CredMethodPassword,
	}}, nil
}

// BuildPTHCandidate builds one pass-the-hash credential. nthash must parse as
// a 32-hex NT hash or LM:NT pair; the stored secret is the normalized NT hex.
func BuildPTHCandidate(username, domain, nthash string) ([]model.Credential, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("brute: username is required for pass-the-hash mode")
	}
	raw, err := ntlm.ParseNTHash(nthash)
	if err != nil {
		return nil, fmt.Errorf("brute: %w", err)
	}
	user, dom := ParseUserDomain(username, domain)
	return []model.Credential{{
		Username: user,
		Domain:   dom,
		Secret:   ntlm.FormatNTHash(raw),
		Method:   model.CredMethodNTHash,
	}}, nil
}
