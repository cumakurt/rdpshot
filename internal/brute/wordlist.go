package brute

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"rdpshot/internal/model"
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

// BuildCandidates produces the user x password candidate list.
func BuildCandidates(users, passwords []string) ([]model.Credential, error) {
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
	candidates := make([]model.Credential, 0, total)
	for _, user := range users {
		for _, password := range passwords {
			candidates = append(candidates, model.Credential{Username: user, Secret: password})
		}
	}
	return candidates, nil
}
