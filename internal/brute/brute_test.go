package brute

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/model"
)

type fakeAuth struct {
	valid     map[string]string
	lockedFor string
	calls     []string
	failWith  error
}

func (f *fakeAuth) Authenticate(_ context.Context, ep model.Endpoint, cred model.Credential) error {
	f.calls = append(f.calls, cred.Username+":"+cred.Secret)
	if f.failWith != nil {
		return f.failWith
	}
	if cred.Username == f.lockedFor {
		return ErrLockedOut
	}
	if f.valid[cred.Username] == cred.Secret {
		return nil
	}
	return ErrInvalidCredential
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testCandidates(pairs ...string) []model.Credential {
	var out []model.Credential
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		out = append(out, model.Credential{Username: parts[0], Secret: parts[1]})
	}
	return out
}

func TestRunFindsValidCredential(t *testing.T) {
	auth := &fakeAuth{valid: map[string]string{"admin": "s3cret"}}
	engine := New(auth, Options{}, Hooks{}, quietLogger())
	ep := model.Endpoint{Address: "10.0.0.1", Port: 3389}

	result, err := engine.Run(context.Background(), ep, 1, "scan-1",
		testCandidates("admin:wrong", "admin:s3cret", "admin:never"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(result.Credentials) != 1 || result.Credentials[0].Secret != "s3cret" {
		t.Fatalf("credentials = %+v", result.Credentials)
	}
	if result.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2 (audit must stop at first success)", result.Attempts)
	}
	if result.Credentials[0].ScanID != "scan-1" || result.Credentials[0].HostID != 1 {
		t.Fatalf("credential not tagged: %+v", result.Credentials[0])
	}
}

func TestRunStopsAtFailSafeLimit(t *testing.T) {
	auth := &fakeAuth{valid: map[string]string{}}
	engine := New(auth, Options{MaxFailuresPerHost: 2}, Hooks{}, quietLogger())
	ep := model.Endpoint{Address: "10.0.0.2", Port: 3389}

	result, err := engine.Run(context.Background(), ep, 1, "s",
		testCandidates("u:1", "u:2", "u:3", "u:4"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Attempts != 2 || result.Failures != 2 {
		t.Fatalf("attempts=%d failures=%d, want 2/2", result.Attempts, result.Failures)
	}
	if !strings.Contains(result.StoppedReason, "fail-safe") {
		t.Fatalf("stopped reason = %q", result.StoppedReason)
	}
}

func TestRunUnlimitedFailuresWhenLimitDisabled(t *testing.T) {
	auth := &fakeAuth{valid: map[string]string{}}
	engine := New(auth, Options{MaxFailuresPerHost: 0}, Hooks{}, quietLogger())
	ep := model.Endpoint{Address: "10.0.0.2", Port: 3389}
	cands := testCandidates("u:1", "u:2", "u:3", "u:4")

	result, err := engine.Run(context.Background(), ep, 1, "s", cands)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Attempts != len(cands) || result.Failures != len(cands) {
		t.Fatalf("attempts=%d failures=%d, want full list %d", result.Attempts, result.Failures, len(cands))
	}
	if result.StoppedReason != "candidate list exhausted" {
		t.Fatalf("stopped reason = %q", result.StoppedReason)
	}
}

func TestRunStopsOnLockout(t *testing.T) {
	auth := &fakeAuth{valid: map[string]string{}, lockedFor: "admin"}
	engine := New(auth, Options{MaxFailuresPerHost: 10}, Hooks{}, quietLogger())
	ep := model.Endpoint{Address: "10.0.0.3", Port: 3389}

	result, err := engine.Run(context.Background(), ep, 1, "s",
		testCandidates("admin:1", "admin:2", "admin:3"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !result.LockedOut || result.Attempts != 1 {
		t.Fatalf("result = %+v", result)
	}
	if !strings.Contains(result.StoppedReason, "locked") {
		t.Fatalf("stopped reason = %q", result.StoppedReason)
	}
}

func TestRunReportsTransportErrors(t *testing.T) {
	auth := &fakeAuth{failWith: errors.New("connection reset")}
	engine := New(auth, Options{}, Hooks{}, quietLogger())
	ep := model.Endpoint{Address: "10.0.0.4", Port: 3389}

	result, err := engine.Run(context.Background(), ep, 1, "s", testCandidates("u:p"))
	if err == nil {
		t.Fatal("expected the transport error to surface")
	}
	if result.Attempts != 1 {
		t.Fatalf("attempts = %d", result.Attempts)
	}
}

func TestRunHonoursCancellation(t *testing.T) {
	auth := &fakeAuth{valid: map[string]string{}}
	engine := New(auth, Options{MaxFailuresPerHost: 10}, Hooks{}, quietLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := engine.Run(ctx, model.Endpoint{Address: "10.0.0.5", Port: 3389}, 1, "s",
		testCandidates("u:1", "u:2"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if result.Attempts != 0 {
		t.Fatalf("attempts = %d, want 0", result.Attempts)
	}
}

func TestRunStopsOnCredSSPUnavailable(t *testing.T) {
	auth := &fakeAuth{failWith: ErrCredSSPUnavailable}
	var outcomes []string
	engine := New(auth, Options{MaxFailuresPerHost: 5}, Hooks{
		OnAttempt: func(_ model.Credential, outcome, _ string) {
			outcomes = append(outcomes, outcome)
		},
	}, quietLogger())
	result, err := engine.Run(context.Background(), model.Endpoint{Address: "10.0.0.9", Port: 3389}, 1, "s",
		testCandidates("u:1", "u:2"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Attempts != 1 || result.Failures != 0 {
		t.Fatalf("result = %+v", result)
	}
	if result.StoppedReason != StopReasonNoCredSSP {
		t.Fatalf("stopped = %q", result.StoppedReason)
	}
	if len(outcomes) != 1 || outcomes[0] != model.AuthOutcomeUnavailable {
		t.Fatalf("outcomes = %#v", outcomes)
	}
}

func TestPrependOCRUsers(t *testing.T) {
	base, err := BuildCandidates([]string{"admin"}, []string{"p1", "p2"}, "LAB")
	if err != nil {
		t.Fatal(err)
	}
	got := PrependOCRUsers(base, []string{"Yasemin", "admin", "Other user"}, "LAB")
	if len(got) != len(base)+2 {
		t.Fatalf("len = %d, want %d", len(got), len(base)+2)
	}
	if got[0].Username != "Yasemin" || got[0].Domain != "LAB" || got[0].Secret != "p1" {
		t.Fatalf("first = %+v", got[0])
	}
	if got[1].Username != "Yasemin" || got[1].Secret != "p2" {
		t.Fatalf("second = %+v", got[1])
	}
}

func TestRunCallsHooks(t *testing.T) {
	auth := &fakeAuth{valid: map[string]string{"admin": "ok"}}
	var successes, failures int
	engine := New(auth, Options{}, Hooks{
		OnSuccess: func(model.Credential) { successes++ },
		OnFailure: func(model.Credential, error) { failures++ },
	}, quietLogger())

	_, err := engine.Run(context.Background(), model.Endpoint{Address: "10.0.0.6", Port: 3389}, 1, "s",
		testCandidates("admin:no", "admin:ok"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("successes=%d failures=%d", successes, failures)
	}
}

func TestPauseAddsJitter(t *testing.T) {
	engine := New(&fakeAuth{}, Options{Delay: 10 * time.Millisecond, Jitter: 5 * time.Millisecond}, Hooks{}, quietLogger())
	var slept time.Duration
	engine.sleep = func(d time.Duration) { slept = d }
	engine.pause()
	if slept < 10*time.Millisecond || slept > 15*time.Millisecond {
		t.Fatalf("slept %s, want within [10ms,15ms)", slept)
	}
}

func TestLoadWordlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.txt")
	content := "# comment\n\nadmin\nuser\nadmin\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := LoadWordlist(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(entries) != 2 || entries[0] != "admin" || entries[1] != "user" {
		t.Fatalf("entries = %v", entries)
	}
}

func TestLoadWordlistErrors(t *testing.T) {
	if _, err := LoadWordlist(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("expected error for missing wordlist")
	}
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("# only comments\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadWordlist(empty); err == nil {
		t.Fatal("expected error for empty wordlist")
	}
}

func TestBuildCandidates(t *testing.T) {
	candidates, err := BuildCandidates([]string{"a", "b"}, []string{"1", "2", "3"}, "")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(candidates) != 6 {
		t.Fatalf("candidates = %d, want 6", len(candidates))
	}
	if _, err := BuildCandidates(nil, []string{"1"}, ""); err == nil {
		t.Fatal("expected error for empty user list")
	}
	if _, err := BuildCandidates([]string{"a"}, nil, ""); err == nil {
		t.Fatal("expected error for empty password list")
	}
	if _, err := BuildCandidates(make([]string, 2000), make([]string, 2000), ""); err == nil {
		t.Fatal("expected error for oversized candidate list")
	}
}

func TestBuildCandidatesAppliesDomain(t *testing.T) {
	cands, err := BuildCandidates(
		[]string{"alice", `CORP\bob`, "carol@fabrikam.local"},
		[]string{"x"},
		"DEFAULT",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 3 {
		t.Fatalf("len = %d, want 3", len(cands))
	}
	want := []struct{ user, domain string }{
		{"alice", "DEFAULT"},
		{"bob", "CORP"},
		{"carol", "fabrikam.local"},
	}
	for i, w := range want {
		if cands[i].Username != w.user || cands[i].Domain != w.domain {
			t.Fatalf("cand[%d] = %s\\%s, want %s\\%s", i, cands[i].Domain, cands[i].Username, w.domain, w.user)
		}
	}
}

func TestParseUserDomain(t *testing.T) {
	user, domain := ParseUserDomain("alice", "LAB")
	if user != "alice" || domain != "LAB" {
		t.Fatalf("got %q %q", user, domain)
	}
	user, domain = ParseUserDomain(`CORP\bob`, "LAB")
	if user != "bob" || domain != "CORP" {
		t.Fatalf("backslash got %q %q", user, domain)
	}
	user, domain = ParseUserDomain("carol@fabrikam.local", "LAB")
	if user != "carol" || domain != "fabrikam.local" {
		t.Fatalf("at-sign got %q %q", user, domain)
	}
}

func TestBuildSingleAndPTHCandidates(t *testing.T) {
	single, err := BuildSingleCandidate("alice", "CORP", "pass")
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 || single[0].Method != model.CredMethodPassword || single[0].Secret != "pass" {
		t.Fatalf("single = %+v", single)
	}
	hash := "a4f49c406510bdcab6824ee7c30fd852"
	pth, err := BuildPTHCandidate("bob", "", hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(pth) != 1 || pth[0].Method != model.CredMethodNTHash || pth[0].Secret != hash {
		t.Fatalf("pth = %+v", pth)
	}
	if _, err := BuildSingleCandidate("", "", "x"); err == nil {
		t.Fatal("empty username must fail")
	}
	if _, err := BuildPTHCandidate("bob", "", "not-a-hash"); err == nil {
		t.Fatal("invalid hash must fail")
	}
}
