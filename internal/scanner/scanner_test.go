package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"rdpshot/internal/brute"
	"rdpshot/internal/events"
	"rdpshot/internal/model"
	"rdpshot/internal/rdp"
	"rdpshot/internal/screenshot"
	"rdpshot/internal/store"
)

// gatherReply is one scripted outcome for a fake gather call.
type gatherReply struct {
	result rdp.GatherResult
	err    error
}

// fakeGather scripts the recon outcome per endpoint address and records calls.
type fakeGather struct {
	mu      sync.Mutex
	replies map[string]gatherReply
	hook    func(ctx context.Context, ep model.Endpoint) (rdp.GatherResult, error)
	calls   []model.Endpoint
}

func newFakeGather() *fakeGather {
	return &fakeGather{replies: make(map[string]gatherReply)}
}

func (f *fakeGather) script(addr string, result rdp.GatherResult, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[addr] = gatherReply{result: result, err: err}
}

// setHook replaces scripted replies with custom behavior (used to block until
// cancellation in the cancellation test).
func (f *fakeGather) setHook(hook func(ctx context.Context, ep model.Endpoint) (rdp.GatherResult, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = hook
}

func (f *fakeGather) gather(ctx context.Context, ep model.Endpoint, opts rdp.Options) (rdp.GatherResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, ep)
	hook := f.hook
	reply, ok := f.replies[ep.Address]
	f.mu.Unlock()

	if hook != nil {
		return hook(ctx, ep)
	}
	if !ok {
		return rdp.GatherResult{}, fmt.Errorf("fake gather: no reply scripted for %s", ep.Address)
	}
	return reply.result, reply.err
}

func (f *fakeGather) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// fakeAuthenticator accepts exactly one credential and rejects the rest with
// brute.ErrInvalidCredential. Every call is recorded.
type fakeAuthenticator struct {
	mu         sync.Mutex
	validUser  string
	validSecrt string
	attempts   []model.Credential
}

func (f *fakeAuthenticator) Authenticate(ctx context.Context, ep model.Endpoint, cred model.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts = append(f.attempts, cred)
	if cred.Username == f.validUser && cred.Secret == f.validSecrt {
		return nil
	}
	return brute.ErrInvalidCredential
}

func (f *fakeAuthenticator) attemptCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.attempts)
}

// fakeGrabber implements screenshot.Grabber with scripted availability and
// capture outcomes.
type fakeGrabber struct {
	mu           sync.Mutex
	availableErr error
	grabErr      error
	shot         model.Screenshot
	grabs        []model.Credential
}

func (f *fakeGrabber) Available() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.availableErr
}

func (f *fakeGrabber) Grab(ctx context.Context, ep model.Endpoint, cred model.Credential) (model.Screenshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grabs = append(f.grabs, cred)
	if f.grabErr != nil {
		return model.Screenshot{}, f.grabErr
	}
	shot := f.shot
	shot.Address = ep.Address
	shot.Port = ep.Port
	if shot.Username == "" {
		shot.Username = cred.Username
	}
	return shot, nil
}

// testEnv bundles the real store and hub with fakes for the network side.
type testEnv struct {
	engine    *Engine
	store     *store.Store
	hub       *events.Hub
	gather    *fakeGather
	wordlists map[string][]string

	mu      sync.Mutex
	wlCalls []string
}

// newTestEnv builds an engine backed by a real store in t.TempDir() and a real
// event hub. The recon gather and wordlist loader are faked so no network or
// wordlist files are needed. auth and grabber may be nil.
func newTestEnv(t *testing.T, auth brute.Authenticator, grabber screenshot.Grabber) *testEnv {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})

	hub := events.NewHub(128)
	t.Cleanup(hub.Close)

	env := &testEnv{
		store:     st,
		hub:       hub,
		gather:    newFakeGather(),
		wordlists: make(map[string][]string),
	}
	engine := New(Dependencies{
		Store:         st,
		Hub:           hub,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Authenticator: auth,
		Grabber:       grabber,
	})
	engine.gather = env.gather.gather
	engine.loadWordlist = env.loadWordlist
	env.engine = engine
	return env
}

func (env *testEnv) setWordlist(path string, entries []string) {
	env.mu.Lock()
	defer env.mu.Unlock()
	env.wordlists[path] = entries
}

func (env *testEnv) loadWordlist(path string) ([]string, error) {
	env.mu.Lock()
	defer env.mu.Unlock()
	env.wlCalls = append(env.wlCalls, path)
	entries, ok := env.wordlists[path]
	if !ok {
		return nil, fmt.Errorf("fake wordlist: no entries scripted for %q", path)
	}
	return entries, nil
}

func (env *testEnv) wordlistCallCount() int {
	env.mu.Lock()
	defer env.mu.Unlock()
	return len(env.wlCalls)
}

// newScan creates the scan row Run persists into.
func (env *testEnv) newScan(t *testing.T, name string, opts model.ScanOptions) *model.Scan {
	t.Helper()
	scan := &model.Scan{
		ID:        model.NewID("scan"),
		Name:      name,
		Status:    model.ScanPending,
		CreatedAt: time.Now().UTC(),
		Options:   opts,
	}
	if err := env.store.CreateScan(*scan); err != nil {
		t.Fatalf("create scan row: %v", err)
	}
	return scan
}

// baseOptions returns scan options that keep the run fast and free of the
// intrusive stages; the rate limiter is covered by limiter_test.go.
func baseOptions() model.ScanOptions {
	return model.ScanOptions{
		TimeoutMS:     200,
		Concurrency:   2,
		RatePerSecond: 0,
	}
}

// runWithWatchdog runs the engine and fails the test if it does not return
// within the watchdog window.
func runWithWatchdog(t *testing.T, env *testEnv, ctx context.Context, scan *model.Scan, endpoints []model.Endpoint) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		env.engine.Run(ctx, scan, endpoints)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within the watchdog window")
	}
}

// drainEvents collects every buffered event of a subscription. All publishes
// happen before Run returns, so no concurrent reader is needed.
func drainEvents(sub *events.Subscription) []model.Event {
	var out []model.Event
	for {
		select {
		case ev, ok := <-sub.C():
			if !ok {
				return out
			}
			out = append(out, ev)
		default:
			return out
		}
	}
}

// TestRunPersistsOpenHostsAndFindings checks that recon outcomes map to host
// states, that the BlueKeep finding is persisted for the open host and that the
// scan counters and row reflect the finished run.
func TestRunPersistsOpenHostsAndFindings(t *testing.T) {
	const (
		openAddr     = "10.0.0.1"
		closedAddr   = "10.0.0.2"
		filteredAddr = "10.0.0.3"
	)

	env := newTestEnv(t, nil, nil)
	env.gather.script(openAddr, rdp.GatherResult{
		Service: model.ServiceInfo{
			NegotiatedProtocol: rdp.ProtocolRDP,
			NLARequired:        true,
			OSGuess:            "Windows",
		},
		BlueKeep: &rdp.BlueKeepResult{
			Attempted: true,
			Triggered: true,
			Reason:    "server answered the benign MS_T120 channel probe with a Disconnect Provider Ultimatum",
			Evidence:  "unit test evidence",
		},
	}, nil)
	env.gather.script(closedAddr, rdp.GatherResult{}, fmt.Errorf("dial tcp: %w", rdp.ErrNetwork))
	env.gather.script(filteredAddr, rdp.GatherResult{}, fmt.Errorf("read tcp: %w", rdp.ErrTimeout))

	opts := baseOptions()
	opts.EnableVuln = true
	scan := env.newScan(t, "open-hosts-and-findings", opts)

	endpoints := []model.Endpoint{
		{Address: openAddr, Port: 3389},
		{Address: closedAddr, Port: 3389},
		{Address: filteredAddr, Port: 3389},
	}
	runWithWatchdog(t, env, context.Background(), scan, endpoints)

	// Host states.
	hosts, err := env.store.ListHosts(scan.ID)
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	if len(hosts) != len(endpoints) {
		t.Fatalf("stored %d hosts, want %d", len(hosts), len(endpoints))
	}
	wantStates := map[string]string{
		openAddr:     "open",
		closedAddr:   "closed",
		filteredAddr: "filtered",
	}
	var openHost *model.Host
	for i := range hosts {
		h := &hosts[i]
		want, ok := wantStates[h.Endpoint.Address]
		if !ok {
			t.Errorf("unexpected host %s in store", h.Endpoint.Key())
			continue
		}
		if h.State != want {
			t.Errorf("host %s state = %q, want %q", h.Endpoint.Key(), h.State, want)
		}
		if h.Endpoint.Address == openAddr {
			openHost = h
		}
	}
	if openHost == nil {
		t.Fatal("open host missing from store")
	}
	if openHost.Service == nil {
		t.Fatal("open host has no persisted service info")
	}
	if !openHost.Service.NLARequired {
		t.Error("persisted service info lost NLARequired flag")
	}

	// Findings are only produced for open hosts; the BlueKeep probe triggered,
	// so the CVE-2019-0708 finding must be stored as vulnerable.
	findings, err := env.store.ListFindings(scan.ID)
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("no findings stored for the open host")
	}
	var bluekeep *model.Finding
	for i := range findings {
		f := &findings[i]
		if f.Address != openAddr {
			t.Errorf("finding %s stored for %s, want only open host %s", f.CheckID, f.Address, openAddr)
		}
		if f.CheckID == "bluekeep-cve-2019-0708" {
			bluekeep = &findings[i]
		}
	}
	if bluekeep == nil {
		t.Fatal("bluekeep-cve-2019-0708 finding not stored")
	}
	if bluekeep.Status != model.FindingVulnerable {
		t.Errorf("bluekeep finding status = %q, want %q", bluekeep.Status, model.FindingVulnerable)
	}
	if bluekeep.CVE != "CVE-2019-0708" {
		t.Errorf("bluekeep finding CVE = %q, want CVE-2019-0708", bluekeep.CVE)
	}
	if bluekeep.HostID != openHost.ID {
		t.Errorf("bluekeep finding host id = %d, want open host id %d", bluekeep.HostID, openHost.ID)
	}

	// In-memory progress counters.
	if scan.Status != model.ScanCompleted {
		t.Errorf("scan status = %q, want %q", scan.Status, model.ScanCompleted)
	}
	p := scan.Progress
	if p.Total != 3 || p.Done != 3 || p.Open != 1 || p.Closed != 2 {
		t.Errorf("progress = %+v, want Total=3 Done=3 Open=1 Closed=2", p)
	}
	if p.Findings < 1 {
		t.Errorf("progress.Findings = %d, want >= 1", p.Findings)
	}

	// The scan row in the store reflects the finished state.
	stored, err := env.store.GetScan(scan.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if stored.Status != model.ScanCompleted {
		t.Errorf("stored scan status = %q, want %q", stored.Status, model.ScanCompleted)
	}
	if stored.StartedAt == nil || stored.FinishedAt == nil {
		t.Error("stored scan is missing started_at or finished_at")
	}
	if stored.Progress != p {
		t.Errorf("stored progress = %+v, want %+v", stored.Progress, p)
	}
}

// TestRunCredentialAuditStoresMaskedEvents checks that a verified credential is
// stored with its real secret but every published event carries only the masked
// payload.
func TestRunCredentialAuditStoresMaskedEvents(t *testing.T) {
	const (
		authAddr   = "10.0.0.10"
		authUser   = "admin"
		authSecret = "s3cret"
		userList   = "users.txt"
		passList   = "passwords.txt"
	)

	auth := &fakeAuthenticator{validUser: authUser, validSecrt: authSecret}
	env := newTestEnv(t, auth, nil)
	// Two candidates: (guest, s3cret) fails, (admin, s3cret) succeeds. The
	// audit stops at the first valid credential.
	env.setWordlist(userList, []string{"guest", authUser})
	env.setWordlist(passList, []string{authSecret})
	env.gather.script(authAddr, rdp.GatherResult{
		Service: model.ServiceInfo{NegotiatedProtocol: rdp.ProtocolRDP, NLARequired: true},
	}, nil)

	opts := baseOptions()
	opts.EnableAuth = true
	opts.Acknowledged = true
	opts.MaxAuthFailures = 2
	opts.UserWordlist = userList
	opts.PasswordWordlist = passList
	scan := env.newScan(t, "credential-audit", opts)

	sub := env.hub.Subscribe("")
	t.Cleanup(sub.Close)

	runWithWatchdog(t, env, context.Background(), scan, []model.Endpoint{{Address: authAddr, Port: 3389}})

	// The verified credential is stored with the real secret.
	creds, err := env.store.ListCredentials(scan.ID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("stored %d credentials, want 1", len(creds))
	}
	if creds[0].Username != authUser || creds[0].Secret != authSecret {
		t.Errorf("stored credential = %q/%q, want %q/%q", creds[0].Username, creds[0].Secret, authUser, authSecret)
	}
	if scan.Progress.Creds != 1 {
		t.Errorf("progress.Creds = %d, want 1", scan.Progress.Creds)
	}

	// Events must never leak the raw secret and must carry a masked credential.
	var credEvents []model.Event
	for _, ev := range drainEvents(sub) {
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal event %s: %v", ev.Type, err)
		}
		if bytes.Contains(raw, []byte(authSecret)) {
			t.Errorf("event %s leaks the raw secret: %s", ev.Type, raw)
		}
		if ev.Type == model.EventCredential {
			credEvents = append(credEvents, ev)
		}
	}
	if len(credEvents) != 1 {
		t.Fatalf("got %d credential events, want 1", len(credEvents))
	}
	payload, err := json.Marshal(credEvents[0].Payload)
	if err != nil {
		t.Fatalf("marshal credential payload: %v", err)
	}
	if !bytes.Contains(payload, []byte(`"secret":"********"`)) {
		t.Errorf("credential payload = %s, want masked secret", payload)
	}
	cred, ok := credEvents[0].Payload.(model.Credential)
	if !ok {
		t.Fatalf("credential event payload has type %T, want model.Credential", credEvents[0].Payload)
	}
	if cred.Username != authUser || cred.Secret != "********" {
		t.Errorf("credential event payload = %q/%q, want %q/masked", cred.Username, cred.Secret, authUser)
	}
}

// TestRunSkipsAuthWithoutCredSSP ensures TLS-only hosts do not burn candidates
// and record a skipped auth summary aligned with nla-not-required.
func TestRunSkipsAuthWithoutCredSSP(t *testing.T) {
	const addr = "10.0.0.55"
	auth := &fakeAuthenticator{validUser: "admin", validSecrt: "s3cret"}
	env := newTestEnv(t, auth, nil)
	env.setWordlist("users.txt", []string{"admin"})
	env.setWordlist("passwords.txt", []string{"s3cret"})
	env.gather.script(addr, rdp.GatherResult{
		Service: model.ServiceInfo{NegotiatedProtocol: rdp.ProtocolSSL, NLARequired: false},
	}, nil)

	opts := baseOptions()
	opts.EnableAuth = true
	opts.Acknowledged = true
	opts.MaxAuthFailures = 5
	opts.UserWordlist = "users.txt"
	opts.PasswordWordlist = "passwords.txt"
	scan := env.newScan(t, "auth-skip-tls", opts)
	runWithWatchdog(t, env, context.Background(), scan, []model.Endpoint{{Address: addr, Port: 3389}})

	if auth.attemptCount() != 0 {
		t.Fatalf("authenticator attempts = %d, want 0", auth.attemptCount())
	}
	hosts, err := env.store.ListHosts(scan.ID)
	if err != nil {
		t.Fatalf("hosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Service == nil {
		t.Fatalf("hosts = %+v", hosts)
	}
	if hosts[0].Service.AuthStoppedReason != brute.StopReasonNoCredSSP {
		t.Fatalf("stopped = %q", hosts[0].Service.AuthStoppedReason)
	}
	if hosts[0].Service.Evidence["auth_path"] != "skipped_no_credssp" {
		t.Fatalf("evidence = %#v", hosts[0].Service.Evidence)
	}
	attempts, err := env.store.ListAuthAttempts(scan.ID)
	if err != nil {
		t.Fatalf("attempts: %v", err)
	}
	if len(attempts) != 1 || attempts[0].Outcome != model.AuthOutcomeSkipped {
		t.Fatalf("attempts = %+v", attempts)
	}
}

// TestRunScreenshotCapture checks that a verified credential yields one stored
// screenshot and that an unavailable capture tool leaves no row behind while
// the run still completes.
func TestRunScreenshotCapture(t *testing.T) {
	const (
		screenAddr = "10.0.0.20"
		screenUser = "admin"
		screenPass = "s3cret"
		userList   = "users.txt"
		passList   = "passwords.txt"
	)

	t.Run("capture succeeds", func(t *testing.T) {
		grabber := &fakeGrabber{shot: model.Screenshot{
			FilePath: "outputs/screenshots/x.png",
			Width:    1024,
			Height:   768,
		}}
		auth := &fakeAuthenticator{validUser: screenUser, validSecrt: screenPass}
		env := newTestEnv(t, auth, grabber)
		env.setWordlist(userList, []string{screenUser})
		env.setWordlist(passList, []string{screenPass})
		env.gather.script(screenAddr, rdp.GatherResult{
			Service: model.ServiceInfo{NegotiatedProtocol: rdp.ProtocolRDP, NLARequired: true},
		}, nil)

		opts := baseOptions()
		opts.EnableAuth = true
		opts.EnableScreens = true
		opts.Acknowledged = true
		opts.MaxAuthFailures = 3
		opts.UserWordlist = userList
		opts.PasswordWordlist = passList
		scan := env.newScan(t, "screenshot-capture", opts)

		runWithWatchdog(t, env, context.Background(), scan, []model.Endpoint{{Address: screenAddr, Port: 3389}})

		shots, err := env.store.ListScreenshots(scan.ID)
		if err != nil {
			t.Fatalf("list screenshots: %v", err)
		}
		if len(shots) != 1 {
			t.Fatalf("stored %d screenshots, want 1", len(shots))
		}
		if shots[0].FilePath != "outputs/screenshots/x.png" || shots[0].Width != 1024 || shots[0].Height != 768 {
			t.Errorf("stored screenshot = %q %dx%d, want %q 1024x768",
				shots[0].FilePath, shots[0].Width, shots[0].Height, "outputs/screenshots/x.png")
		}
		if scan.Progress.Screens != 1 {
			t.Errorf("progress.Screens = %d, want 1", scan.Progress.Screens)
		}
		if len(grabber.grabs) != 1 {
			t.Fatalf("grabber was called %d times, want 1", len(grabber.grabs))
		}
		if grabber.grabs[0].Username != screenUser {
			t.Errorf("grabber received user %q, want %q", grabber.grabs[0].Username, screenUser)
		}
	})

	t.Run("grabber unavailable", func(t *testing.T) {
		grabber := &fakeGrabber{grabErr: screenshot.ErrGrabberUnavailable}
		auth := &fakeAuthenticator{validUser: screenUser, validSecrt: screenPass}
		env := newTestEnv(t, auth, grabber)
		env.setWordlist(userList, []string{screenUser})
		env.setWordlist(passList, []string{screenPass})
		env.gather.script(screenAddr, rdp.GatherResult{
			Service: model.ServiceInfo{NegotiatedProtocol: rdp.ProtocolRDP, NLARequired: true},
		}, nil)

		opts := baseOptions()
		opts.EnableAuth = true
		opts.EnableScreens = true
		opts.Acknowledged = true
		opts.MaxAuthFailures = 3
		opts.UserWordlist = userList
		opts.PasswordWordlist = passList
		scan := env.newScan(t, "screenshot-unavailable", opts)

		runWithWatchdog(t, env, context.Background(), scan, []model.Endpoint{{Address: screenAddr, Port: 3389}})

		shots, err := env.store.ListScreenshots(scan.ID)
		if err != nil {
			t.Fatalf("list screenshots: %v", err)
		}
		if len(shots) != 0 {
			t.Fatalf("stored %d screenshots after ErrGrabberUnavailable, want 0", len(shots))
		}
		if scan.Status != model.ScanCompleted {
			t.Errorf("scan status = %q, want %q (run must complete despite capture failure)", scan.Status, model.ScanCompleted)
		}
		if scan.Progress.Screens != 0 {
			t.Errorf("progress.Screens = %d, want 0", scan.Progress.Screens)
		}
	})
}

// TestRunRefusesAuthWithoutAcknowledgement is a safety guardrail: without the
// operator acknowledgement the engine must not attempt a single login and must
// not persist any credential.
func TestRunRefusesAuthWithoutAcknowledgement(t *testing.T) {
	const authAddr = "10.0.0.30"

	auth := &fakeAuthenticator{validUser: "admin", validSecrt: "s3cret"}
	env := newTestEnv(t, auth, nil)
	env.setWordlist("users.txt", []string{"admin"})
	env.setWordlist("passwords.txt", []string{"s3cret"})
	env.gather.script(authAddr, rdp.GatherResult{
		Service: model.ServiceInfo{NegotiatedProtocol: rdp.ProtocolRDP, NLARequired: true},
	}, nil)

	opts := baseOptions()
	opts.EnableAuth = true // intrusive stage requested but NOT acknowledged
	opts.Acknowledged = false
	opts.MaxAuthFailures = 2
	opts.UserWordlist = "users.txt"
	opts.PasswordWordlist = "passwords.txt"
	scan := env.newScan(t, "auth-without-acknowledgement", opts)

	runWithWatchdog(t, env, context.Background(), scan, []model.Endpoint{{Address: authAddr, Port: 3389}})

	if n := auth.attemptCount(); n != 0 {
		t.Errorf("authenticator was called %d times, want 0 without acknowledgement", n)
	}
	creds, err := env.store.ListCredentials(scan.ID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("stored %d credentials, want 0 without acknowledgement", len(creds))
	}
	if n := env.wordlistCallCount(); n != 0 {
		t.Errorf("wordlists were loaded %d times, want 0 without acknowledgement", n)
	}
	if scan.Progress.Creds != 0 {
		t.Errorf("progress.Creds = %d, want 0", scan.Progress.Creds)
	}
}

// TestRunCancellation checks that a cancelled context stops the run promptly
// and records the scan as cancelled.
func TestRunCancellation(t *testing.T) {
	t.Run("cancelled before Run", func(t *testing.T) {
		env := newTestEnv(t, nil, nil)
		scan := env.newScan(t, "cancelled-before", baseOptions())

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		runWithWatchdog(t, env, ctx, scan, []model.Endpoint{{Address: "10.0.0.40", Port: 3389}})

		if scan.Status != model.ScanCancelled {
			t.Errorf("scan status = %q, want %q", scan.Status, model.ScanCancelled)
		}
	})

	t.Run("cancelled while gathering", func(t *testing.T) {
		env := newTestEnv(t, nil, nil)
		gatherStarted := make(chan struct{}, 1)
		env.gather.setHook(func(ctx context.Context, ep model.Endpoint) (rdp.GatherResult, error) {
			select {
			case gatherStarted <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return rdp.GatherResult{}, ctx.Err()
		})
		scan := env.newScan(t, "cancelled-during", baseOptions())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		go func() {
			env.engine.Run(ctx, scan, []model.Endpoint{{Address: "10.0.0.41", Port: 3389}})
			close(done)
		}()

		select {
		case <-gatherStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("gather was never invoked")
		}
		cancel()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return promptly after cancellation")
		}
		if scan.Status != model.ScanCancelled {
			t.Errorf("scan status = %q, want %q", scan.Status, model.ScanCancelled)
		}
		if scan.FinishedAt == nil {
			t.Error("cancelled scan is missing finished_at")
		}
	})
}

// TestRunPublishesLifecycleEvents checks the event stream shape: the run starts
// with scan.started, reports every host with host.done and ends with
// scan.finished.
func TestRunPublishesLifecycleEvents(t *testing.T) {
	const (
		closedAddr   = "10.0.0.50"
		filteredAddr = "10.0.0.51"
	)

	env := newTestEnv(t, nil, nil)
	env.gather.script(closedAddr, rdp.GatherResult{}, fmt.Errorf("dial tcp: %w", rdp.ErrNetwork))
	env.gather.script(filteredAddr, rdp.GatherResult{}, fmt.Errorf("read tcp: %w", rdp.ErrTimeout))

	scan := env.newScan(t, "lifecycle-events", baseOptions())

	sub := env.hub.Subscribe("")
	t.Cleanup(sub.Close)

	endpoints := []model.Endpoint{
		{Address: closedAddr, Port: 3389},
		{Address: filteredAddr, Port: 3389},
	}
	runWithWatchdog(t, env, context.Background(), scan, endpoints)

	evs := drainEvents(sub)
	if n := sub.Dropped(); n != 0 {
		t.Fatalf("subscription dropped %d events, event stream is incomplete", n)
	}
	if len(evs) < len(endpoints)+2 {
		t.Fatalf("got %d events, want at least %d (started + hosts + finished)", len(evs), len(endpoints)+2)
	}
	if evs[0].Type != model.EventScanStarted {
		t.Errorf("first event = %q, want %q", evs[0].Type, model.EventScanStarted)
	}
	if last := evs[len(evs)-1].Type; last != model.EventScanFinished {
		t.Errorf("last event = %q, want %q", last, model.EventScanFinished)
	}

	hostDone := 0
	for _, ev := range evs {
		if ev.ScanID != scan.ID {
			t.Errorf("event %s carries scan id %q, want %q", ev.Type, ev.ScanID, scan.ID)
		}
		if ev.Type == model.EventHostDone {
			hostDone++
		}
	}
	if hostDone != len(endpoints) {
		t.Errorf("got %d host.done events, want %d", hostDone, len(endpoints))
	}
}

// TestRunOpenHostSkipsSyntheticEvidenceWhenLoginUIUnavailable verifies that
// NLA/blocked hosts do not get a synthetic detection PNG in the gallery.
func TestRunOpenHostSkipsSyntheticEvidenceWhenLoginUIUnavailable(t *testing.T) {
	const addr = "192.168.52.112"
	dir := t.TempDir()
	env := newTestEnv(t, nil, nil)
	env.engine.deps.OpenEvidence = screenshot.NewEvidenceGrabber(dir)
	env.engine.deps.LoginScreen = stubLoginScreen{err: errors.New("HYBRID required")}
	env.gather.script(addr, rdp.GatherResult{
		Service: model.ServiceInfo{
			NegotiatedProtocol: rdp.ProtocolHybrid,
			NLARequired:        true,
			TLSVersion:         "TLS 1.2",
			OSGuess:            "Windows",
		},
	}, nil)

	opts := baseOptions()
	opts.EnableAuth = false
	opts.EnableScreens = false
	scan := env.newScan(t, "open-host-no-synthetic", opts)
	runWithWatchdog(t, env, context.Background(), scan, []model.Endpoint{{Address: addr, Port: 3389}})

	shots, err := env.store.ListScreenshots(scan.ID)
	if err != nil {
		t.Fatalf("list screenshots: %v", err)
	}
	if len(shots) != 0 {
		t.Fatalf("stored %d screenshots, want 0 (no synthetic detection card)", len(shots))
	}
	if scan.Progress.Screens != 0 {
		t.Errorf("progress.Screens = %d, want 0", scan.Progress.Screens)
	}
}

type stubLoginScreen struct {
	shot model.Screenshot
	err  error
}

func (s stubLoginScreen) Available() error { return nil }
func (s stubLoginScreen) GrabLoginScreen(context.Context, model.Endpoint) (model.Screenshot, error) {
	return s.shot, s.err
}

// TestRunPrefersLoginScreenCapture verifies TLS login-screen grabs win over
// the evidence-card fallback when FreeRDP tooling is wired.
func TestRunPrefersLoginScreenCapture(t *testing.T) {
	const addr = "192.168.112.76"
	dir := t.TempDir()
	out := filepath.Join(dir, "login.png")
	if err := os.WriteFile(out, []byte("png"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := newTestEnv(t, nil, nil)
	env.engine.deps.LoginScreen = stubLoginScreen{
		shot: model.Screenshot{
			Address: addr, Port: 3389, Username: screenshot.LoginScreenLabel,
			FilePath: out, Width: 1024, Height: 768, CapturedAt: time.Now().UTC(),
		},
	}
	env.engine.deps.OpenEvidence = screenshot.NewEvidenceGrabber(dir)
	// HYBRID_EX / NLARequired from gather must still try FreeRDP /sec:tls —
	// many labs accept forced TLS Winlogon even when preferred nego is HYBRID.
	env.gather.script(addr, rdp.GatherResult{
		Service: model.ServiceInfo{
			NegotiatedProtocol: rdp.ProtocolHybridEx,
			NLARequired:        true,
			TLSVersion:         "TLS 1.2",
		},
	}, nil)

	opts := baseOptions()
	opts.EnableAuth = false
	scan := env.newScan(t, "login-screen", opts)
	runWithWatchdog(t, env, context.Background(), scan, []model.Endpoint{{Address: addr, Port: 3389}})

	shots, err := env.store.ListScreenshots(scan.ID)
	if err != nil {
		t.Fatalf("list screenshots: %v", err)
	}
	if len(shots) != 1 {
		t.Fatalf("stored %d screenshots, want 1", len(shots))
	}
	if shots[0].Username != screenshot.LoginScreenLabel {
		t.Fatalf("username = %q, want %q", shots[0].Username, screenshot.LoginScreenLabel)
	}
	hosts, err := env.store.ListHosts(scan.ID)
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Service == nil {
		t.Fatalf("hosts = %+v", hosts)
	}
	if hosts[0].Service.Evidence["login_screen"] != "ssl-tls" {
		t.Fatalf("evidence = %#v", hosts[0].Service.Evidence)
	}
}

// TestRunLoginScreenFailureStoresNoScreenshot ensures a FreeRDP failure does
// not invent a synthetic detection card for the gallery.
func TestRunLoginScreenFailureStoresNoScreenshot(t *testing.T) {
	const addr = "10.0.0.76"
	dir := t.TempDir()
	env := newTestEnv(t, nil, nil)
	env.engine.deps.LoginScreen = stubLoginScreen{err: errors.New("freerdp failed")}
	env.engine.deps.OpenEvidence = screenshot.NewEvidenceGrabber(dir)
	env.gather.script(addr, rdp.GatherResult{
		Service: model.ServiceInfo{NegotiatedProtocol: rdp.ProtocolSSL, NLARequired: false},
	}, nil)

	opts := baseOptions()
	opts.EnableAuth = false
	scan := env.newScan(t, "login-screen-no-fallback", opts)
	runWithWatchdog(t, env, context.Background(), scan, []model.Endpoint{{Address: addr, Port: 3389}})

	shots, err := env.store.ListScreenshots(scan.ID)
	if err != nil {
		t.Fatalf("list screenshots: %v", err)
	}
	if len(shots) != 0 {
		t.Fatalf("shots = %+v, want none", shots)
	}
}
