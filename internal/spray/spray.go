// Package spray implements a domain-aware "Low & Slow" password spraying
// engine.  It tracks per-account failure counters, respects domain lockout
// policies, and automatically moves accounts into a cooldown queue when they
// approach the bad-attempt threshold.
//
// Usage pattern:
//
//	policy := spray.DomainPolicy{MaxBadAttempts: 5, ObservationWindowSec: 1800, LockoutDurationSec: 1800}
//	opts   := spray.Options{Mode: spray.ModeLowSlow, DelayBetweenSpraysSec: 30, MaxGlobalFailures: 20}
//	eng    := spray.New(auth, policy, opts, hooks, logger)
//	result, err := eng.RunSpray(ctx, endpoints, candidates)
package spray

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"rdpshot/internal/model"
)

// SprayMode controls the cadence of the spray.
type SprayMode string

const (
	// ModeLowSlow fires one password per spray round across all accounts,
	// waiting DelayBetweenSpraysSec between rounds.  Minimal lockout risk.
	ModeLowSlow SprayMode = "low_slow"
	// ModeAggressive fires passwords as fast as the rate limiter allows.
	// Intended for internal-network engagements where lockout is irrelevant.
	ModeAggressive SprayMode = "aggressive"
)

// DomainPolicy holds the observed or operator-supplied AD lockout policy.
// Set MaxBadAttempts=0 to disable the per-account fail-safe.
type DomainPolicy struct {
	// MaxBadAttempts is the domain threshold before an account locks (e.g. 5).
	// The tracker will stop attempting an account when it has (MaxBadAttempts-1)
	// failures to leave a one-attempt safety margin.
	MaxBadAttempts int `json:"max_bad_attempts"`
	// ObservationWindowSec is the sliding window (seconds) the DC uses to count
	// bad attempts.  After this period the counter resets.
	ObservationWindowSec int `json:"observation_window_sec"`
	// LockoutDurationSec is how long a locked account stays locked.
	// Used to set cooldown timers.
	LockoutDurationSec int `json:"lockout_duration_sec"`
}

// safeLimit returns the safe maximum attempts per account per window.
// We always stop one attempt *before* the threshold.
func (p DomainPolicy) safeLimit() int {
	if p.MaxBadAttempts <= 0 {
		return 0 // unlimited
	}
	safe := p.MaxBadAttempts - 1
	if safe < 1 {
		return 1
	}
	return safe
}

// Options tunes the spray engine.
type Options struct {
	Mode SprayMode `json:"mode"`
	// DelayBetweenSpraysSec is the pause between spray rounds (Low & Slow mode).
	DelayBetweenSpraysSec int `json:"delay_between_sprays_sec"`
	// MaxGlobalFailures aborts the entire spray after this many total failures
	// across all accounts. 0 disables.
	MaxGlobalFailures int `json:"max_global_failures"`
}

func (o Options) withDefaults() Options {
	if o.Mode == "" {
		o.Mode = ModeLowSlow
	}
	if o.DelayBetweenSpraysSec <= 0 {
		o.DelayBetweenSpraysSec = 30
	}
	return o
}

// SprayResult summarises a completed spray operation.
type SprayResult struct {
	ValidCreds     []model.Credential `json:"valid_creds"`
	TotalAttempts  int                `json:"total_attempts"`
	TotalFailures  int                `json:"total_failures"`
	LockedAccounts []string           `json:"locked_accounts,omitempty"`
	CooledAccounts []string           `json:"cooled_accounts,omitempty"`
	StoppedReason  string             `json:"stopped_reason,omitempty"`
}

// Hooks are optional progress callbacks.
type Hooks struct {
	OnSuccess func(ep model.Endpoint, cred model.Credential)
	OnFailure func(ep model.Endpoint, cred model.Credential, err error)
	OnCooldown func(username string, remaining time.Duration)
	OnStatus   func(status StatusSnapshot)
}

// StatusSnapshot is a point-in-time view of the spray progress.
type StatusSnapshot struct {
	Round          int            `json:"round"`
	TotalAttempts  int            `json:"total_attempts"`
	TotalFailures  int            `json:"total_failures"`
	ValidCreds     int            `json:"valid_creds"`
	ActiveAccounts int            `json:"active_accounts"`
	CooledAccounts int            `json:"cooled_accounts"`
	AccountCounters map[string]int `json:"account_counters,omitempty"`
}

// Authenticator matches brute.Authenticator so the same auth backend is reused.
type Authenticator interface {
	Authenticate(ctx context.Context, ep model.Endpoint, cred model.Credential) error
}

// ErrInvalidCredential mirrors brute.ErrInvalidCredential (re-declared to
// avoid the import cycle).
var ErrInvalidCredential = fmt.Errorf("invalid credentials")

// ─────────────────────────────────────────────────────────────────────────────
// Lockout tracker
// ─────────────────────────────────────────────────────────────────────────────

type accountState struct {
	mu           sync.Mutex
	failures     int
	windowStart  time.Time
	cooldownUntil time.Time
}

func (a *accountState) isInCooldown(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return now.Before(a.cooldownUntil)
}

func (a *accountState) remainingCooldown(now time.Time) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Before(a.cooldownUntil) {
		return a.cooldownUntil.Sub(now)
	}
	return 0
}

func (a *accountState) recordFailure(policy DomainPolicy, now time.Time) (startCooldown bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Reset window if it has elapsed.
	windowDur := time.Duration(policy.ObservationWindowSec) * time.Second
	if windowDur > 0 && now.Sub(a.windowStart) >= windowDur {
		a.failures = 0
		a.windowStart = now
	}
	a.failures++

	limit := policy.safeLimit()
	if limit > 0 && a.failures >= limit {
		lockDur := time.Duration(policy.LockoutDurationSec) * time.Second
		if lockDur <= 0 {
			lockDur = 30 * time.Minute
		}
		a.cooldownUntil = now.Add(lockDur)
		return true
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────────────────────

// Engine is the smart spray controller.
type Engine struct {
	auth    Authenticator
	policy  DomainPolicy
	opts    Options
	hooks   Hooks
	logger  *slog.Logger
	sleep   func(time.Duration)
}

// New creates a new spray Engine.
func New(auth Authenticator, policy DomainPolicy, opts Options, hooks Hooks, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		auth:   auth,
		policy: policy,
		opts:   opts.withDefaults(),
		hooks:  hooks,
		logger: logger,
		sleep:  time.Sleep,
	}
}

// RunSpray executes a password spray across multiple endpoints.
// In ModeLowSlow it fires one password per round across all endpoints then waits;
// in ModeAggressive it fires all passwords immediately.
func (e *Engine) RunSpray(ctx context.Context, endpoints []model.Endpoint, candidates []model.Credential) (SprayResult, error) {
	var result SprayResult
	if len(endpoints) == 0 || len(candidates) == 0 {
		result.StoppedReason = "no endpoints or candidates"
		return result, nil
	}

	// Build per-account state tracker.
	states := map[string]*accountState{}
	statesMu := sync.Mutex{}
	getState := func(username string) *accountState {
		statesMu.Lock()
		defer statesMu.Unlock()
		if states[username] == nil {
			states[username] = &accountState{windowStart: time.Now()}
		}
		return states[username]
	}

	var mu sync.Mutex // protects result fields
	globalFailures := 0

	tryAttempt := func(ep model.Endpoint, cand model.Credential) (stop bool) {
		if err := ctx.Err(); err != nil {
			return true
		}

		st := getState(cand.Username)
		now := time.Now()
		if st.isInCooldown(now) {
			remaining := st.remainingCooldown(now)
			if e.hooks.OnCooldown != nil {
				e.hooks.OnCooldown(cand.Username, remaining)
			}
			return false // skip, not a fatal stop
		}

		err := e.auth.Authenticate(ctx, ep, cand)
		mu.Lock()
		result.TotalAttempts++
		mu.Unlock()

		if err == nil {
			// Success
			cred := model.Credential{
				ScanID:     cand.ScanID,
				Address:    ep.Address,
				Port:       ep.Port,
				Username:   cand.Username,
				Domain:     cand.Domain,
				Method:     cand.Method,
				VerifiedAt: time.Now(),
			}
			mu.Lock()
			result.ValidCreds = append(result.ValidCreds, cred)
			mu.Unlock()
			if e.hooks.OnSuccess != nil {
				e.hooks.OnSuccess(ep, cred)
			}
			return false
		}

		// Classify the error
		errStr := err.Error()
		isLockout := containsAny(errStr, "locked", "disabled", "lockout")
		isInvalid := containsAny(errStr, "invalid", "wrong", "authentication failure", "logon failure")

		if isLockout {
			mu.Lock()
			result.LockedAccounts = appendUniq(result.LockedAccounts, cand.Username)
			mu.Unlock()
			e.logger.Warn("spray: account locked", "user", cand.Username, "host", ep.Address)
			return false
		}

		if isInvalid || err != nil {
			mu.Lock()
			result.TotalFailures++
			globalFailures++
			tooMany := e.opts.MaxGlobalFailures > 0 && globalFailures >= e.opts.MaxGlobalFailures
			mu.Unlock()

			// Record per-account failure.
			enteredCooldown := st.recordFailure(e.policy, time.Now())
			if enteredCooldown {
				mu.Lock()
				result.CooledAccounts = appendUniq(result.CooledAccounts, cand.Username)
				mu.Unlock()
				e.logger.Info("spray: account entering cooldown", "user", cand.Username,
					"cooldown_remaining", st.remainingCooldown(time.Now()))
			}

			if e.hooks.OnFailure != nil {
				e.hooks.OnFailure(ep, cand, err)
			}
			if tooMany {
				mu.Lock()
				result.StoppedReason = fmt.Sprintf("max global failures (%d) reached", e.opts.MaxGlobalFailures)
				mu.Unlock()
				return true // stop entire spray
			}
		}
		return false
	}

	switch e.opts.Mode {
	case ModeAggressive:
		// Fire every password × every endpoint immediately.
		for _, cand := range candidates {
			for _, ep := range endpoints {
				if stop := tryAttempt(ep, cand); stop {
					return result, nil
				}
			}
		}

	default: // ModeLowSlow
		// Spray one password per round across all endpoints; wait between rounds.
		for round, cand := range candidates {
			for _, ep := range endpoints {
				if stop := tryAttempt(ep, cand); stop {
					return result, nil
				}
			}
			if e.hooks.OnStatus != nil {
				statesMu.Lock()
				counters := make(map[string]int, len(states))
				cooled := 0
				for u, st := range states {
					st.mu.Lock()
					counters[u] = st.failures
					if time.Now().Before(st.cooldownUntil) {
						cooled++
					}
					st.mu.Unlock()
				}
				statesMu.Unlock()
				mu.Lock()
				snap := StatusSnapshot{
					Round:          round + 1,
					TotalAttempts:  result.TotalAttempts,
					TotalFailures:  result.TotalFailures,
					ValidCreds:     len(result.ValidCreds),
					ActiveAccounts: len(candidates),
					CooledAccounts: cooled,
					AccountCounters: counters,
				}
				mu.Unlock()
				e.hooks.OnStatus(snap)
			}
			// Only sleep between rounds if there are more to go.
			if round < len(candidates)-1 {
				delay := time.Duration(e.opts.DelayBetweenSpraysSec) * time.Second
				select {
				case <-ctx.Done():
					result.StoppedReason = "cancelled"
					return result, ctx.Err()
				case <-time.After(delay):
				}
			}
		}
	}

	return result, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

func containsAny(s string, substrs ...string) bool {
	lower := toLower(s)
	for _, sub := range substrs {
		if len(lower) >= len(sub) {
			for i := 0; i <= len(lower)-len(sub); i++ {
				if lower[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func appendUniq(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}
