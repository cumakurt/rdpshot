// Package brute implements the bounded, fail-safe credential audit engine.
//
// Intrusive by design, it only runs when the operator explicitly enabled it and
// confirmed authorisation. Per-host attempt limits and lockout detection keep
// the audit from triggering account lockouts on the target.
package brute

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"rdpshot/internal/model"
)

// Authenticator verifies a single credential against one endpoint.
//
// Implementations must return ErrInvalidCredential for a rejected login,
// ErrLockedOut when the target reports a lockout or disabled account, and any
// other error for transport or protocol failures.
type Authenticator interface {
	Authenticate(ctx context.Context, ep model.Endpoint, cred model.Credential) error
}

// Classified authentication errors.
var (
	// ErrInvalidCredential means the credentials were rejected.
	ErrInvalidCredential = errors.New("invalid credentials")
	// ErrLockedOut means the account is locked or disabled; no further
	// attempts must be made against the target.
	ErrLockedOut = errors.New("account locked or disabled")
)

// Options tunes the credential audit.
type Options struct {
	// MaxFailuresPerHost stops the audit against one endpoint after this many
	// rejected logins (fail-safe). Values <= 0 select the default of 5.
	MaxFailuresPerHost int
	// Delay is the base pause between attempts.
	Delay time.Duration
	// Jitter adds a random extra pause in [0, Jitter) to avoid burst patterns.
	Jitter time.Duration
}

func (o Options) withDefaults() Options {
	if o.MaxFailuresPerHost <= 0 {
		o.MaxFailuresPerHost = 5
	}
	if o.Delay < 0 {
		o.Delay = 0
	}
	if o.Jitter < 0 {
		o.Jitter = 0
	}
	return o
}

// Result summarises one endpoint audit.
type Result struct {
	Credentials   []model.Credential
	Attempts      int
	Failures      int
	StoppedReason string
	LockedOut     bool
}

// Hooks receive progress callbacks; all fields are optional.
type Hooks struct {
	OnSuccess func(cred model.Credential)
	OnFailure func(cred model.Credential, err error)
}

// Engine runs credential attempts with bounded concurrency by the caller.
type Engine struct {
	auth   Authenticator
	opts   Options
	hooks  Hooks
	logger *slog.Logger
	// sleep is swappable for tests.
	sleep func(time.Duration)
}

// New builds a credential audit engine.
func New(auth Authenticator, opts Options, hooks Hooks, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		auth:   auth,
		opts:   opts.withDefaults(),
		hooks:  hooks,
		logger: logger,
		sleep:  time.Sleep,
	}
}

// Run tries the candidates against one endpoint and stops at the first valid
// credential, on lockout, on cancellation or at the per-host fail-safe limit.
func (e *Engine) Run(ctx context.Context, ep model.Endpoint, hostID int64, scanID string, candidates []model.Credential) (Result, error) {
	var result Result
	if e.auth == nil {
		return result, fmt.Errorf("brute: no authenticator configured")
	}
	maxFailures := e.opts.MaxFailuresPerHost

	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			result.StoppedReason = "cancelled"
			return result, err
		}
		if result.Failures >= maxFailures {
			result.StoppedReason = fmt.Sprintf("fail-safe: %d rejected attempts", result.Failures)
			break
		}

		e.pause()

		cred := candidate
		cred.ScanID = scanID
		cred.HostID = hostID
		cred.Address = ep.Address
		cred.Port = ep.Port
		cred.VerifiedAt = time.Now().UTC()

		err := e.auth.Authenticate(ctx, ep, cred)
		result.Attempts++
		switch {
		case err == nil:
			cred.Method = "credssp-nla"
			result.Credentials = append(result.Credentials, cred)
			if e.hooks.OnSuccess != nil {
				e.hooks.OnSuccess(cred)
			}
			// One verified credential per endpoint is enough to prove access
			// and keeps the audit footprint minimal.
			result.StoppedReason = "valid credential found"
			return result, nil
		case errors.Is(err, ErrLockedOut):
			result.LockedOut = true
			result.StoppedReason = "target reported a locked or disabled account"
			return result, nil
		case errors.Is(err, ErrInvalidCredential):
			result.Failures++
			if e.hooks.OnFailure != nil {
				e.hooks.OnFailure(cred, err)
			}
		default:
			result.StoppedReason = "authentication transport error: " + err.Error()
			return result, err
		}
	}
	if result.StoppedReason == "" {
		result.StoppedReason = "candidate list exhausted"
	}
	return result, nil
}

// pause sleeps for the configured delay plus jitter unless the wait is zero.
func (e *Engine) pause() {
	delay := e.opts.Delay
	if e.opts.Jitter > 0 {
		delay += time.Duration(rand.Int63n(int64(e.opts.Jitter))) //nolint:gosec // jitter does not need crypto randomness
	}
	if delay > 0 {
		e.sleep(delay)
	}
}
