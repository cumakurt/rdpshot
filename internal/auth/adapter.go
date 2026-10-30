package auth

import (
	"context"
	"errors"
	"fmt"

	"rdpshot/internal/brute"
	"rdpshot/internal/model"
)

// BruteAdapter maps classified auth errors onto the brute.Authenticator
// sentinels expected by the credential audit engine.
type BruteAdapter struct {
	Inner Authenticator
}

// Authenticate implements brute.Authenticator.
func (a BruteAdapter) Authenticate(ctx context.Context, ep model.Endpoint, cred model.Credential) error {
	if a.Inner == nil {
		return fmt.Errorf("auth: no authenticator configured")
	}
	err := a.Inner.Authenticate(ctx, ep, cred)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrAuthFailed), errors.Is(err, ErrSmartCardRequired):
		return fmt.Errorf("%w: %v", brute.ErrInvalidCredential, err)
	case errors.Is(err, ErrAccountLocked):
		return fmt.Errorf("%w: %v", brute.ErrLockedOut, err)
	case errors.Is(err, ErrNLARequired):
		// TLS/RDP-only endpoints cannot complete a CredSSP password audit.
		return fmt.Errorf("%w: %v", brute.ErrCredSSPUnavailable, err)
	default:
		return err
	}
}
