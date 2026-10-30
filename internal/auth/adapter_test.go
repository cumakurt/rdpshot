package auth

import (
	"context"
	"errors"
	"testing"

	"rdpshot/internal/brute"
	"rdpshot/internal/model"
)

type stubAuth struct {
	err error
}

func (s stubAuth) Authenticate(context.Context, model.Endpoint, model.Credential) error {
	return s.err
}

func TestBruteAdapterMapsNLARequired(t *testing.T) {
	err := BruteAdapter{Inner: stubAuth{err: ErrNLARequired}}.Authenticate(
		context.Background(),
		model.Endpoint{Address: "10.0.0.1", Port: 3389},
		model.Credential{Username: "u", Secret: "p"},
	)
	if !errors.Is(err, brute.ErrCredSSPUnavailable) {
		t.Fatalf("err = %v, want ErrCredSSPUnavailable", err)
	}
}

func TestBruteAdapterMapsAuthFailed(t *testing.T) {
	err := BruteAdapter{Inner: stubAuth{err: ErrAuthFailed}}.Authenticate(
		context.Background(),
		model.Endpoint{Address: "10.0.0.1", Port: 3389},
		model.Credential{Username: "u", Secret: "p"},
	)
	if !errors.Is(err, brute.ErrInvalidCredential) {
		t.Fatalf("err = %v, want ErrInvalidCredential", err)
	}
}
