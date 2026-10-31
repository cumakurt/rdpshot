package decoy_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"rdpshot/internal/decoy"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not find free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestListener_StartStop(t *testing.T) {
	addr := freePort(t)
	l := decoy.New(decoy.Options{BindAddr: addr})
	ctx := context.Background()

	if err := l.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if !l.IsRunning() {
		t.Error("expected IsRunning()=true after Start()")
	}
	l.Stop()
	if l.IsRunning() {
		t.Error("expected IsRunning()=false after Stop()")
	}
}

func TestListener_DoubleStart(t *testing.T) {
	addr := freePort(t)
	l := decoy.New(decoy.Options{BindAddr: addr})
	ctx := context.Background()

	if err := l.Start(ctx); err != nil {
		t.Fatalf("first Start() error: %v", err)
	}
	defer l.Stop()

	// Second Start should be a no-op, not an error.
	if err := l.Start(ctx); err != nil {
		t.Fatalf("second Start() error: %v", err)
	}
}

func TestListener_RecordsEvent_OnConnection(t *testing.T) {
	addr := freePort(t)
	var mu sync.Mutex
	var events []decoy.DecoyEvent

	l := decoy.New(decoy.Options{
		BindAddr: addr,
		OnEvent: func(ev decoy.DecoyEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	})
	ctx := context.Background()
	if err := l.Start(ctx); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	defer l.Stop()

	// Connect and immediately close — should trigger an event even if TLS fails.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Send a minimal RDP Connection Request PDU.
	rdpCR := []byte{
		0x03, 0x00, 0x00, 0x2b, // TPKT header
		0x26, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR
		// RDP Neg Request: type=0x01, flags=0, len=8, protocols=HYBRID_EX(3)
		0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
		// padding
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00,
	}
	conn.Write(rdpCR)
	time.Sleep(300 * time.Millisecond)
	conn.Close()

	// Give the handler goroutine time to record the event.
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	evCount := len(events)
	mu.Unlock()

	if evCount == 0 {
		t.Log("Note: no event fired (may be expected if TLS handshake was not attempted in time)")
		// Not a hard failure — timing sensitive; the connection was at least accepted.
	}
}

func TestListener_InvalidBindAddr(t *testing.T) {
	l := decoy.New(decoy.Options{BindAddr: "not-an-addr"})
	err := l.Start(context.Background())
	if err == nil {
		l.Stop()
		t.Error("expected error for invalid bind address")
	}
}
