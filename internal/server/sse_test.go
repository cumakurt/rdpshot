package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/model"
)

// TestSSEStreamDeliversEvents publishes on the hub and asserts one event
// reaches the stream. The context timeout guarantees the test cannot hang.
func TestSSEStreamDeliversEvents(t *testing.T) {
	env := newTestEnv(t, Config{})
	ts := httptest.NewServer(env.server.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/events?scan=scan-sse00000000001", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type = %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("cache control = %q", cc)
	}
	if xa := resp.Header.Get("X-Accel-Buffering"); xa != "no" {
		t.Fatalf("x-accel-buffering = %q", xa)
	}

	reader := bufio.NewReader(resp.Body)
	first, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read stream head: %v", err)
	}
	if strings.TrimSpace(first) != "retry: 3000" {
		t.Fatalf("first stream line = %q, want retry: 3000", first)
	}

	// Keep publishing until the stream delivers one matching event; the
	// subscription may register slightly after the response starts.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				env.hub.Publish(model.Event{
					Type:    model.EventScanProgress,
					ScanID:  "scan-sse00000000001",
					At:      time.Now().UTC(),
					Payload: model.Progress{Done: 1, Total: 2},
				})
			}
		}
	}()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read stream event: %v", err)
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev model.Event
		if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data: "))), &ev); err != nil {
			t.Fatalf("decode event %q: %v", line, err)
		}
		if ev.Type != model.EventScanProgress {
			t.Fatalf("event type = %q", ev.Type)
		}
		if ev.ScanID != "scan-sse00000000001" {
			t.Fatalf("event scan id = %q", ev.ScanID)
		}
		return
	}
}

// TestSSEScanFilter checks that a scan-scoped stream ignores other scans.
func TestSSEScanFilter(t *testing.T) {
	env := newTestEnv(t, Config{})
	ts := httptest.NewServer(env.server.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/events?scan=scan-filter00000001", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer resp.Body.Close()

	// Publish a foreign event followed by a matching one. Only the matching
	// one may be delivered: the subscription is registered before the response
	// headers reach the client.
	env.hub.Publish(model.Event{Type: model.EventLog, ScanID: "scan-other0000000001",
		At: time.Now().UTC(), Payload: model.LogPayload{Level: "info", Message: "foreign"}})
	env.hub.Publish(model.Event{Type: model.EventScanFinished, ScanID: "scan-filter00000001",
		At: time.Now().UTC(), Payload: model.Progress{Done: 2, Total: 2}})

	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read stream event: %v", err)
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev model.Event
		if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data: "))), &ev); err != nil {
			t.Fatalf("decode event %q: %v", line, err)
		}
		if ev.ScanID != "scan-filter00000001" {
			t.Fatalf("stream leaked an event for scan %q", ev.ScanID)
		}
		if ev.Type != model.EventScanFinished {
			t.Fatalf("event type = %q", ev.Type)
		}
		return
	}
}
