package events

import (
	"testing"
	"time"

	"rdpshot/internal/model"
)

func publishAndWait(t *testing.T, hub *Hub, ev model.Event) model.Event {
	t.Helper()
	hub.Publish(ev)
	return ev
}

func TestHubBroadcast(t *testing.T) {
	hub := NewHub(0)
	defer hub.Close()
	sub := hub.Subscribe("")
	defer sub.Close()

	ev := model.Event{Type: model.EventScanProgress, ScanID: "s1", At: time.Now()}
	publishAndWait(t, hub, ev)

	select {
	case got := <-sub.C():
		if got.ScanID != "s1" || got.Type != model.EventScanProgress {
			t.Fatalf("unexpected event: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestHubFiltersByScan(t *testing.T) {
	hub := NewHub(0)
	defer hub.Close()
	sub := hub.Subscribe("s1")
	defer sub.Close()

	hub.Publish(model.Event{Type: model.EventLog, ScanID: "other"})
	hub.Publish(model.Event{Type: model.EventLog, ScanID: "s1"})

	select {
	case got := <-sub.C():
		if got.ScanID != "s1" {
			t.Fatalf("received foreign scan event: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
	select {
	case got := <-sub.C():
		t.Fatalf("unexpected extra event: %+v", got)
	default:
	}
}

func TestHubDropsWhenFull(t *testing.T) {
	hub := NewHub(1)
	defer hub.Close()
	sub := hub.Subscribe("")
	defer sub.Close()

	for i := 0; i < 5; i++ {
		hub.Publish(model.Event{Type: model.EventLog, ScanID: "s"})
	}
	if got := sub.Dropped(); got != 4 {
		t.Fatalf("dropped = %d, want 4", got)
	}
}

func TestHubCloseReleasesSubscribers(t *testing.T) {
	hub := NewHub(0)
	sub := hub.Subscribe("")
	hub.Close()
	if _, ok := <-sub.C(); ok {
		t.Fatal("expected channel to be closed")
	}
	sub.Close() // must be safe after hub close
}

func TestSubscribeAfterClose(t *testing.T) {
	hub := NewHub(0)
	hub.Close()
	sub := hub.Subscribe("")
	defer sub.Close()
	if _, ok := <-sub.C(); ok {
		t.Fatal("expected closed channel for late subscription")
	}
}
