// Package events provides a bounded publish/subscribe hub used to stream live
// scan progress to consumers such as the web UI (Server-Sent Events).
package events

import (
	"sync"
	"sync/atomic"

	"rdpshot/internal/model"
)

// defaultBuffer is the per-subscriber queue depth. A slow subscriber drops
// events instead of blocking scan execution.
const defaultBuffer = 256

// Hub broadcasts events to all matching subscribers.
type Hub struct {
	mu      sync.RWMutex
	subs    map[*Subscription]struct{}
	closed  bool
	bufSize int
}

// NewHub creates a hub whose subscriber queues hold up to buffer events
// (values <= 0 select the default).
func NewHub(buffer int) *Hub {
	if buffer <= 0 {
		buffer = defaultBuffer
	}
	return &Hub{subs: make(map[*Subscription]struct{}), bufSize: buffer}
}

// Subscription is one event consumer.
type Subscription struct {
	scanID  string
	ch      chan model.Event
	hub     *Hub
	closed  bool
	dropped atomic.Int64
}

// C is the receive-only event stream of the subscription.
func (s *Subscription) C() <-chan model.Event { return s.ch }

// Dropped reports how many events were discarded because the queue was full.
func (s *Subscription) Dropped() int64 { return s.dropped.Load() }

// Close unsubscribes and releases the queue. It is safe to call more than once.
func (s *Subscription) Close() {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	s.closeLocked()
}

// closeLocked releases the queue; callers must hold hub.mu. Closing twice is
// prevented by the closed flag so hub and subscriber shutdown cannot race.
func (s *Subscription) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	delete(s.hub.subs, s)
	close(s.ch)
}

// Subscribe registers a consumer. An empty scanID subscribes to every scan.
// The caller must Close the subscription to release resources.
func (h *Hub) Subscribe(scanID string) *Subscription {
	sub := &Subscription{
		scanID: scanID,
		ch:     make(chan model.Event, h.bufSize),
		hub:    h,
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		sub.closed = true
		close(sub.ch)
		return sub
	}
	h.subs[sub] = struct{}{}
	return sub
}

// Publish delivers ev to every matching subscriber without blocking. Events
// for a subscriber whose queue is full are dropped and counted.
func (h *Hub) Publish(ev model.Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		return
	}
	for sub := range h.subs {
		if sub.scanID != "" && sub.scanID != ev.ScanID {
			continue
		}
		select {
		case sub.ch <- ev:
		default:
			sub.dropped.Add(1)
		}
	}
}

// Close shuts the hub down and closes every subscriber channel.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for sub := range h.subs {
		sub.closeLocked()
	}
}
