package scanner

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// Limiter is a small token bucket that paces connection attempts. It keeps the
// scanner from bursting into a target network, which would trip rate based
// protections and distort results.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time

	now func() time.Time
}

// NewLimiter creates a limiter allowing rate events per second (<= 0 disables
// limiting). A small random jitter is applied to the wait to avoid synchronised
// bursts across workers.
func NewLimiter(rate float64) *Limiter {
	burst := rate
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:   rate,
		burst:  burst,
		tokens: burst,
		last:   time.Now(),
		now:    time.Now,
	}
}

// Wait blocks until an attempt is permitted or the context is cancelled.
func (l *Limiter) Wait(ctx context.Context) error {
	if l.rate <= 0 {
		return ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		now := l.now()
		elapsed := now.Sub(l.last).Seconds()
		if elapsed > 0 {
			l.tokens += elapsed * l.rate
			if l.tokens > l.burst {
				l.tokens = l.burst
			}
			l.last = now
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()

		// Add up to 10% random jitter so worker wake-ups do not synchronise
		// into bursts.
		wait += time.Duration(rand.Int63n(int64(wait)/10 + 1)) //nolint:gosec // pacing jitter needs no crypto randomness
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
