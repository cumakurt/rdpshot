package scanner

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// virtualClock is a deterministic stand-in for time.Now in limiter tests. It
// returns base for the first hold calls and jumps forward by step on every
// call afterwards so the tests control exactly when the bucket refills.
type virtualClock struct {
	mu    sync.Mutex
	base  time.Time
	calls int
	hold  int
	step  time.Duration
}

func (c *virtualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls <= c.hold {
		return c.base
	}
	return c.base.Add(time.Duration(c.calls-c.hold) * c.step)
}

// TestLimiterAllowsBurstThenPaces verifies that a rate of 2/s admits the first
// two attempts without delay and paces the third one by about one token
// interval (500ms plus up to 10% random jitter).
func TestLimiterAllowsBurstThenPaces(t *testing.T) {
	const rate = 2 // tokens per second, burst 2

	clock := &virtualClock{base: time.Now(), hold: 3, step: time.Second}

	lim := NewLimiter(rate)
	lim.now = clock.Now
	lim.last = clock.base // align the bucket with the virtual clock

	ctx := context.Background()

	// The first two calls consume the burst and must not wait.
	for i := 0; i < 2; i++ {
		start := time.Now()
		if err := lim.Wait(ctx); err != nil {
			t.Fatalf("Wait #%d returned error: %v", i+1, err)
		}
		if elapsed := time.Since(start); elapsed >= 100*time.Millisecond {
			t.Fatalf("Wait #%d took %v, want no measurable delay (burst token)", i+1, elapsed)
		}
	}

	// The third call must block for one token interval: the computed wait is
	// 500ms plus up to 10% random jitter. The upper bound catches gross
	// over-waiting such as a full extra refill period.
	start := time.Now()
	if err := lim.Wait(ctx); err != nil {
		t.Fatalf("third Wait returned error: %v", err)
	}
	elapsed := time.Since(start)
	const (
		minWait = 500 * time.Millisecond
		maxWait = 1 * time.Second
	)
	if elapsed < minWait {
		t.Fatalf("third Wait took %v, want at least %v (one token interval)", elapsed, minWait)
	}
	if elapsed >= maxWait {
		t.Fatalf("third Wait took %v, want less than %v (500ms + up to 10%% jitter)", elapsed, maxWait)
	}
}

// TestLimiterDisabled verifies that a non-positive rate disables pacing and
// returns immediately.
func TestLimiterDisabled(t *testing.T) {
	for _, rate := range []float64{0, -1} {
		lim := NewLimiter(rate)

		start := time.Now()
		for i := 0; i < 5; i++ {
			if err := lim.Wait(context.Background()); err != nil {
				t.Fatalf("rate %v: Wait #%d returned error: %v", rate, i+1, err)
			}
		}
		if elapsed := time.Since(start); elapsed >= 100*time.Millisecond {
			t.Fatalf("rate %v: five Wait calls took %v, want immediate return", rate, elapsed)
		}
	}
}

// TestLimiterRespectsCancellation verifies that Wait returns context.Canceled
// promptly, both when the context is already cancelled and when cancellation
// lands while Wait is pacing. A watchdog turns a hang into a test failure.
func TestLimiterRespectsCancellation(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		lim := NewLimiter(2)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		done := make(chan error, 1)
		go func() { done <- lim.Wait(ctx) }()

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Wait error = %v, want context.Canceled", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Wait did not return promptly on a cancelled context")
		}
	})

	t.Run("cancelled while pacing", func(t *testing.T) {
		// The frozen virtual clock keeps the bucket empty so Wait is
		// guaranteed to sit in its pacing timer when the cancel arrives.
		clock := &virtualClock{base: time.Now(), hold: 1 << 30}
		lim := NewLimiter(2)
		lim.now = clock.Now
		lim.last = clock.base

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Drain the burst so the next Wait has to pace.
		for i := 0; i < 2; i++ {
			if err := lim.Wait(ctx); err != nil {
				t.Fatalf("burst Wait #%d returned error: %v", i+1, err)
			}
		}

		done := make(chan error, 1)
		go func() { done <- lim.Wait(ctx) }()
		time.AfterFunc(50*time.Millisecond, cancel)

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Wait error = %v, want context.Canceled", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Wait did not return promptly after cancellation")
		}
	})
}

// TestLimiterIsConcurrencySafe exercises the limiter's mutex from many
// goroutines at once; run under -race to catch data races.
func TestLimiterIsConcurrencySafe(t *testing.T) {
	const workers = 50

	lim := NewLimiter(1000) // burst 1000: every call is admitted immediately

	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- lim.Wait(context.Background())
		}()
	}

	waited := make(chan struct{})
	go func() {
		wg.Wait()
		close(waited)
	}()

	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Wait calls did not all return")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Wait returned error: %v", err)
		}
	}
}
