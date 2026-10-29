package scanner

import (
	"context"
	"sync"

	"rdpshot/internal/model"
)

// RunControl drives pause and resume for one running scan. It is safe for
// concurrent use and can be created before the engine starts running: a pause
// requested early takes effect as soon as the run attaches to the control.
type RunControl struct {
	mu       sync.Mutex
	gate     *pauseGate
	progress *model.Progress
	paused   bool
	finished bool

	onChange func(model.ScanStatus, model.Progress)
	publish  func(model.EventType, model.Progress)
}

// NewRunControl creates a control for one scan run. onChange may be nil; it is
// invoked on every pause/resume transition with a progress snapshot so the
// caller can persist the new state.
func NewRunControl(onChange func(model.ScanStatus, model.Progress)) *RunControl {
	return &RunControl{onChange: onChange}
}

// Pause stops workers from taking new endpoints. Work already in flight runs
// to completion, so no partially probed host is recorded. It reports whether
// the run was still active.
func (c *RunControl) Pause() bool { return c.setPaused(true) }

// Resume reopens the worker gate so the queued endpoints continue.
func (c *RunControl) Resume() bool { return c.setPaused(false) }

// Paused reports whether the run is currently paused.
func (c *RunControl) Paused() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paused
}

func (c *RunControl) setPaused(paused bool) bool {
	c.mu.Lock()
	if c.finished {
		c.mu.Unlock()
		return false
	}
	if c.paused == paused {
		c.mu.Unlock()
		return true
	}
	c.paused = paused
	gate := c.gate
	progress := c.progress
	onChange := c.onChange
	publish := c.publish
	c.mu.Unlock()

	if gate != nil {
		if paused {
			gate.pause()
		} else {
			gate.resume()
		}
	}

	status := model.ScanRunning
	eventType := model.EventScanResumed
	if paused {
		status = model.ScanPaused
		eventType = model.EventScanPaused
	}
	var snapshot model.Progress
	if progress != nil {
		snapshot = snapshotProgress(progress)
	}
	if onChange != nil {
		onChange(status, snapshot)
	}
	if publish != nil {
		publish(eventType, snapshot)
	}
	return true
}

// attach binds the control to the live progress of one run. Called by the
// engine before the worker pool starts.
func (c *RunControl) attach(progress *model.Progress, publish func(model.EventType, model.Progress)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.progress = progress
	c.publish = publish
	gate := newPauseGate()
	if c.paused {
		gate.pause()
	}
	c.gate = gate
}

// finish marks the run as no longer controllable.
func (c *RunControl) finish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.finished = true
	c.gate = nil
	c.progress = nil
	c.publish = nil
}

// wait blocks while the run is paused and returns ctx.Err() when it is
// cancelled.
func (c *RunControl) wait(ctx context.Context) error {
	c.mu.Lock()
	gate := c.gate
	c.mu.Unlock()
	if gate == nil {
		return ctx.Err()
	}
	return gate.wait(ctx)
}

// pauseGate parks workers without spinning. A new channel is created for every
// pause so wake-ups cannot be missed.
type pauseGate struct {
	mu     sync.Mutex
	wake   chan struct{}
	paused bool
}

func newPauseGate() *pauseGate {
	return &pauseGate{}
}

func (g *pauseGate) pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.paused {
		g.paused = true
		g.wake = make(chan struct{})
	}
}

func (g *pauseGate) resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		g.paused = false
		close(g.wake)
	}
}

func (g *pauseGate) wait(ctx context.Context) error {
	g.mu.Lock()
	if !g.paused {
		g.mu.Unlock()
		return ctx.Err()
	}
	wake := g.wake
	g.mu.Unlock()

	select {
	case <-wake:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}
