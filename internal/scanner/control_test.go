package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rdpshot/internal/model"
)

func TestRunControlPauseResume(t *testing.T) {
	var status model.ScanStatus
	control := NewRunControl(func(s model.ScanStatus, _ model.Progress) {
		status = s
	})

	progress := &model.Progress{Total: 3}
	control.attach(progress, nil)
	defer control.finish()

	if !control.Pause() {
		t.Fatal("Pause returned false")
	}
	if status != model.ScanPaused {
		t.Fatalf("status = %q, want paused", status)
	}
	if !control.Paused() {
		t.Fatal("Paused() = false after Pause")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := control.wait(ctx); err == nil {
		t.Fatal("wait returned while paused; want context deadline")
	}

	if !control.Resume() {
		t.Fatal("Resume returned false")
	}
	if status != model.ScanRunning {
		t.Fatalf("status = %q, want running", status)
	}
	if err := control.wait(context.Background()); err != nil {
		t.Fatalf("wait after resume: %v", err)
	}
}

func TestRunControlBlocksWorkersUntilResume(t *testing.T) {
	control := NewRunControl(nil)
	progress := &model.Progress{Total: 1}
	control.attach(progress, nil)
	defer control.finish()

	control.Pause()

	var passed int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := control.wait(context.Background()); err != nil {
			t.Errorf("wait: %v", err)
			return
		}
		atomic.StoreInt32(&passed, 1)
	}()

	time.Sleep(30 * time.Millisecond)
	if atomic.LoadInt32(&passed) != 0 {
		t.Fatal("worker passed the pause gate early")
	}
	control.Resume()
	wg.Wait()
	if atomic.LoadInt32(&passed) != 1 {
		t.Fatal("worker did not continue after resume")
	}
}

func TestRunControlIgnoresAfterFinish(t *testing.T) {
	control := NewRunControl(nil)
	control.attach(&model.Progress{}, nil)
	control.finish()
	if control.Pause() {
		t.Fatal("Pause after finish should return false")
	}
	if control.Resume() {
		t.Fatal("Resume after finish should return false")
	}
}
