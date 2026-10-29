package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"rdpshot/internal/events"
	"rdpshot/internal/model"
)

// printEvents renders live scan progress. On a TTY it keeps a fixed colorful
// panel and only redraws when values change; otherwise it prints compact lines.
func printEvents(sub *events.Subscription, w io.Writer) {
	if isTTY(w) {
		printEventsTTY(sub, w)
		return
	}
	printEventsPlain(sub, w)
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func printEventsPlain(sub *events.Subscription, w io.Writer) {
	lastStatus := ""
	for ev := range sub.C() {
		switch ev.Type {
		case model.EventScanProgress, model.EventScanStarted, model.EventScanPaused, model.EventScanResumed, model.EventScanFinished:
			p, ok := ev.Payload.(model.Progress)
			if !ok {
				continue
			}
			line := fmt.Sprintf("%s  %d/%d  open=%d findings=%d creds=%d jobs=%d",
				ev.Type, p.Done, p.Total, p.Open, p.Findings, p.Creds, p.ActiveJobs)
			if line != lastStatus {
				fmt.Fprintln(w, line)
				lastStatus = line
			}
		case model.EventFinding:
			f, ok := ev.Payload.(model.Finding)
			if !ok {
				continue
			}
			fmt.Fprintf(w, "finding  %-8s  %s  %s:%d  %s\n", f.Severity, f.CheckID, f.Address, f.Port, f.Title)
		case model.EventCredential:
			c, ok := ev.Payload.(model.Credential)
			if !ok {
				continue
			}
			fmt.Fprintf(w, "credential  %s@%s:%d\n", c.Username, c.Address, c.Port)
		case model.EventScreenshot:
			s, ok := ev.Payload.(model.Screenshot)
			if !ok {
				continue
			}
			fmt.Fprintf(w, "screenshot  %s\n", s.FilePath)
		case model.EventLog:
			p, ok := ev.Payload.(model.LogPayload)
			if !ok {
				continue
			}
			fmt.Fprintf(w, "log  [%s] %s\n", p.Level, p.Message)
		case model.EventScanFailed:
			fmt.Fprintln(w, "scan failed")
		}
	}
}

type livePanel struct {
	w          io.Writer
	lines      int
	drawn      bool
	status     string
	progress   model.Progress
	hasProg    bool
	lastEvent  string
	lastColor  string
	startedAt  time.Time
}

func printEventsTTY(sub *events.Subscription, w io.Writer) {
	panel := &livePanel{w: w, status: "starting", startedAt: time.Now()}
	panel.redraw()
	for ev := range sub.C() {
		changed := false
		switch ev.Type {
		case model.EventScanStarted:
			panel.status = "running"
			changed = true
			if p, ok := ev.Payload.(model.Progress); ok {
				panel.progress = p
				panel.hasProg = true
			}
		case model.EventScanProgress:
			if p, ok := ev.Payload.(model.Progress); ok {
				if !panel.hasProg || p != panel.progress {
					panel.progress = p
					panel.hasProg = true
					changed = true
				}
			}
			if panel.status == "starting" || panel.status == "" {
				panel.status = "running"
				changed = true
			}
		case model.EventScanPaused:
			panel.status = "paused"
			changed = true
			if p, ok := ev.Payload.(model.Progress); ok {
				panel.progress = p
				panel.hasProg = true
			}
		case model.EventScanResumed:
			panel.status = "running"
			changed = true
			if p, ok := ev.Payload.(model.Progress); ok {
				panel.progress = p
				panel.hasProg = true
			}
		case model.EventScanFinished:
			panel.status = "completed"
			changed = true
			if p, ok := ev.Payload.(model.Progress); ok {
				panel.progress = p
				panel.hasProg = true
			}
		case model.EventScanFailed:
			panel.status = "failed"
			changed = true
		case model.EventFinding:
			if f, ok := ev.Payload.(model.Finding); ok {
				panel.lastEvent = fmt.Sprintf("%s  %s  %s:%d  %s", f.Severity, f.CheckID, f.Address, f.Port, f.Title)
				panel.lastColor = severityANSI(string(f.Severity))
				changed = true
			}
		case model.EventCredential:
			if c, ok := ev.Payload.(model.Credential); ok {
				panel.lastEvent = fmt.Sprintf("credential verified  %s@%s:%d", c.Username, c.Address, c.Port)
				panel.lastColor = ansiGreen
				changed = true
			}
		case model.EventScreenshot:
			if s, ok := ev.Payload.(model.Screenshot); ok {
				panel.lastEvent = fmt.Sprintf("screenshot  %s", s.FilePath)
				panel.lastColor = ansiAmber
				changed = true
			}
		case model.EventLog:
			if p, ok := ev.Payload.(model.LogPayload); ok {
				panel.lastEvent = fmt.Sprintf("[%s] %s", p.Level, p.Message)
				panel.lastColor = ansiMuted
				changed = true
			}
		}
		if changed {
			panel.redraw()
		}
	}
	if panel.status == "running" || panel.status == "starting" {
		panel.status = "done"
	}
	panel.redraw()
	fmt.Fprintln(w)
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiGreen  = "\033[32m"
	ansiRed    = "\033[31m"
	ansiAmber  = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiMagenta = "\033[35m"
	ansiMuted  = "\033[90m"
	ansiClear  = "\033[2K"
	ansiUp     = "\033[%dA"
)

func (p *livePanel) redraw() {
	if p.drawn && p.lines > 0 {
		fmt.Fprintf(p.w, ansiUp, p.lines)
	}

	var rows []string
	statusColor := statusANSI(p.status)
	elapsed := formatElapsedCLI(time.Since(p.startedAt))
	rows = append(rows, fmt.Sprintf("%s%s rdpshot %s%s%s · %s%s%s · %s%s%s",
		ansiBold, ansiCyan, ansiReset, statusColor, p.status, ansiDim, elapsed, ansiReset, ansiDim, "live", ansiReset))

	if p.hasProg {
		pct := 0.0
		if p.progress.Total > 0 {
			pct = float64(p.progress.Done) / float64(p.progress.Total) * 100
		}
		rows = append(rows, fmt.Sprintf("  %s%5.1f%%%s  %s", ansiBold, pct, ansiReset, progressBar(p.progress.Done, p.progress.Total, 28)))
		rows = append(rows, fmt.Sprintf("  %s%d/%d%s  %sopen%s %s%d%s  %sclosed%s %s%d%s  %sfindings%s %s%d%s  %screds%s %s%d%s  %sscreens%s %s%d%s  %sjobs%s %s%d%s",
			ansiBold, p.progress.Done, p.progress.Total, ansiReset,
			ansiDim, ansiReset, ansiGreen, p.progress.Open, ansiReset,
			ansiDim, ansiReset, ansiMuted, p.progress.Closed, ansiReset,
			ansiDim, ansiReset, ansiRed, p.progress.Findings, ansiReset,
			ansiDim, ansiReset, ansiGreen, p.progress.Creds, ansiReset,
			ansiDim, ansiReset, ansiAmber, p.progress.Screens, ansiReset,
			ansiDim, ansiReset, ansiBlue, p.progress.ActiveJobs, ansiReset,
		))
	} else {
		rows = append(rows, "  "+ansiDim+"waiting for first progress update…"+ansiReset)
		rows = append(rows, "")
	}

	if p.lastEvent != "" {
		color := p.lastColor
		if color == "" {
			color = ansiMuted
		}
		rows = append(rows, fmt.Sprintf("  %slast%s  %s%s%s", ansiDim, ansiReset, color, truncateRunes(p.lastEvent, 90), ansiReset))
	} else {
		rows = append(rows, "  "+ansiDim+"last  —"+ansiReset)
	}

	for _, row := range rows {
		fmt.Fprintf(p.w, "%s\r%s\n", ansiClear, row)
	}
	p.lines = len(rows)
	p.drawn = true
}

func progressBar(done, total int64, width int) string {
	if width < 8 {
		width = 8
	}
	filled := 0
	if total > 0 {
		filled = int(float64(done) / float64(total) * float64(width))
		if filled > width {
			filled = width
		}
		if done > 0 && filled == 0 {
			filled = 1
		}
	}
	return ansiBlue + strings.Repeat("█", filled) + ansiMuted + strings.Repeat("░", width-filled) + ansiReset
}

func statusANSI(status string) string {
	switch status {
	case "running", "starting":
		return ansiBlue
	case "paused":
		return ansiAmber
	case "completed", "done":
		return ansiGreen
	case "failed":
		return ansiRed
	default:
		return ansiMuted
	}
}

func severityANSI(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return ansiMagenta
	case "high":
		return ansiRed
	case "medium":
		return ansiAmber
	case "low":
		return ansiCyan
	default:
		return ansiMuted
	}
}

func formatElapsedCLI(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	sec := int(d.Seconds())
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}
