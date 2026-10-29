package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// sseRetry advises clients how long to wait before reconnecting.
	sseRetry = 3000
	// sseKeepaliveInterval keeps intermediary proxies from closing an idle
	// event stream.
	sseKeepaliveInterval = 15 * time.Second
)

// handleEvents streams live scan events as Server-Sent Events. The optional
// ?scan= query parameter limits the stream to one scan.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.deps.Hub == nil {
		s.writeAPIError(w, http.StatusServiceUnavailable, "event stream is unavailable")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeAPIError(w, http.StatusInternalServerError, "streaming is not supported")
		return
	}

	sub := s.deps.Hub.Subscribe(r.URL.Query().Get("scan"))
	defer sub.Close()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "retry: %d\n\n", sseRetry)
	flusher.Flush()

	keepalive := time.NewTicker(sseKeepaliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case ev, ok := <-sub.C():
			if !ok {
				return
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				s.deps.Logger.Error("encode sse event", "error", err.Error())
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, payload)
			flusher.Flush()
		}
	}
}
