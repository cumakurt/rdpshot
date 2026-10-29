package siem

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/model"
)

func TestDeliverJSON(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = string(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	err := Deliver(context.Background(), srv.URL, FormatJSON, []Event{{
		Type: "finding", At: time.Now().UTC(), ScanID: "s1", Severity: "high", Message: "test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"type":"finding"`) {
		t.Fatalf("body=%s", got)
	}
}

func TestToCEF(t *testing.T) {
	line := toCEF(FromFinding(model.Scan{ID: "s1"}, model.Finding{
		CheckID: "nla-missing", Title: "NLA missing", Severity: model.SeverityHigh,
		Address: "10.0.0.1", Port: 3389, DetectedAt: time.Now().UTC(),
	}))
	if !strings.HasPrefix(line, "CEF:0|RDPShot|rdpshot|1|") {
		t.Fatalf("cef=%s", line)
	}
}
