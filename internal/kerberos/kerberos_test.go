package kerberos

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProbeNoneShape(t *testing.T) {
	st := Probe()
	if st.Kind == "" {
		t.Fatal("kind must be set")
	}
	if st.Available && st.Kind == KindNone {
		t.Fatal("available with kind none")
	}
}

func TestProbeCCacheEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ccache")
	if err := os.WriteFile(path, []byte("ticket"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KRB5CCNAME", "FILE:"+path)
	t.Setenv("KRB5_KTNAME", "")
	st := Probe()
	if !st.Available || st.Kind != KindCCache || st.Path != path {
		t.Fatalf("status = %+v", st)
	}
	line := SummaryLine(st)
	if !strings.Contains(line, "Kerberos") {
		t.Fatalf("summary = %q", line)
	}
}
