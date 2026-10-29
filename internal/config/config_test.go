package config

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestDefaultIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}

func TestLoadFileOverridesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := `{"db_path":"data/x.db","concurrency":8,"timeout":2000000000}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.DBPath != "data/x.db" || cfg.Concurrency != 8 || cfg.Timeout != 2*time.Second {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.Addr != Default().Addr {
		t.Fatalf("untouched default lost: %+v", cfg)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"nope":1}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestEnvOverridesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"concurrency":8}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("RDSHOT_CONCURRENCY", "32")
	t.Setenv("RDSHOT_TIMEOUT", "1500ms")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Concurrency != 32 {
		t.Fatalf("env did not override file: %+v", cfg)
	}
	if cfg.Timeout != 1500*time.Millisecond {
		t.Fatalf("timeout not applied: %s", cfg.Timeout)
	}
}

func TestEnvInvalidValues(t *testing.T) {
	for key, value := range map[string]string{
		"RDSHOT_CONCURRENCY": "many",
		"RDSHOT_RATE":        "fast",
		"RDSHOT_TIMEOUT":     "later",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)
			if _, err := Load(""); err == nil {
				t.Fatalf("expected error for %s=%s", key, value)
			}
		})
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := []func(*Config){
		func(c *Config) { c.DBPath = "" },
		func(c *Config) { c.Concurrency = 0 },
		func(c *Config) { c.Concurrency = 10000 },
		func(c *Config) { c.Rate = -1 },
		func(c *Config) { c.Timeout = 0 },
		func(c *Config) { c.MaxTargets = -5 },
		func(c *Config) { c.MaxAuthFailures = -1 },
		func(c *Config) { c.LogLevel = "verbose" },
		func(c *Config) { c.LogFormat = "yaml" },
	}
	for i, mutate := range cases {
		cfg := Default()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}

func TestLoadEmptyFileValuesKeepDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg != Default() {
		t.Fatalf("expected defaults, got %+v", cfg)
	}
}

func TestConfigJSONRoundTrip(t *testing.T) {
	// Timeouts are serialized as nanoseconds; the loader must accept the same shape.
	path := filepath.Join(t.TempDir(), "config.json")
	content := `{"timeout":` + strconv.FormatInt(Default().Timeout.Nanoseconds(), 10) + `}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Timeout != Default().Timeout {
		t.Fatalf("timeout mismatch: %s", cfg.Timeout)
	}
}
