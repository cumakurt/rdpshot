// Package config resolves runtime configuration from defaults, an optional
// JSON config file, environment variables and command line flags.
//
// Precedence (lowest to highest): defaults, config file, environment, flags.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds every runtime setting of the tool.
type Config struct {
	DBPath             string        `json:"db_path"`
	OutputsDir         string        `json:"outputs_dir"`
	Concurrency        int           `json:"concurrency"`
	Rate               float64       `json:"rate"`
	Timeout            time.Duration `json:"timeout"`
	MaxTargets         int           `json:"max_targets"`
	MaxAuthFailures    int           `json:"max_auth_failures"`
	MaxConcurrentScans int           `json:"max_concurrent_scans"`
	Addr               string        `json:"addr"`
	Token              string        `json:"token"`
	LogLevel           string        `json:"log_level"`
	LogFormat          string        `json:"log_format"`
	UserWordlist       string        `json:"user_wordlist"`
	PasswordWordlist   string        `json:"password_wordlist"`
	WebhookURL         string        `json:"webhook_url"`
	WebhookLevel       string        `json:"webhook_level"`
}

// Default returns the built-in configuration values.
func Default() Config {
	return Config{
		DBPath:             "outputs/rdpshot.db",
		OutputsDir:         "outputs",
		Concurrency:        64,
		Rate:               10,
		Timeout:            5 * time.Second,
		MaxTargets:         0, // 0 = unlimited CIDR expansion
		MaxAuthFailures:    5,
		MaxConcurrentScans: 2,
		Addr:               "127.0.0.1:8722",
		LogLevel:           "info",
		LogFormat:          "text",
		UserWordlist:       "wordlists/default_users.txt",
		PasswordWordlist:   "wordlists/default_passwords.txt",
		WebhookLevel:       "critical",
	}
}

// Load resolves configuration starting from defaults, then the optional JSON
// file at path (ignored when empty), then RDSHOT_* environment variables.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		if err := cfg.loadFile(path); err != nil {
			return Config{}, err
		}
	}
	if err := cfg.applyEnv(os.LookupEnv); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) loadFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read %q: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return fmt.Errorf("config: parse %q: %w", path, err)
	}
	return nil
}

func (c *Config) applyEnv(lookup func(string) (string, bool)) error {
	strs := []struct {
		key string
		dst *string
	}{
		{"RDSHOT_DB", &c.DBPath},
		{"RDSHOT_OUTPUTS", &c.OutputsDir},
		{"RDSHOT_ADDR", &c.Addr},
		{"RDSHOT_TOKEN", &c.Token},
		{"RDSHOT_LOG_LEVEL", &c.LogLevel},
		{"RDSHOT_LOG_FORMAT", &c.LogFormat},
		{"RDSHOT_USER_WORDLIST", &c.UserWordlist},
		{"RDSHOT_PASSWORD_WORDLIST", &c.PasswordWordlist},
		{"RDSHOT_WEBHOOK_URL", &c.WebhookURL},
		{"RDSHOT_WEBHOOK_LEVEL", &c.WebhookLevel},
	}
	for _, s := range strs {
		if v, ok := lookup(s.key); ok {
			*s.dst = v
		}
	}
	ints := []struct {
		key string
		dst *int
	}{
		{"RDSHOT_CONCURRENCY", &c.Concurrency},
		{"RDSHOT_MAX_TARGETS", &c.MaxTargets},
		{"RDSHOT_MAX_AUTH_FAILURES", &c.MaxAuthFailures},
		{"RDSHOT_MAX_CONCURRENT_SCANS", &c.MaxConcurrentScans},
	}
	for _, s := range ints {
		v, ok := lookup(s.key)
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("config: %s: invalid integer %q", s.key, v)
		}
		*s.dst = n
	}
	if v, ok := lookup("RDSHOT_RATE"); ok {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("config: RDSHOT_RATE: invalid number %q", v)
		}
		c.Rate = f
	}
	if v, ok := lookup("RDSHOT_TIMEOUT"); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("config: RDSHOT_TIMEOUT: invalid duration %q", v)
		}
		c.Timeout = d
	}
	return nil
}

// Validate rejects unusable configuration values early.
func (c Config) Validate() error {
	if c.DBPath == "" {
		return fmt.Errorf("config: db_path must not be empty")
	}
	if c.OutputsDir == "" {
		return fmt.Errorf("config: outputs_dir must not be empty")
	}
	if c.Concurrency <= 0 || c.Concurrency > 4096 {
		return fmt.Errorf("config: concurrency must be between 1 and 4096, got %d", c.Concurrency)
	}
	if c.Rate <= 0 {
		return fmt.Errorf("config: rate must be positive, got %g", c.Rate)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("config: timeout must be positive, got %s", c.Timeout)
	}
	if c.MaxTargets < 0 {
		return fmt.Errorf("config: max_targets must not be negative (0 = unlimited), got %d", c.MaxTargets)
	}
	if c.MaxAuthFailures < 0 {
		return fmt.Errorf("config: max_auth_failures must not be negative, got %d", c.MaxAuthFailures)
	}
	if c.MaxConcurrentScans < 0 {
		return fmt.Errorf("config: max_concurrent_scans must not be negative (0 uses default 2), got %d", c.MaxConcurrentScans)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log_level must be one of debug|info|warn|error, got %q", c.LogLevel)
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("config: log_format must be text or json, got %q", c.LogFormat)
	}
	return nil
}
