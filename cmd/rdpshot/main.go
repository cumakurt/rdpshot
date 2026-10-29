// Command rdpshot is the single-binary CLI of the rdpshot RDP security-audit
// platform.
//
// It runs scans in the foreground, serves the web UI and REST API, renders
// reports from stored results and resolves target specifications. The tool is
// intended for authorized security audits only: credential checks and
// screenshot capture are disabled by default and require the explicit
// --ack-authorized acknowledgement.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"rdpshot/internal/auth"
	"rdpshot/internal/config"
	"rdpshot/internal/events"
	"rdpshot/internal/model"
	"rdpshot/internal/reporter"
	"rdpshot/internal/scanner"
	"rdpshot/internal/screenshot"
	"rdpshot/internal/server"
	"rdpshot/internal/store"
	"rdpshot/internal/target"
)

// version is reported by the version command and embedded into reports. It is
// overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes: 0 success, 1 runtime error, 2 usage or validation error.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

const usageText = `rdpshot - RDP security-audit platform (authorized testing only)

Usage:
  rdpshot <command> [flags] [targets...]

Commands:
  scan      Run a scan in the foreground.
  serve     Start the web UI and REST API.
  report    Generate a report from stored scan results.
  targets   Resolve target specifications and print the endpoints.
  version   Print the tool version.

Use "rdpshot <command> -h" for the flags of a command.

Target specifications:
  192.168.1.10            single address
  10.0.0.0/24             CIDR range
  host.example.com        hostname
  10.0.0.5:3389           address with explicit port
  @targets.txt            file with one specification per line

Only scan systems you are authorized to test. Credential checks and
screenshots require --ack-authorized to confirm you are authorized to test
these targets.

Exit codes: 0 success, 1 runtime error, 2 usage or validation error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches one command and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "report":
		return runReport(args[1:], stdout, stderr)
	case "targets":
		return runTargets(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "rdpshot %s\n", version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stderr, usageText)
		return exitOK
	default:
		fmt.Fprintf(stderr, "rdpshot: unknown command %q\n\n", args[0])
		fmt.Fprint(stderr, usageText)
		return exitUsage
	}
}

// newFlagSet builds a command flag set whose help goes to stderr.
func newFlagSet(name, usageLine, description string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "rdpshot %s - %s\n\nUsage: rdpshot %s\n\nFlags:\n", name, description, usageLine)
		fs.PrintDefaults()
	}
	return fs
}

// flagErrorExit maps a flag parse result to an exit code. Explicit help
// requests are successful; anything else is a usage error.
func flagErrorExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	return exitUsage
}

// newLogger builds the structured logger used for operational output. Logs go
// to stderr so stdout stays machine-readable.
func newLogger(level, format string, w io.Writer) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// splitList splits a comma separated flag value into trimmed, non-empty items.
func splitList(spec string) []string {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	parts := strings.Split(spec, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// runScan scans targets in the foreground and prints live progress to stderr.
func runScan(args []string, stdout, stderr io.Writer) int {
	def := config.Default()
	fs := newFlagSet("scan", "scan [flags] <targets...>",
		"Run a scan in the foreground.", stderr)

	name := fs.String("name", "", "scan name stored in the database (default: generated from the current time)")
	portsSpec := fs.String("ports", "3389", "ports to scan, e.g. \"3389,3390,33800-33810\"")
	blacklistSpec := fs.String("blacklist", "", "comma separated IPs, CIDRs or hostnames to exclude from the scan")
	concurrency := fs.Int("concurrency", def.Concurrency, "number of endpoints probed in parallel")
	rate := fs.Float64("rate", def.Rate, "maximum connection attempts per second")
	timeout := fs.Duration("timeout", def.Timeout, "per-connection timeout")
	maxTargets := fs.Int("max-targets", def.MaxTargets, "hard limit on the number of expanded endpoints")
	maxAuthFailures := fs.Int("max-auth-failures", def.MaxAuthFailures, "maximum rejected logins per host during the credential audit")
	enableVuln := fs.Bool("enable-vuln", true, "run the vulnerability checks")
	enableAuth := fs.Bool("enable-auth", false, "run the credential audit (requires --ack-authorized)")
	enableScreens := fs.Bool("enable-screens", false, "capture session screenshots (requires --ack-authorized)")
	ackAuthorized := fs.Bool("ack-authorized", false, "confirm you are authorized to test these targets")
	userWordlist := fs.String("user-wordlist", def.UserWordlist, "username wordlist for the credential audit")
	passwordWordlist := fs.String("password-wordlist", def.PasswordWordlist, "password wordlist for the credential audit")
	reportFormat := fs.String("report", "html", "report to generate after the scan: none, html, csv or pdf")
	reportDir := fs.String("report-dir", "", "directory for generated reports (default: <outputs>/reports)")
	dbPath := fs.String("db", def.DBPath, "path to the SQLite database")
	outputsDir := fs.String("outputs", def.OutputsDir, "directory for reports and screenshots")
	configPath := fs.String("config", "", "path to a JSON configuration file")
	logLevel := fs.String("log-level", def.LogLevel, "log level: debug, info, warn or error")
	logFormat := fs.String("log-format", def.LogFormat, "log format: text or json")

	if err := fs.Parse(args); err != nil {
		return flagErrorExit(err)
	}
	specs := fs.Args()
	if len(specs) == 0 {
		fmt.Fprintln(stderr, "rdpshot scan: at least one target specification is required")
		fs.Usage()
		return exitUsage
	}
	switch *reportFormat {
	case "none", "html", "csv", "pdf":
	default:
		fmt.Fprintf(stderr, "rdpshot scan: invalid --report format %q (want none, html, csv or pdf)\n", *reportFormat)
		return exitUsage
	}
	// Safety guardrail: the intrusive stages need an explicit authorization
	// acknowledgement so the tool cannot be pointed at third-party hosts by
	// accident.
	if (*enableAuth || *enableScreens) && !*ackAuthorized {
		fmt.Fprintln(stderr, "rdpshot scan: credential checks and screenshots require --ack-authorized to confirm you are authorized to test these targets")
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot scan: %v\n", err)
		return exitUsage
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "db":
			cfg.DBPath = *dbPath
		case "outputs":
			cfg.OutputsDir = *outputsDir
		case "concurrency":
			cfg.Concurrency = *concurrency
		case "rate":
			cfg.Rate = *rate
		case "timeout":
			cfg.Timeout = *timeout
		case "max-targets":
			cfg.MaxTargets = *maxTargets
		case "max-auth-failures":
			cfg.MaxAuthFailures = *maxAuthFailures
		case "user-wordlist":
			cfg.UserWordlist = *userWordlist
		case "password-wordlist":
			cfg.PasswordWordlist = *passwordWordlist
		case "log-level":
			cfg.LogLevel = *logLevel
		case "log-format":
			cfg.LogFormat = *logFormat
		}
	})
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "rdpshot scan: %v\n", err)
		return exitUsage
	}

	ports, err := target.ParsePorts(*portsSpec)
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot scan: %v\n", err)
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res, err := target.Resolve(ctx, target.Options{
		Specs:      specs,
		Ports:      ports,
		Blacklist:  splitList(*blacklistSpec),
		MaxTargets: cfg.MaxTargets,
	})
	for _, warning := range res.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", warning)
	}
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot scan: resolve targets: %v\n", err)
		return exitUsage
	}
	if len(res.Endpoints) == 0 {
		fmt.Fprintln(stderr, "rdpshot scan: no endpoints resolved from the given targets")
		return exitError
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot scan: %v\n", err)
		return exitError
	}
	defer st.Close()

	logger := newLogger(cfg.LogLevel, cfg.LogFormat, stderr)
	hub := events.NewHub(0)
	defer hub.Close()

	authenticator := auth.NewCredSSPAuthenticator(cfg.Timeout)
	grabber := screenshot.NewXFreeRDPGrabber(filepath.Join(cfg.OutputsDir, "screenshots"))
	engine := scanner.New(scanner.Dependencies{
		Store:         st,
		Hub:           hub,
		Logger:        logger,
		Authenticator: authenticator,
		Grabber:       grabber,
	})

	scanName := *name
	if scanName == "" {
		scanName = "scan-" + time.Now().UTC().Format("20060102-150405")
	}
	scan := model.Scan{
		ID:        model.NewID("scan"),
		Name:      scanName,
		Status:    model.ScanPending,
		CreatedAt: time.Now().UTC(),
		Options: model.ScanOptions{
			Targets:          specs,
			Ports:            ports,
			Blacklist:        splitList(*blacklistSpec),
			TimeoutMS:        int(cfg.Timeout.Milliseconds()),
			Concurrency:      cfg.Concurrency,
			RatePerSecond:    cfg.Rate,
			EnableVuln:       *enableVuln,
			EnableAuth:       *enableAuth,
			EnableScreens:    *enableScreens,
			MaxAuthFailures:  cfg.MaxAuthFailures,
			UserWordlist:     cfg.UserWordlist,
			PasswordWordlist: cfg.PasswordWordlist,
			Acknowledged:     *ackAuthorized,
		},
	}
	if err := st.CreateScan(scan); err != nil {
		fmt.Fprintf(stderr, "rdpshot scan: %v\n", err)
		return exitError
	}

	// Subscribe before starting so no live event is missed.
	sub := hub.Subscribe(scan.ID)
	printerDone := make(chan struct{})
	go func() {
		defer close(printerDone)
		printEvents(sub, stderr)
	}()

	fmt.Fprintf(stderr, "scan %s started: %d endpoints, %d port(s)\n", scan.ID, len(res.Endpoints), len(ports))
	engine.Run(ctx, &scan, res.Endpoints)
	sub.Close()
	<-printerDone

	if scan.Status == model.ScanCancelled {
		fmt.Fprintf(stderr, "scan %s cancelled; partial results were kept\n", scan.ID)
	}

	summary, err := st.Summary(scan.ID)
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot scan: summary: %v\n", err)
		return exitError
	}
	fmt.Fprintf(stdout, "scan %s %s\n", scan.ID, scan.Status)
	fmt.Fprintf(stdout, "hosts: %d open, %d closed/filtered\n", summary.HostsOpen, summary.HostsTotal-summary.HostsOpen)
	fmt.Fprintln(stdout, "findings by severity:")
	for _, bucket := range summary.BySeverity {
		fmt.Fprintf(stdout, "  %-8s %d\n", bucket.Severity, bucket.Count)
	}

	// Only usernames and endpoints are printed; secrets never leave the
	// database except masked inside reports.
	creds, err := st.ListCredentials(scan.ID)
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot scan: list credentials: %v\n", err)
		return exitError
	}
	fmt.Fprintf(stdout, "verified credentials: %d\n", len(creds))
	for _, cred := range creds {
		fmt.Fprintf(stdout, "  %s@%s:%d\n", cred.Username, cred.Address, cred.Port)
	}
	fmt.Fprintf(stdout, "screenshots: %d\n", summary.ScreensTotal)

	if *reportFormat != "none" {
		dir := *reportDir
		if dir == "" {
			dir = filepath.Join(cfg.OutputsDir, "reports")
		}
		path := filepath.Join(dir, fmt.Sprintf("rdpshot-%s.%s", scan.ID, *reportFormat))
		data, err := loadReportData(st, scan.ID)
		if err != nil {
			fmt.Fprintf(stderr, "rdpshot scan: %v\n", err)
			return exitError
		}
		if err := writeReport(*reportFormat, path, data); err != nil {
			fmt.Fprintf(stderr, "rdpshot scan: %v\n", err)
			return exitError
		}
		fmt.Fprintln(stdout, path)
	}

	if scan.Status == model.ScanCancelled {
		return exitError
	}
	return exitOK
}

// printEvents renders live scan events as plain, non-interactive-friendly
// lines. Progress lines are only reprinted when the counters change.
func printEvents(sub *events.Subscription, w io.Writer) {
	lastStatus := ""
	for ev := range sub.C() {
		switch ev.Type {
		case model.EventScanProgress:
			p, ok := ev.Payload.(model.Progress)
			if !ok {
				continue
			}
			line := fmt.Sprintf("[%d/%d] open=%d findings=%d creds=%d", p.Done, p.Total, p.Open, p.Findings, p.Creds)
			if line != lastStatus {
				fmt.Fprintln(w, line)
				lastStatus = line
			}
		case model.EventFinding:
			f, ok := ev.Payload.(model.Finding)
			if !ok {
				continue
			}
			fmt.Fprintf(w, "[%s] %s %s:%d %s\n", f.Severity, f.CheckID, f.Address, f.Port, f.Title)
		case model.EventCredential:
			c, ok := ev.Payload.(model.Credential)
			if !ok {
				continue
			}
			fmt.Fprintf(w, "verified credential: %s@%s:%d\n", c.Username, c.Address, c.Port)
		case model.EventScreenshot:
			s, ok := ev.Payload.(model.Screenshot)
			if !ok {
				continue
			}
			fmt.Fprintf(w, "screenshot: %s\n", s.FilePath)
		case model.EventLog:
			p, ok := ev.Payload.(model.LogPayload)
			if !ok {
				continue
			}
			fmt.Fprintf(w, "log: [%s] %s\n", p.Level, p.Message)
		}
	}
}

// runServe starts the web UI and REST API.
func runServe(args []string, stdout, stderr io.Writer) int {
	def := config.Default()
	fs := newFlagSet("serve", "serve [flags]",
		"Start the web UI and REST API.", stderr)

	addr := fs.String("addr", def.Addr, "listen address for the web UI and REST API")
	token := fs.String("token", "", "bearer token required for every request (recommended when listening beyond localhost)")
	dbPath := fs.String("db", def.DBPath, "path to the SQLite database")
	outputsDir := fs.String("outputs", def.OutputsDir, "directory for reports and screenshots")
	configPath := fs.String("config", "", "path to a JSON configuration file")
	logLevel := fs.String("log-level", def.LogLevel, "log level: debug, info, warn or error")
	logFormat := fs.String("log-format", def.LogFormat, "log format: text or json")
	userWordlist := fs.String("user-wordlist", def.UserWordlist, "default username wordlist for credential audits")
	passwordWordlist := fs.String("password-wordlist", def.PasswordWordlist, "default password wordlist for credential audits")
	maxAuthFailures := fs.Int("max-auth-failures", def.MaxAuthFailures, "default maximum rejected logins per host")

	if err := fs.Parse(args); err != nil {
		return flagErrorExit(err)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "rdpshot serve: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot serve: %v\n", err)
		return exitUsage
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "addr":
			cfg.Addr = *addr
		case "token":
			cfg.Token = *token
		case "db":
			cfg.DBPath = *dbPath
		case "outputs":
			cfg.OutputsDir = *outputsDir
		case "log-level":
			cfg.LogLevel = *logLevel
		case "log-format":
			cfg.LogFormat = *logFormat
		case "user-wordlist":
			cfg.UserWordlist = *userWordlist
		case "password-wordlist":
			cfg.PasswordWordlist = *passwordWordlist
		case "max-auth-failures":
			cfg.MaxAuthFailures = *maxAuthFailures
		}
	})
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "rdpshot serve: %v\n", err)
		return exitUsage
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot serve: %v\n", err)
		return exitError
	}
	defer st.Close()

	logger := newLogger(cfg.LogLevel, cfg.LogFormat, stderr)
	hub := events.NewHub(0)
	defer hub.Close()

	authenticator := auth.NewCredSSPAuthenticator(cfg.Timeout)
	grabber := screenshot.NewXFreeRDPGrabber(filepath.Join(cfg.OutputsDir, "screenshots"))
	engine := scanner.New(scanner.Dependencies{
		Store:         st,
		Hub:           hub,
		Logger:        logger,
		Authenticator: authenticator,
		Grabber:       grabber,
	})

	srv, err := server.New(server.Config{
		Addr:        cfg.Addr,
		Token:       cfg.Token,
		OutputsDir:  cfg.OutputsDir,
		ToolVersion: version,
	}, server.Dependencies{
		Store:  st,
		Hub:    hub,
		Engine: engine,
		Logger: logger,
	})
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot serve: %v\n", err)
		return exitError
	}

	fmt.Fprintf(stdout, "web UI: http://%s/\n", cfg.Addr)
	if cfg.Token != "" {
		fmt.Fprintln(stdout, "token auth: enabled")
	} else {
		fmt.Fprintln(stdout, "token auth: disabled")
		if !isLoopbackAddr(cfg.Addr) {
			fmt.Fprintln(stderr, "warning: listening beyond localhost without --token; anyone who can reach this address can start scans and read results")
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.ListenAndServe(ctx); err != nil {
		fmt.Fprintf(stderr, "rdpshot serve: %v\n", err)
		return exitError
	}
	return exitOK
}

// isLoopbackAddr reports whether addr binds to a loopback address only.
func isLoopbackAddr(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// runReport renders one stored scan into an HTML, CSV or PDF report.
func runReport(args []string, stdout, stderr io.Writer) int {
	def := config.Default()
	fs := newFlagSet("report", "report --scan <id> [flags]",
		"Generate a report from stored scan results.", stderr)

	scanID := fs.String("scan", "", "scan ID to render (required)")
	format := fs.String("format", "html", "report format: html, csv or pdf")
	output := fs.String("output", "", "output file (default outputs/reports/rdpshot-<id>.<format>)")
	fs.StringVar(output, "o", "", "shorthand for --output")
	dbPath := fs.String("db", def.DBPath, "path to the SQLite database")

	if err := fs.Parse(args); err != nil {
		return flagErrorExit(err)
	}
	if *scanID == "" {
		fmt.Fprintln(stderr, "rdpshot report: --scan is required")
		fs.Usage()
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "rdpshot report: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	switch *format {
	case "html", "csv", "pdf":
	default:
		fmt.Fprintf(stderr, "rdpshot report: invalid --format %q (want html, csv or pdf)\n", *format)
		return exitUsage
	}

	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot report: %v\n", err)
		return exitUsage
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "db" {
			cfg.DBPath = *dbPath
		}
	})
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "rdpshot report: %v\n", err)
		return exitUsage
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot report: %v\n", err)
		return exitError
	}
	defer st.Close()

	data, err := loadReportData(st, *scanID)
	if err != nil {
		if errors.Is(err, store.ErrScanNotFound) {
			fmt.Fprintf(stderr, "rdpshot report: scan %q not found\n", *scanID)
			return exitError
		}
		fmt.Fprintf(stderr, "rdpshot report: %v\n", err)
		return exitError
	}

	path := *output
	if path == "" {
		path = filepath.Join(cfg.OutputsDir, "reports", fmt.Sprintf("rdpshot-%s.%s", *scanID, *format))
	}
	if err := writeReport(*format, path, data); err != nil {
		fmt.Fprintf(stderr, "rdpshot report: %v\n", err)
		return exitError
	}
	fmt.Fprintln(stdout, path)
	return exitOK
}

// loadReportData collects everything one report needs from the store. The
// credentials are masked here so raw secrets never reach the renderers.
func loadReportData(st *store.Store, scanID string) (reporter.Data, error) {
	scan, err := st.GetScan(scanID)
	if err != nil {
		return reporter.Data{}, fmt.Errorf("load scan: %w", err)
	}
	hosts, err := st.ListHosts(scanID)
	if err != nil {
		return reporter.Data{}, fmt.Errorf("load hosts: %w", err)
	}
	findings, err := st.ListFindings(scanID)
	if err != nil {
		return reporter.Data{}, fmt.Errorf("load findings: %w", err)
	}
	creds, err := st.ListCredentials(scanID)
	if err != nil {
		return reporter.Data{}, fmt.Errorf("load credentials: %w", err)
	}
	masked := make([]model.Credential, len(creds))
	for i, cred := range creds {
		masked[i] = cred.Masked()
	}
	screens, err := st.ListScreenshots(scanID)
	if err != nil {
		return reporter.Data{}, fmt.Errorf("load screenshots: %w", err)
	}
	cveStats, err := st.CVEStats(scanID)
	if err != nil {
		return reporter.Data{}, fmt.Errorf("load CVE statistics: %w", err)
	}
	summary, err := st.Summary(scanID)
	if err != nil {
		return reporter.Data{}, fmt.Errorf("load summary: %w", err)
	}
	return reporter.Data{
		Scan:        scan,
		Summary:     summary,
		Hosts:       hosts,
		Findings:    findings,
		Credentials: masked,
		Screens:     screens,
		CVEStats:    cveStats,
		GeneratedAt: time.Now().UTC(),
		ToolVersion: version,
	}, nil
}

// writeReport renders data into path with the requested format.
func writeReport(format, path string, data reporter.Data) error {
	var render func(io.Writer, reporter.Data) error
	switch format {
	case "html":
		render = reporter.HTML
	case "csv":
		render = reporter.CSV
	case "pdf":
		render = reporter.PDF
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	renderErr := render(f, data)
	closeErr := f.Close()
	if renderErr != nil {
		return fmt.Errorf("render %s report: %w", format, renderErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close report file: %w", closeErr)
	}
	return nil
}

// runTargets resolves target specifications and prints the endpoints.
func runTargets(args []string, stdout, stderr io.Writer) int {
	def := config.Default()
	fs := newFlagSet("targets", "targets [flags] <targets...>",
		"Resolve target specifications and print the endpoints.", stderr)

	portsSpec := fs.String("ports", "3389", "ports for specs without an explicit port, e.g. \"3389,3390,33800-33810\"")
	blacklistSpec := fs.String("blacklist", "", "comma separated IPs, CIDRs or hostnames to exclude")
	maxTargets := fs.Int("max-targets", def.MaxTargets, "hard limit on the number of expanded endpoints")

	if err := fs.Parse(args); err != nil {
		return flagErrorExit(err)
	}
	specs := fs.Args()
	if len(specs) == 0 {
		fmt.Fprintln(stderr, "rdpshot targets: at least one target specification is required")
		fs.Usage()
		return exitUsage
	}
	ports, err := target.ParsePorts(*portsSpec)
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot targets: %v\n", err)
		return exitUsage
	}

	res, err := target.Resolve(context.Background(), target.Options{
		Specs:      specs,
		Ports:      ports,
		Blacklist:  splitList(*blacklistSpec),
		MaxTargets: *maxTargets,
	})
	for _, warning := range res.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", warning)
	}
	if err != nil {
		fmt.Fprintf(stderr, "rdpshot targets: resolve targets: %v\n", err)
		return exitUsage
	}
	for _, ep := range res.Endpoints {
		fmt.Fprintln(stdout, ep.Key())
	}
	if len(res.Endpoints) == 0 {
		fmt.Fprintln(stderr, "warning: no endpoints resolved from the given targets")
	}
	return exitOK
}
