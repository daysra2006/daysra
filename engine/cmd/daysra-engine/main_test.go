package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMainVersion(t *testing.T) {
	if code := run([]string{"--version"}); code != 0 {
		t.Errorf("run(--version) = %d, want 0", code)
	}
	if code := run([]string{"-version"}); code != 0 {
		t.Errorf("run(-version) = %d, want 0", code)
	}
}

func TestMainUnknownCommand(t *testing.T) {
	if code := run([]string{"unknown"}); code != 2 {
		t.Errorf("run(unknown) = %d, want 2", code)
	}
	if code := run([]string{}); code != 2 {
		t.Errorf("run() = %d, want 2", code)
	}
}

func TestCheckScopeCommand(t *testing.T) {
	tempDir := t.TempDir()
	scopePath := filepath.Join(tempDir, "scope.yaml")
	scopeContent := `authorization: owned lab
allow:
  - example.com
  - '*.example.com'
  - xn--mnchen-3ya.de
deny:
  - admin.example.com
`
	if err := os.WriteFile(scopePath, []byte(scopeContent), 0600); err != nil {
		t.Fatalf("failed to write test scope.yaml: %v", err)
	}

	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{
			name:     "allowed apex target",
			args:     []string{"check-scope", "--scope", scopePath, "--target", "example.com"},
			wantCode: 0,
		},
		{
			name:     "allowed subdomain target",
			args:     []string{"check-scope", "--scope", scopePath, "--target", "api.example.com"},
			wantCode: 0,
		},
		{
			name:     "allowed IDN target converted to punycode",
			args:     []string{"check-scope", "--scope", scopePath, "--target", "münchen.de"},
			wantCode: 0,
		},
		{
			name:     "denied target returns 2",
			args:     []string{"check-scope", "--scope", scopePath, "--target", "admin.example.com"},
			wantCode: 2,
		},
		{
			name:     "out of scope target returns 2",
			args:     []string{"check-scope", "--scope", scopePath, "--target", "other-domain.com"},
			wantCode: 2,
		},
		{
			name:     "invalid target hostname returns 2",
			args:     []string{"check-scope", "--scope", scopePath, "--target", "bad host"},
			wantCode: 2,
		},
		{
			name:     "missing target returns 2",
			args:     []string{"check-scope", "--scope", scopePath},
			wantCode: 2,
		},
		{
			name:     "missing scope returns 2",
			args:     []string{"check-scope", "--target", "example.com"},
			wantCode: 2,
		},
		{
			name:     "non-existent scope file returns 2",
			args:     []string{"check-scope", "--scope", filepath.Join(tempDir, "nonexistent.yaml"), "--target", "example.com"},
			wantCode: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if code := run(tt.args); code != tt.wantCode {
				t.Errorf("run(%v) = %d, want %d", tt.args, code, tt.wantCode)
			}
		})
	}
}

// Helper process used as fake subfinder binary during testing.
func TestReconFakeSubfinderProcess(t *testing.T) {
	if os.Getenv("GO_WANT_RECON_HELPER") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}

	mode := os.Getenv("FAKE_SUBFINDER_MODE")

	for _, a := range args {
		if a == "-version" {
			switch mode {
			case "version-fail":
				os.Stderr.WriteString("error: initialization failure\n")
				os.Exit(1)
			case "version-diff":
				os.Stderr.WriteString("[INF] Current Version: v2.16.0\n")
				os.Exit(0)
			default:
				os.Stderr.WriteString("[INF] Current Version: v2.17.0\n[INF] Subfinder Config: /home/user/.config\n")
				os.Exit(0)
			}
		}
	}

	switch mode {
	case "normal":
		os.Stderr.WriteString("[INF] Enumerating subdomains for target\n")
		// In scope host 1
		os.Stdout.WriteString("{\"host\":\"api.example.com\",\"input\":\"example.com\",\"sources\":[\"alienvault\",\"crtsh\"]}\n")
		// In scope host 2
		os.Stdout.WriteString("{\"host\":\"web.example.com\",\"input\":\"example.com\",\"sources\":[\"crtsh\"]}\n")
		// Out of scope host (should be filtered)
		os.Stdout.WriteString("{\"host\":\"outside.com\",\"input\":\"example.com\",\"sources\":[\"alienvault\"]}\n")
		// Denied by scope (should be filtered)
		os.Stdout.WriteString("{\"host\":\"admin.example.com\",\"input\":\"example.com\",\"sources\":[\"crtsh\"]}\n")
		// Duplicate of api.example.com with different source
		os.Stdout.WriteString("{\"host\":\"api.example.com\",\"input\":\"example.com\",\"sources\":[\"censys\"]}\n")
		os.Stderr.WriteString("[INF] Done finding subdomains\n")
		os.Exit(0)

	case "corrupt":
		os.Stderr.WriteString("[INF] Starting scan\n")
		os.Stdout.WriteString("{\"host\":\"api.example.com\",\"sources\":[\"crtsh\"]}\n")
		os.Stdout.WriteString("{corrupt json line\n")
		os.Stdout.WriteString("{\"no_host\":true}\n")
		os.Stdout.WriteString("{\"host\":\"valid.example.com\",\"sources\":[\"alienvault\"]}\n")
		os.Exit(0)

	case "noisy":
		for i := 0; i < 20; i++ {
			fmt.Fprintf(os.Stderr, "[INF] noisy log line %d\n", i)
		}
		os.Stdout.WriteString("{\"host\":\"api.example.com\",\"sources\":[\"crtsh\"]}\n")
		os.Exit(0)

	case "timeout":
		time.Sleep(3 * time.Second)
		os.Exit(0)

	case "sigint":
		time.Sleep(5 * time.Second)
		os.Exit(0)

	case "fail":
		os.Stderr.WriteString("fatal subfinder failure\n")
		os.Exit(2)

	default:
		os.Exit(0)
	}
}

func createFakeSubfinder(t *testing.T, mode string) string {
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "fake-subfinder")
	script := fmt.Sprintf("#!/bin/sh\nexport GO_WANT_RECON_HELPER=1\nexport FAKE_SUBFINDER_MODE=%q\nexec %q -test.run=TestReconFakeSubfinderProcess -- \"$@\"\n", mode, os.Args[0])
	if err := os.WriteFile(binPath, []byte(script), 0755); err != nil {
		t.Fatalf("failed to create fake subfinder script: %v", err)
	}
	return binPath
}

func createTestScope(t *testing.T, allow []string, deny []string, timeout int) string {
	tempDir := t.TempDir()
	scopePath := filepath.Join(tempDir, "scope.yaml")
	var sb strings.Builder
	sb.WriteString("authorization: test authorization\nallow:\n")
	for _, a := range allow {
		sb.WriteString("  - '" + a + "'\n")
	}
	if len(deny) > 0 {
		sb.WriteString("deny:\n")
		for _, d := range deny {
			sb.WriteString("  - '" + d + "'\n")
		}
	}
	if timeout > 0 {
		sb.WriteString(fmt.Sprintf("timeout: %d\n", timeout))
	}
	if err := os.WriteFile(scopePath, []byte(sb.String()), 0600); err != nil {
		t.Fatalf("failed to write test scope.yaml: %v", err)
	}
	return scopePath
}

type eventRecord struct {
	SchemaVersion string         `json:"schema_version"`
	Type          string         `json:"type"`
	RunID         string         `json:"run_id"`
	Timestamp     string         `json:"ts"`
	Data          map[string]any `json:"data"`
}

func parseEvents(t *testing.T, output string, expectedRunID string) []eventRecord {
	var events []eventRecord
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev eventRecord
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("failed to parse event JSON %q: %v", line, err)
		}
		if ev.SchemaVersion != "1" {
			t.Errorf("expected schema_version 1, got %q", ev.SchemaVersion)
		}
		if ev.RunID != expectedRunID {
			t.Errorf("expected run_id %q, got %q", expectedRunID, ev.RunID)
		}
		if _, err := time.Parse(time.RFC3339, ev.Timestamp); err != nil {
			t.Errorf("invalid timestamp %q: %v", ev.Timestamp, err)
		}
		events = append(events, ev)
	}
	return events
}

func TestReconNormalOutput(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, []string{"admin.example.com"}, 600)
	fakeBin := createFakeSubfinder(t, "normal")
	runID := "01JTESTRECONNORMAL000000000"

	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"recon",
		"--target", "example.com",
		"--scope", scopePath,
		"--run-id", runID,
		"--subfinder-bin", fakeBin,
	}

	code := runWithIO(context.Background(), args, &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(recon) exit code = %d, want 0; stderr: %s", code, stderrBuf.String())
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	if len(events) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(events))
	}

	// 1. Check run_start
	if events[0].Type != "run_start" {
		t.Errorf("events[0].Type = %s, want run_start", events[0].Type)
	}
	if events[0].Data["target"] != "example.com" {
		t.Errorf("run_start target = %v, want example.com", events[0].Data["target"])
	}

	// 2. Collect host events and warning events
	var hosts []string
	var warnings []string
	var runEndEvent *eventRecord

	for i := range events {
		ev := &events[i]
		switch ev.Type {
		case "host":
			if h, ok := ev.Data["hostname"].(string); ok {
				hosts = append(hosts, h)
			}
		case "warning":
			if msg, ok := ev.Data["message"].(string); ok {
				warnings = append(warnings, msg)
			}
		case "run_end":
			runEndEvent = ev
		}
	}

	// Host deduplication and filtering
	if len(hosts) != 2 {
		t.Errorf("expected 2 unique hosts, got %d: %v", len(hosts), hosts)
	}
	if hosts[0] != "api.example.com" || hosts[1] != "web.example.com" {
		t.Errorf("unexpected hosts: %v", hosts)
	}

	// Verify out-of-scope hosts were filtered and emitted as warning count
	foundScopeWarning := false
	for _, w := range warnings {
		if strings.Contains(w, "filtered out of scope") {
			foundScopeWarning = true
			break
		}
	}
	if !foundScopeWarning {
		t.Errorf("expected out of scope warning, got warnings: %v", warnings)
	}

	// Check run_end event
	if runEndEvent == nil {
		t.Fatal("missing run_end event")
	}
	if runEndEvent.Data["status"] != "complete" {
		t.Errorf("run_end status = %v, want complete", runEndEvent.Data["status"])
	}
	if total, ok := runEndEvent.Data["total_hosts"].(float64); !ok || int(total) != 2 {
		t.Errorf("run_end total_hosts = %v, want 2", runEndEvent.Data["total_hosts"])
	}

	// Check stderr contains logged output
	if !strings.Contains(stderrBuf.String(), "[subfinder log]") {
		t.Errorf("expected stderr to contain [subfinder log], got %q", stderrBuf.String())
	}
}

func TestReconCorruptJSONLines(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, nil, 600)
	fakeBin := createFakeSubfinder(t, "corrupt")
	runID := "01JTESTRECONCORRUPT00000000"

	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"recon",
		"--target", "example.com",
		"--scope", scopePath,
		"--run-id", runID,
		"--subfinder-bin", fakeBin,
	}

	code := runWithIO(context.Background(), args, &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(recon) exit code = %d, want 0; stderr: %s", code, stderrBuf.String())
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	var hosts []string
	var foundCorruptWarning bool

	for _, ev := range events {
		if ev.Type == "host" {
			hosts = append(hosts, ev.Data["hostname"].(string))
		}
		if ev.Type == "warning" && strings.Contains(ev.Data["message"].(string), "corrupt output lines skipped") {
			foundCorruptWarning = true
			if count, ok := ev.Data["count"].(float64); !ok || int(count) != 2 {
				t.Errorf("warning count = %v, want 2", ev.Data["count"])
			}
		}
	}

	if len(hosts) != 2 {
		t.Errorf("expected 2 valid hosts, got %d: %v", len(hosts), hosts)
	}
	if !foundCorruptWarning {
		t.Errorf("expected corrupt lines warning event in stdout")
	}
}

func TestReconNoisyStderr(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, nil, 600)
	fakeBin := createFakeSubfinder(t, "noisy")
	runID := "01JTESTRECONNOISY0000000000"

	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"recon",
		"--target", "example.com",
		"--scope", scopePath,
		"--run-id", runID,
		"--subfinder-bin", fakeBin,
	}

	code := runWithIO(context.Background(), args, &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(recon) exit code = %d, want 0", code)
	}

	// Verify stdout contains ONLY valid JSON events
	events := parseEvents(t, stdoutBuf.String(), runID)
	if len(events) == 0 {
		t.Fatal("expected events on stdout")
	}

	// Verify stderr received the noise
	if !strings.Contains(stderrBuf.String(), "noisy log line 0") || !strings.Contains(stderrBuf.String(), "noisy log line 19") {
		t.Errorf("expected stderr to contain all noisy log lines, got: %s", stderrBuf.String())
	}
}

func TestReconTimeout(t *testing.T) {
	// Set scope timeout to 1 second
	scopePath := createTestScope(t, []string{"example.com"}, nil, 1)
	fakeBin := createFakeSubfinder(t, "timeout")
	runID := "01JTESTRECONTIMEOUT00000000"

	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"recon",
		"--target", "example.com",
		"--scope", scopePath,
		"--run-id", runID,
		"--subfinder-bin", fakeBin,
	}

	start := time.Now()
	code := runWithIO(context.Background(), args, &stdoutBuf, &stderrBuf)
	elapsed := time.Since(start)

	if code != 4 {
		t.Errorf("run(recon) exit code = %d, want 4 (partial on timeout)", code)
	}
	if elapsed > 2500*time.Millisecond {
		t.Errorf("command took too long: %v", elapsed)
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	var runEndEvent *eventRecord
	for i := range events {
		if events[i].Type == "run_end" {
			runEndEvent = &events[i]
		}
	}

	if runEndEvent == nil {
		t.Fatal("missing run_end event on timeout")
	}
	if runEndEvent.Data["status"] != "partial" {
		t.Errorf("run_end status = %v, want partial", runEndEvent.Data["status"])
	}
}

func TestReconCancelled(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 600)
	fakeBin := createFakeSubfinder(t, "sigint")
	runID := "01JTESTRECONCANCEL000000000"

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"recon",
		"--target", "example.com",
		"--scope", scopePath,
		"--run-id", runID,
		"--subfinder-bin", fakeBin,
	}

	code := runWithIO(ctx, args, &stdoutBuf, &stderrBuf)
	if code != 130 {
		t.Errorf("run(recon) exit code = %d, want 130 (cancelled)", code)
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	var runEndEvent *eventRecord
	for i := range events {
		if events[i].Type == "run_end" {
			runEndEvent = &events[i]
		}
	}

	if runEndEvent == nil {
		t.Fatal("missing run_end event on cancellation")
	}
	if runEndEvent.Data["status"] != "cancelled" {
		t.Errorf("run_end status = %v, want cancelled", runEndEvent.Data["status"])
	}
}

func TestReconMissingSubfinder(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 600)
	runID := "01JTESTRECONMISSING00000000"

	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"recon",
		"--target", "example.com",
		"--scope", scopePath,
		"--run-id", runID,
		"--subfinder-bin", "/nonexistent/subfinder/bin/xyz123",
	}

	code := runWithIO(context.Background(), args, &stdoutBuf, &stderrBuf)
	if code != 3 {
		t.Errorf("run(recon) exit code = %d, want 3", code)
	}
	if stdoutBuf.Len() > 0 {
		t.Errorf("expected no stdout on missing binary, got %q", stdoutBuf.String())
	}
	if !strings.Contains(stderrBuf.String(), "subfinder binary not found") && !strings.Contains(stderrBuf.String(), "no such file or directory") {
		t.Errorf("expected binary not found error in stderr, got %q", stderrBuf.String())
	}
}

func TestReconVersionMismatchWarning(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 600)
	fakeBin := createFakeSubfinder(t, "version-diff")
	runID := "01JTESTRECONVERDIFF00000000"

	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"recon",
		"--target", "example.com",
		"--scope", scopePath,
		"--run-id", runID,
		"--subfinder-bin", fakeBin,
	}

	code := runWithIO(context.Background(), args, &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(recon) exit code = %d, want 0", code)
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	var foundVerWarn bool
	for _, ev := range events {
		if ev.Type == "warning" && strings.Contains(ev.Data["message"].(string), "differs from expected fixture version") {
			foundVerWarn = true
		}
	}
	if !foundVerWarn {
		t.Errorf("expected version difference warning event, got events: %v", events)
	}
}

func TestReconTargetOutOfScope(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 600)
	runID := "01JTESTRECONOUTOFSCOPE0000"

	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"recon",
		"--target", "evil.com",
		"--scope", scopePath,
		"--run-id", runID,
	}

	code := runWithIO(context.Background(), args, &stdoutBuf, &stderrBuf)
	if code != 2 {
		t.Errorf("run(recon) exit code = %d, want 2", code)
	}
	if stdoutBuf.Len() > 0 {
		t.Errorf("expected no events on out of scope target, got %q", stdoutBuf.String())
	}
	if !strings.Contains(stderrBuf.String(), "is out of scope") {
		t.Errorf("expected 'out of scope' in stderr, got %q", stderrBuf.String())
	}
}

func TestReconMissingRequiredFlags(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 600)

	tests := []struct {
		name string
		args []string
	}{
		{"missing target", []string{"recon", "--scope", scopePath, "--run-id", "01J..."}},
		{"missing scope", []string{"recon", "--target", "example.com", "--run-id", "01J..."}},
		{"missing run-id", []string{"recon", "--target", "example.com", "--scope", scopePath}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdoutBuf, stderrBuf bytes.Buffer
			code := runWithIO(context.Background(), tt.args, &stdoutBuf, &stderrBuf)
			if code != 2 {
				t.Errorf("code = %d, want 2", code)
			}
		})
	}
}

// Helper process used as fake httpx binary during testing.
func TestProbeFakeHttpxProcess(t *testing.T) {
	if os.Getenv("GO_WANT_PROBE_HELPER") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}

	mode := os.Getenv("FAKE_HTTPX_MODE")

	for _, a := range args {
		if a == "-version" {
			switch mode {
			case "version-fail":
				os.Stderr.WriteString("error: initialization failure\n")
				os.Exit(1)
			case "version-diff":
				os.Stderr.WriteString("[INF] Current Version: v1.11.0\n")
				os.Exit(0)
			default:
				os.Stderr.WriteString("[INF] Current Version: v1.12.0\n")
				os.Exit(0)
			}
		}
	}

	switch mode {
	case "normal":
		os.Stderr.WriteString("[INF] Starting probing\n")
		os.Stdout.WriteString("{\"url\":\"https://api.example.com\",\"host\":\"api.example.com\",\"status_code\":200,\"title\":\"API\",\"tech\":[\"Nginx\"],\"content_length\":512}\n")
		os.Stdout.WriteString("{\"url\":\"http://web.example.com\",\"host\":\"web.example.com\",\"status_code\":200,\"title\":\"Web\",\"tech\":[\"Apache\"],\"content_length\":1024}\n")
		os.Stderr.WriteString("[INF] Probing finished\n")
		os.Exit(0)

	case "out-of-scope":
		os.Stderr.WriteString("[INF] Starting probing\n")
		// In-scope observation
		os.Stdout.WriteString("{\"url\":\"https://api.example.com\",\"host\":\"api.example.com\",\"status_code\":200,\"title\":\"API\",\"tech\":[\"Nginx\"],\"content_length\":512}\n")
		// Out-of-scope observation 1
		os.Stdout.WriteString("{\"url\":\"https://evil.com\",\"host\":\"evil.com\",\"status_code\":200,\"title\":\"Evil\",\"tech\":[],\"content_length\":100}\n")
		// Out-of-scope observation 2 (denied by scope)
		os.Stdout.WriteString("{\"url\":\"https://admin.example.com\",\"host\":\"admin.example.com\",\"status_code\":200,\"title\":\"Admin\",\"tech\":[],\"content_length\":200}\n")
		os.Stderr.WriteString("[INF] Probing finished\n")
		os.Exit(0)

	case "corrupt":
		os.Stderr.WriteString("[INF] Starting probing\n")
		os.Stdout.WriteString("{\"url\":\"https://api.example.com\",\"host\":\"api.example.com\",\"status_code\":200,\"title\":\"API\",\"tech\":[\"Nginx\"],\"content_length\":512}\n")
		os.Stdout.WriteString("{broken json line\n")
		os.Stdout.WriteString("{\"no_host_or_url\":true}\n")
		os.Stdout.WriteString("{\"url\":\"http://web.example.com\",\"host\":\"web.example.com\",\"status_code\":200,\"title\":\"Web\",\"tech\":[\"Apache\"],\"content_length\":1024}\n")
		os.Stderr.WriteString("[INF] Probing finished\n")
		os.Exit(0)

	case "noisy":
		for i := 0; i < 20; i++ {
			fmt.Fprintf(os.Stderr, "[INF] noisy log line %d\n", i)
		}
		os.Stdout.WriteString("{\"url\":\"https://api.example.com\",\"host\":\"api.example.com\",\"status_code\":200,\"title\":\"API\",\"tech\":[\"Nginx\"],\"content_length\":512}\n")
		os.Exit(0)

	case "timeout":
		time.Sleep(3 * time.Second)
		os.Exit(0)

	case "sigint":
		time.Sleep(5 * time.Second)
		os.Exit(0)

	default:
		os.Exit(0)
	}
}

func createFakeHttpx(t *testing.T, mode string) string {
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "fake-httpx")
	script := fmt.Sprintf("#!/bin/sh\nexport GO_WANT_PROBE_HELPER=1\nexport FAKE_HTTPX_MODE=%q\nexec %q -test.run=TestProbeFakeHttpxProcess -- \"$@\"\n", mode, os.Args[0])
	if err := os.WriteFile(binPath, []byte(script), 0755); err != nil {
		t.Fatalf("failed to create fake httpx script: %v", err)
	}
	return binPath
}

func TestProbeNormalOutput(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, []string{"admin.example.com"}, 600)
	fakeBin := createFakeHttpx(t, "normal")
	runID := "01JTESTPROBENORMAL000000000"

	input := "api.example.com\nweb.example.com\n"
	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"probe",
		"--scope", scopePath,
		"--run-id", runID,
		"--httpx-bin", fakeBin,
	}

	code := runWithIOStdin(context.Background(), args, strings.NewReader(input), &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(probe) exit code = %d, want 0; stderr: %s", code, stderrBuf.String())
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	if len(events) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(events))
	}

	// 1. Check run_start
	if events[0].Type != "run_start" {
		t.Errorf("events[0].Type = %s, want run_start", events[0].Type)
	}

	// 2. Collect http events
	var httpObs []map[string]any
	var runEndEvent *eventRecord

	for i := range events {
		ev := &events[i]
		switch ev.Type {
		case "http":
			httpObs = append(httpObs, ev.Data)
		case "run_end":
			runEndEvent = ev
		}
	}

	if len(httpObs) != 2 {
		t.Fatalf("expected 2 http observation events, got %d", len(httpObs))
	}

	if httpObs[0]["hostname"] != "api.example.com" || httpObs[0]["url"] != "https://api.example.com" {
		t.Errorf("unexpected http observation 0: %v", httpObs[0])
	}
	if httpObs[1]["hostname"] != "web.example.com" || httpObs[1]["url"] != "http://web.example.com" {
		t.Errorf("unexpected http observation 1: %v", httpObs[1])
	}

	// 3. Check run_end
	if runEndEvent == nil {
		t.Fatal("missing run_end event")
	}
	if runEndEvent.Data["status"] != "complete" {
		t.Errorf("run_end status = %v, want complete", runEndEvent.Data["status"])
	}
	if total, ok := runEndEvent.Data["total_http"].(float64); !ok || int(total) != 2 {
		t.Errorf("run_end total_http = %v, want 2", runEndEvent.Data["total_http"])
	}

	// 4. Check stderr contains logged output
	if !strings.Contains(stderrBuf.String(), "[httpx log]") {
		t.Errorf("expected stderr to contain [httpx log], got %q", stderrBuf.String())
	}
}

func TestProbeCorruptJSONLines(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, nil, 600)
	fakeBin := createFakeHttpx(t, "corrupt")
	runID := "01JTESTPROBECORRUPT00000000"

	input := "api.example.com\nweb.example.com\n"
	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"probe",
		"--scope", scopePath,
		"--run-id", runID,
		"--httpx-bin", fakeBin,
	}

	code := runWithIOStdin(context.Background(), args, strings.NewReader(input), &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(probe) exit code = %d, want 0; stderr: %s", code, stderrBuf.String())
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	var httpObs []map[string]any
	var foundCorruptWarning bool

	for _, ev := range events {
		if ev.Type == "http" {
			httpObs = append(httpObs, ev.Data)
		}
		if ev.Type == "warning" && strings.Contains(ev.Data["message"].(string), "corrupt output lines skipped") {
			foundCorruptWarning = true
			if count, ok := ev.Data["count"].(float64); !ok || int(count) != 2 {
				t.Errorf("warning count = %v, want 2", ev.Data["count"])
			}
		}
	}

	if len(httpObs) != 2 {
		t.Errorf("expected 2 valid http events, got %d: %v", len(httpObs), httpObs)
	}
	if !foundCorruptWarning {
		t.Errorf("expected corrupt lines warning event in stdout")
	}
}

func TestProbeNoisyStderr(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, nil, 600)
	fakeBin := createFakeHttpx(t, "noisy")
	runID := "01JTESTPROBENOISY0000000000"

	input := "api.example.com\n"
	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"probe",
		"--scope", scopePath,
		"--run-id", runID,
		"--httpx-bin", fakeBin,
	}

	code := runWithIOStdin(context.Background(), args, strings.NewReader(input), &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(probe) exit code = %d, want 0", code)
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	if len(events) == 0 {
		t.Fatal("expected events on stdout")
	}

	if !strings.Contains(stderrBuf.String(), "noisy log line 0") || !strings.Contains(stderrBuf.String(), "noisy log line 19") {
		t.Errorf("expected stderr to contain all noisy log lines, got: %s", stderrBuf.String())
	}
}

func TestProbeTimeout(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 1)
	fakeBin := createFakeHttpx(t, "timeout")
	runID := "01JTESTPROBETIMEOUT00000000"

	input := "example.com\n"
	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"probe",
		"--scope", scopePath,
		"--run-id", runID,
		"--httpx-bin", fakeBin,
	}

	start := time.Now()
	code := runWithIOStdin(context.Background(), args, strings.NewReader(input), &stdoutBuf, &stderrBuf)
	elapsed := time.Since(start)

	if code != 4 {
		t.Errorf("run(probe) exit code = %d, want 4 (partial on timeout)", code)
	}
	if elapsed > 2500*time.Millisecond {
		t.Errorf("command took too long: %v", elapsed)
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	var runEndEvent *eventRecord
	for i := range events {
		if events[i].Type == "run_end" {
			runEndEvent = &events[i]
		}
	}

	if runEndEvent == nil {
		t.Fatal("missing run_end event on timeout")
	}
	if runEndEvent.Data["status"] != "partial" {
		t.Errorf("run_end status = %v, want partial", runEndEvent.Data["status"])
	}
}

func TestProbeCancelled(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 600)
	fakeBin := createFakeHttpx(t, "sigint")
	runID := "01JTESTPROBECANCEL000000000"

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	input := "example.com\n"
	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"probe",
		"--scope", scopePath,
		"--run-id", runID,
		"--httpx-bin", fakeBin,
	}

	code := runWithIOStdin(ctx, args, strings.NewReader(input), &stdoutBuf, &stderrBuf)
	if code != 130 {
		t.Errorf("run(probe) exit code = %d, want 130 (cancelled)", code)
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	var runEndEvent *eventRecord
	for i := range events {
		if events[i].Type == "run_end" {
			runEndEvent = &events[i]
		}
	}

	if runEndEvent == nil {
		t.Fatal("missing run_end event on cancellation")
	}
	if runEndEvent.Data["status"] != "cancelled" {
		t.Errorf("run_end status = %v, want cancelled", runEndEvent.Data["status"])
	}
}

func TestProbeOutOfScopeOutputFiltered(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, []string{"admin.example.com"}, 600)
	fakeBin := createFakeHttpx(t, "out-of-scope")
	runID := "01JTESTPROBEOUTSCOPE0000000"

	input := "api.example.com\n"
	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"probe",
		"--scope", scopePath,
		"--run-id", runID,
		"--httpx-bin", fakeBin,
	}

	code := runWithIOStdin(context.Background(), args, strings.NewReader(input), &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(probe) exit code = %d, want 0; stderr: %s", code, stderrBuf.String())
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	var httpObs []map[string]any
	var foundScopeWarning bool
	var warningCount int

	for _, ev := range events {
		if ev.Type == "http" {
			httpObs = append(httpObs, ev.Data)
		}
		if ev.Type == "warning" && strings.Contains(ev.Data["message"].(string), "hosts filtered out of scope") {
			foundScopeWarning = true
			if c, ok := ev.Data["count"].(float64); ok {
				warningCount = int(c)
			}
		}
	}

	// Only api.example.com should be emitted
	if len(httpObs) != 1 {
		t.Fatalf("expected 1 in-scope http event, got %d: %v", len(httpObs), httpObs)
	}
	if httpObs[0]["hostname"] != "api.example.com" {
		t.Errorf("expected api.example.com, got %v", httpObs[0]["hostname"])
	}

	if !foundScopeWarning {
		t.Errorf("expected out-of-scope warning event")
	}
	if warningCount != 2 {
		t.Errorf("expected 2 out-of-scope warnings, got %d", warningCount)
	}
}

func TestProbeMissingHttpx(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 600)
	runID := "01JTESTPROBEMISSING00000000"

	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"probe",
		"--scope", scopePath,
		"--run-id", runID,
		"--httpx-bin", "/nonexistent/httpx/bin/xyz123",
	}

	code := runWithIOStdin(context.Background(), args, strings.NewReader("example.com\n"), &stdoutBuf, &stderrBuf)
	if code != 3 {
		t.Errorf("run(probe) exit code = %d, want 3", code)
	}
	if stdoutBuf.Len() > 0 {
		t.Errorf("expected no stdout on missing binary, got %q", stdoutBuf.String())
	}
	if !strings.Contains(stderrBuf.String(), "httpx binary not found") && !strings.Contains(stderrBuf.String(), "no such file or directory") {
		t.Errorf("expected binary not found error in stderr, got %q", stderrBuf.String())
	}
}

func TestProbeMissingRequiredFlags(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 600)

	tests := []struct {
		name string
		args []string
	}{
		{"missing scope", []string{"probe", "--run-id", "01J..."}},
		{"missing run-id", []string{"probe", "--scope", scopePath}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdoutBuf, stderrBuf bytes.Buffer
			code := runWithIOStdin(context.Background(), tt.args, strings.NewReader(""), &stdoutBuf, &stderrBuf)
			if code != 2 {
				t.Errorf("code = %d, want 2", code)
			}
		})
	}
}

func createFakeNuclei(t *testing.T, mode string) string {
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "fake-nuclei")
	script := fmt.Sprintf("#!/bin/sh\nexport GO_WANT_SCAN_HELPER=1\nexport FAKE_NUCLEI_MODE=%q\nexec %q -test.run=TestScanFakeNucleiProcess -- \"$@\"\n", mode, os.Args[0])
	if err := os.WriteFile(binPath, []byte(script), 0755); err != nil {
		t.Fatalf("failed to create fake nuclei script: %v", err)
	}
	return binPath
}

func TestScanFakeNucleiProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SCAN_HELPER") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}

	mode := os.Getenv("FAKE_NUCLEI_MODE")

	for _, a := range args {
		if a == "-version" {
			switch mode {
			case "version-fail":
				os.Stderr.WriteString("error: initialization failure\n")
				os.Exit(1)
			case "version-diff":
				os.Stderr.WriteString("[INF] Nuclei Engine Version: v3.10.0\n")
				os.Exit(0)
			default:
				os.Stderr.WriteString("[INF] Nuclei Engine Version: v3.11.1\n")
				os.Exit(0)
			}
		}
	}

	switch mode {
	case "derived":
		data, err := os.ReadFile("../../../tests/fixtures/tools/nuclei/v3.11.1/derived/output.jsonl")
		if err != nil {
			os.Stderr.WriteString("cannot read derived fixture: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Stdout.Write(data)
		os.Exit(0)
	case "raw":
		data, err := os.ReadFile("../../../tests/fixtures/tools/nuclei/v3.11.1/output.jsonl")
		if err != nil {
			os.Stderr.WriteString("cannot read raw fixture: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Stdout.Write(data)
		os.Exit(0)
	case "corrupt":
		os.Stdout.WriteString("not json at all\n")
		os.Stdout.WriteString("{\"template-id\":\"corrupt-test\"\n")
		os.Exit(0)
	default:
		os.Stderr.WriteString("unknown mode\n")
		os.Exit(1)
	}
}

func TestScanScopeFilteringWithDerivedFixture(t *testing.T) {
	// Scope allows example.com and subdomains, but denies admin.example.com
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, []string{"admin.example.com"}, 600)
	fakeBin := createFakeNuclei(t, "derived")
	runID := "01JTESTSCANDERIVED000000000"

	input := "http://app.example.com:3000\n"
	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"scan",
		"--scope", scopePath,
		"--run-id", runID,
		"--nuclei-bin", fakeBin,
	}

	code := runWithIOStdin(context.Background(), args, strings.NewReader(input), &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(scan) exit code = %d, want 0; stderr: %s", code, stderrBuf.String())
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	var findings []map[string]any
	var outOfScopeWarnings int

	for _, ev := range events {
		if ev.Type == "finding" {
			findings = append(findings, ev.Data)
		}
		if ev.Type == "warning" && strings.Contains(ev.Data["message"].(string), "findings filtered out of scope") {
			if c, ok := ev.Data["count"].(float64); ok {
				outOfScopeWarnings = int(c)
			}
		}
	}

	// Derived fixture has 13 findings against app.example.com (all in scope)
	if len(findings) != 13 {
		t.Fatalf("expected 13 in-scope findings, got %d", len(findings))
	}
	if outOfScopeWarnings != 0 {
		t.Errorf("expected 0 out of scope warnings, got %d", outOfScopeWarnings)
	}

	// Verify required fields in findings
	for i, f := range findings {
		if f["template_id"] == nil || f["template_id"] == "" {
			t.Errorf("finding %d missing template_id", i)
		}
		if f["name"] == nil || f["name"] == "" {
			t.Errorf("finding %d missing name", i)
		}
		if f["severity"] == nil || f["severity"] == "" {
			t.Errorf("finding %d missing severity", i)
		}
		if f["hostname"] != "app.example.com" {
			t.Errorf("finding %d hostname = %v, want app.example.com", i, f["hostname"])
		}
		if f["tool"] != "nuclei" {
			t.Errorf("finding %d tool = %v, want nuclei", i, f["tool"])
		}
		if f["tool_version"] != "v3.11.1" {
			t.Errorf("finding %d tool_version = %v, want v3.11.1", i, f["tool_version"])
		}
		// Request, response, curl_command must NOT be present
		if _, exists := f["request"]; exists {
			t.Errorf("finding %d leaks request", i)
		}
		if _, exists := f["response"]; exists {
			t.Errorf("finding %d leaks response", i)
		}
	}

	// Now test when scope denies app.example.com (out-of-scope test)
	scopePathOutOfScope := createTestScope(t, []string{"otherdomain.org"}, nil, 600)
	var stdoutBuf2, stderrBuf2 bytes.Buffer
	args2 := []string{
		"scan",
		"--scope", scopePathOutOfScope,
		"--run-id", runID,
		"--nuclei-bin", fakeBin,
	}

	// Host in input is in-scope for input, but let's see if output has different host or input host is filtered
	code2 := runWithIOStdin(context.Background(), args2, strings.NewReader("http://otherdomain.org\n"), &stdoutBuf2, &stderrBuf2)
	if code2 != 0 {
		t.Fatalf("run(scan) exit code = %d, want 0; stderr: %s", code2, stderrBuf2.String())
	}
	events2 := parseEvents(t, stdoutBuf2.String(), runID)
	var findings2 []map[string]any
	var foundScopeWarning2 bool
	for _, ev := range events2 {
		if ev.Type == "finding" {
			findings2 = append(findings2, ev.Data)
		}
		if ev.Type == "warning" && strings.Contains(ev.Data["message"].(string), "findings filtered out of scope") {
			foundScopeWarning2 = true
		}
	}
	if len(findings2) != 0 {
		t.Errorf("expected 0 findings when output host app.example.com is not in scope, got %d", len(findings2))
	}
	if !foundScopeWarning2 {
		t.Errorf("expected out of scope warning for findings")
	}
}

func TestScanRawLiteralIPFilteredOutOfScope(t *testing.T) {
	// Raw fixture has literal IP 127.0.0.1 which is rejected by DAYSRA scope
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, nil, 600)
	fakeBin := createFakeNuclei(t, "raw")
	runID := "01JTESTSCANRAW000000000000"

	input := "http://example.com:3000\n"
	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"scan",
		"--scope", scopePath,
		"--run-id", runID,
		"--nuclei-bin", fakeBin,
	}

	code := runWithIOStdin(context.Background(), args, strings.NewReader(input), &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(scan) exit code = %d, want 0; stderr: %s", code, stderrBuf.String())
	}

	events := parseEvents(t, stdoutBuf.String(), runID)
	var findings []map[string]any
	var foundWarning bool

	for _, ev := range events {
		if ev.Type == "finding" {
			findings = append(findings, ev.Data)
		}
		if ev.Type == "warning" && strings.Contains(ev.Data["message"].(string), "findings filtered out of scope") {
			foundWarning = true
		}
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for raw fixture (literal IPs are out of scope), got %d", len(findings))
	}
	if !foundWarning {
		t.Errorf("expected out of scope warning for literal IP findings")
	}
}

func TestScanMissingRequiredFlags(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 600)

	tests := []struct {
		name string
		args []string
	}{
		{"missing scope", []string{"scan", "--run-id", "01J..."}},
		{"missing run-id", []string{"scan", "--scope", scopePath}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdoutBuf, stderrBuf bytes.Buffer
			code := runWithIOStdin(context.Background(), tt.args, strings.NewReader(""), &stdoutBuf, &stderrBuf)
			if code != 2 {
				t.Errorf("code = %d, want 2", code)
			}
		})
	}
}

func TestScanMissingNuclei(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com"}, nil, 600)
	runID := "01JTESTSCANMISSING00000000"

	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"scan",
		"--scope", scopePath,
		"--run-id", runID,
		"--nuclei-bin", "/nonexistent/nuclei/bin/xyz123",
	}

	code := runWithIOStdin(context.Background(), args, strings.NewReader("http://example.com\n"), &stdoutBuf, &stderrBuf)
	if code != 3 {
		t.Errorf("run(scan) exit code = %d, want 3", code)
	}
}

func TestScanIncludeTagsDefaultLoginWarning(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, nil, 600)
	fakeBin := createFakeNuclei(t, "derived")
	runID := "01JTESTSCANLOGINWARN00000000"

	input := "http://app.example.com:3000\n"
	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"scan",
		"--scope", scopePath,
		"--run-id", runID,
		"--nuclei-bin", fakeBin,
		"--include-tags", "default-login",
	}

	code := runWithIOStdin(context.Background(), args, strings.NewReader(input), &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(scan) exit code = %d, want 0; stderr: %s", code, stderrBuf.String())
	}

	// Verify stderr warning
	stderrStr := stderrBuf.String()
	if !strings.Contains(stderrStr, "default-login") || !strings.Contains(stderrStr, "requires explicit user awareness/confirmation") {
		t.Errorf("expected default-login warning in stderr, got: %q", stderrStr)
	}

	// Verify warning event
	events := parseEvents(t, stdoutBuf.String(), runID)
	var foundLoginWarn bool
	for _, ev := range events {
		if ev.Type == "warning" {
			if msg, ok := ev.Data["message"].(string); ok && strings.Contains(msg, "default-login") {
				foundLoginWarn = true
			}
		}
	}
	if !foundLoginWarn {
		t.Errorf("expected warning event for default-login")
	}
}

func TestScanIncludeTagsForbiddenTagsRejected(t *testing.T) {
	scopePath := createTestScope(t, []string{"example.com", "*.example.com"}, nil, 600)
	fakeBin := createFakeNuclei(t, "derived")
	runID := "01JTESTSCANFORBIDDEN00000000"

	input := "http://app.example.com:3000\n"
	var stdoutBuf, stderrBuf bytes.Buffer
	args := []string{
		"scan",
		"--scope", scopePath,
		"--run-id", runID,
		"--nuclei-bin", fakeBin,
		"--include-tags", "intrusive,dos,fuzz",
	}

	code := runWithIOStdin(context.Background(), args, strings.NewReader(input), &stdoutBuf, &stderrBuf)
	if code != 0 {
		t.Fatalf("run(scan) exit code = %d, want 0; stderr: %s", code, stderrBuf.String())
	}

	// Verify stderr warnings for rejected tags
	stderrStr := stderrBuf.String()
	for _, forbidden := range []string{"intrusive", "dos", "fuzz"} {
		if !strings.Contains(stderrStr, forbidden) || !strings.Contains(stderrStr, "ignored") {
			t.Errorf("expected rejection warning for %q in stderr, got: %q", forbidden, stderrStr)
		}
	}

	// Verify warning events
	events := parseEvents(t, stdoutBuf.String(), runID)
	rejectedCount := 0
	for _, ev := range events {
		if ev.Type == "warning" {
			if msg, ok := ev.Data["message"].(string); ok && strings.Contains(msg, "ignored") {
				rejectedCount++
			}
		}
	}
	if rejectedCount < 3 {
		t.Errorf("expected at least 3 warning events for rejected tags, got %d", rejectedCount)
	}
}
