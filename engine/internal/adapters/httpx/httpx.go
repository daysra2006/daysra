package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"daysra-engine/internal/runner"
)

// ExpectedVersion is the pinned fixture version of httpx.
const ExpectedVersion = "v1.12.0"

var versionRegex = regexp.MustCompile(`(?i)v?\d+\.\d+(?:\.\d+)?`)

// Entry represents a single JSON object produced by httpx with -silent -json -sc -title -td -cl.
type Entry struct {
	Timestamp     string   `json:"timestamp,omitempty"`
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	Input         string   `json:"input"`
	Title         string   `json:"title"`
	StatusCode    int      `json:"status_code"`
	ContentLength int64    `json:"content_length"`
	Tech          []string `json:"tech"`
	Failed        bool     `json:"failed"`
}

// Result represents normalized HTTP observation data emitted as an "http" event.
type Result struct {
	Hostname      string   `json:"hostname"`
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	Tech          []string `json:"tech"`
	ContentLength int64    `json:"content_length"`
}

// BuildArgs constructs the argument array for httpx subprocess execution.
// Host input is passed via stdin, so no target or input file flag is added here.
// Follow-redirects (-fr / -follow-redirects) is intentionally not included per design freeze rule 17.
func BuildArgs(maxRate, timeout int) []string {
	args := []string{
		"-silent",
		"-json",
		"-sc",
		"-title",
		"-td",
		"-cl",
	}

	if maxRate > 0 {
		args = append(args, "-rl", strconv.Itoa(maxRate))
	}
	if timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(timeout))
	}

	return args
}

// ParseLine parses a single JSONL line emitted by httpx into a Result.
func ParseLine(line string) (*Result, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errors.New("empty httpx output line")
	}

	var entry Entry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, fmt.Errorf("invalid httpx JSON: %w", err)
	}

	rawHost := entry.Host
	if rawHost == "" && entry.URL != "" {
		if u, err := url.Parse(entry.URL); err == nil {
			rawHost = u.Hostname()
		}
	}
	if rawHost == "" && entry.Input != "" {
		rawHost = entry.Input
	}
	if rawHost == "" {
		return nil, errors.New("httpx entry missing host, url, and input fields")
	}

	if h, _, err := net.SplitHostPort(rawHost); err == nil {
		rawHost = h
	}

	tech := entry.Tech
	if tech == nil {
		tech = []string{}
	}

	return &Result{
		Hostname:      rawHost,
		URL:           entry.URL,
		StatusCode:    entry.StatusCode,
		Title:         entry.Title,
		Tech:          tech,
		ContentLength: entry.ContentLength,
	}, nil
}

// CheckVersion runs httpx -version to detect whether httpx is available and check its version.
// It returns (version, warning, error). If the version does not match ExpectedVersion, a warning is returned.
func CheckVersion(ctx context.Context, binaryPath string) (string, string, error) {
	if binaryPath == "" {
		var err error
		binaryPath, err = exec.LookPath("httpx")
		if err != nil {
			return "", "", fmt.Errorf("httpx binary not found: %w", err)
		}
	}

	var outBuf bytes.Buffer
	res := runner.Run(ctx, binaryPath, []string{"-version"}, runner.Options{
		Timeout: 5 * time.Second,
		LineHandler: func(line string) {
			outBuf.WriteString(line + "\n")
		},
		StderrHandler: func(line string) {
			outBuf.WriteString(line + "\n")
		},
	})

	if res.Error != nil && res.ExitCode != 0 {
		return "", "", fmt.Errorf("httpx -version failed (exit %d): %w", res.ExitCode, res.Error)
	}

	combined := outBuf.String()
	if combined == "" {
		combined = res.Stderr
	}

	version := ParseVersion(combined)
	if version == "" {
		return "", "", errors.New("unable to determine httpx version from -version output")
	}

	var warning string
	if version != ExpectedVersion {
		warning = fmt.Sprintf("httpx version %q differs from expected fixture version %q", version, ExpectedVersion)
	}

	return version, warning, nil
}

// ParseVersion extracts a version string like "v1.12.0" from httpx banner/output.
func ParseVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "current version") || strings.Contains(lower, "httpx") {
			match := versionRegex.FindString(line)
			if match != "" {
				if !strings.HasPrefix(match, "v") && !strings.HasPrefix(match, "V") {
					match = "v" + match
				}
				return strings.ToLower(match)
			}
		}
	}
	return ""
}
