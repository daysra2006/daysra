package subfinder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"daysra-engine/internal/normalize"
	"daysra-engine/internal/runner"
)

// ExpectedVersion is the pinned fixture version of Subfinder.
const ExpectedVersion = "v2.17.0"

var versionRegex = regexp.MustCompile(`(?i)v?\d+\.\d+(?:\.\d+)?`)

// Entry represents a single JSON object produced by Subfinder with -oJ -cs.
type Entry struct {
	Host    string   `json:"host"`
	Input   string   `json:"input"`
	Source  string   `json:"source"`
	Sources []string `json:"sources"`
	IP      string   `json:"ip"`
	IPs     []string `json:"ips"`
}

// BuildArgs constructs the argument array for Subfinder subprocess execution.
func BuildArgs(target string, maxRate, timeout int) []string {
	args := []string{
		"-d", target,
		"-silent",
		"-oJ",
		"-cs",
	}

	if maxRate > 0 {
		args = append(args, "-rl", strconv.Itoa(maxRate))
	}
	if timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(timeout))
	}

	return args
}

// ParseLine parses a single JSONL line emitted by Subfinder into a normalize.Host.
func ParseLine(line string) (*normalize.Host, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errors.New("empty subfinder output line")
	}

	var entry Entry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, fmt.Errorf("invalid subfinder JSON: %w", err)
	}

	if strings.TrimSpace(entry.Host) == "" {
		return nil, errors.New("subfinder entry missing host field")
	}

	var sources []string
	if len(entry.Sources) > 0 {
		sources = append(sources, entry.Sources...)
	}
	if entry.Source != "" {
		sources = append(sources, entry.Source)
	}

	var ips []string
	if len(entry.IPs) > 0 {
		ips = append(ips, entry.IPs...)
	}
	if entry.IP != "" {
		ips = append(ips, entry.IP)
	}

	return &normalize.Host{
		Hostname: entry.Host,
		IPs:      normalize.MergeIPs(nil, ips),
		Sources:  normalize.MergeSources(nil, sources),
	}, nil
}

// CheckVersion runs subfinder -version to detect whether subfinder is available and check its version.
// It returns (version, warning, error). If the version does not match ExpectedVersion, a warning is returned.
func CheckVersion(ctx context.Context, binaryPath string) (string, string, error) {
	if binaryPath == "" {
		var err error
		binaryPath, err = exec.LookPath("subfinder")
		if err != nil {
			return "", "", fmt.Errorf("subfinder binary not found: %w", err)
		}
	}

	var stderrBuf bytes.Buffer
	res := runner.Run(ctx, binaryPath, []string{"-version"}, runner.Options{
		Timeout: 5 * time.Second,
		StderrHandler: func(line string) {
			stderrBuf.WriteString(line + "\n")
		},
	})

	if res.Error != nil && res.ExitCode != 0 {
		return "", "", fmt.Errorf("subfinder -version failed (exit %d): %w", res.ExitCode, res.Error)
	}

	combined := res.Stderr
	version := ParseVersion(combined)
	if version == "" {
		return "", "", errors.New("unable to determine subfinder version from -version output")
	}

	var warning string
	if version != ExpectedVersion {
		warning = fmt.Sprintf("subfinder version %q differs from expected fixture version %q", version, ExpectedVersion)
	}

	return version, warning, nil
}

// ParseVersion extracts a version string like "v2.17.0" from Subfinder banner/output.
func ParseVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "current version") || strings.Contains(lower, "subfinder") {
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
