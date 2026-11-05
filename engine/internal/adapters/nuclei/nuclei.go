package nuclei

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// ExpectedVersion is the pinned fixture version of nuclei.
const ExpectedVersion = "v3.11.1"

// maxEvidenceBytes is the maximum allowed byte length for sanitized evidence.
const maxEvidenceBytes = 2048

var (
	versionRegex = regexp.MustCompile(`(?i)v?\d+\.\d+(?:\.\d+)?`)

	// Sensitive patterns for evidence redaction pass.
	reAuthHeader = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\r\n,;]+`)
	reBearer     = regexp.MustCompile(`(?i)(bearer\s+)[a-zA-Z0-9_\-\.]+`)
	reCookie     = regexp.MustCompile(`(?i)((?:set-cookie|cookie)\s*[:=]\s*)[^\r\n]+`)
	reToken      = regexp.MustCompile(`(?i)((?:access_token|refresh_token|id_token|csrf_token|token)\s*[:=]\s*)[^\s,;&"']+`)
	reAPIKey     = regexp.MustCompile(`(?i)((?:api[-_]?key|apikey|x-api-key)\s*[:=]\s*)[^\s,;&"']+`)
	rePassword   = regexp.MustCompile(`(?i)((?:password|passwd|pwd)\s*[:=]\s*)[^\s,;&"']+`)
)

// EntryInfo maps the exact "info" object in nuclei JSONL output.
type EntryInfo struct {
	Name           string          `json:"name"`
	Severity       string          `json:"severity"`
	Classification json.RawMessage `json:"classification"`
}

// Entry maps the exact fixture field names from nuclei JSONL output.
// NOTE: request, response, curl-command, and template-path are deliberately omitted
// so they are never unmarshaled or propagated to events, storage, or reports.
type Entry struct {
	TemplateID       string          `json:"template-id"`
	Info             EntryInfo       `json:"info"`
	MatchedAt        string          `json:"matched-at"`
	MatcherName      string          `json:"matcher-name"`
	ExtractedResults json.RawMessage `json:"extracted-results"`
	Timestamp        string          `json:"timestamp"`
	Host             string          `json:"host"`
}

// Finding represents a normalized vulnerability finding emitted as a "finding" event.
type Finding struct {
	ID          string   `json:"id"`
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	CVEs        []string `json:"cve"`
	MatchedAt   string   `json:"matched_at"`
	Evidence    string   `json:"evidence"`
	Tool        string   `json:"tool"`
	ToolVersion string   `json:"tool_version"`
	Hostname    string   `json:"hostname"`
	Timestamp   string   `json:"timestamp,omitempty"`
}

// DefaultTags defines the default safe scanning profile: tech, exposure, misconfig.
// Notice default-login is excluded by default.
var DefaultTags = []string{"tech", "exposure", "misconfig"}

// ExcludedTags defines the mandatory intrusive/fuzz/dos tags that must be excluded.
var ExcludedTags = []string{"intrusive", "fuzz", "fuzzing", "dos"}

// ResolveTags combines DefaultTags with requested includeTags.
// It strictly prevents enabling any tag present in ExcludedTags.
// If requested tags include "default-login", hasDefaultLogin is true.
// Returns (finalTags, hasDefaultLogin, rejectedTags).
func ResolveTags(includeTags []string) ([]string, bool, []string) {
	excludedSet := make(map[string]bool, len(ExcludedTags))
	for _, t := range ExcludedTags {
		excludedSet[strings.ToLower(strings.TrimSpace(t))] = true
	}

	seen := make(map[string]bool)
	var finalTags []string
	for _, t := range DefaultTags {
		norm := strings.ToLower(strings.TrimSpace(t))
		if norm != "" && !seen[norm] {
			seen[norm] = true
			finalTags = append(finalTags, norm)
		}
	}

	var hasDefaultLogin bool
	var rejectedTags []string

	for _, req := range includeTags {
		norm := strings.ToLower(strings.TrimSpace(req))
		if norm == "" {
			continue
		}
		if excludedSet[norm] {
			rejectedTags = append(rejectedTags, norm)
			continue
		}
		if norm == "default-login" {
			hasDefaultLogin = true
		}
		if !seen[norm] {
			seen[norm] = true
			finalTags = append(finalTags, norm)
		}
	}

	return finalTags, hasDefaultLogin, rejectedTags
}

// BuildArgs constructs the argument array for nuclei subprocess execution.
// Follow-redirects is deliberately NOT included per Rule 18.
// -duc (no update check) and -ni (no interactsh/OAST) are always included.
// Custom template paths (-t, -w) are NEVER added per Rule 18.
func BuildArgs(maxRate, concurrency, timeout int, tags, excludeTags []string, severity []string) []string {
	args := []string{
		"-j",
		"-silent",
		"-nc",
		"-duc",
		"-ni",
	}

	if len(severity) > 0 {
		args = append(args, "-s", strings.Join(severity, ","))
	}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	if len(excludeTags) > 0 {
		args = append(args, "-etags", strings.Join(excludeTags, ","))
	}
	if maxRate > 0 {
		args = append(args, "-rl", strconv.Itoa(maxRate))
	}
	if concurrency > 0 {
		args = append(args, "-c", strconv.Itoa(concurrency))
	}
	if timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(timeout))
	}

	return args
}

// FindingID computes a stable sha256-based ID for a finding:
// sha256(hostname | template_id | matcher | path)
func FindingID(hostname, templateID, matcher, path string) string {
	parts := []string{hostname, templateID, matcher, path}
	joined := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(sum[:])
}

// RedactEvidence sanitizes evidence and applies a redaction pass for sensitive keywords
// (Authorization, cookie, token, api-key, password), capping length at 2 KB.
func RedactEvidence(input string) string {
	if input == "" {
		return ""
	}

	s := reAuthHeader.ReplaceAllString(input, "${1}[REDACTED]")
	s = reBearer.ReplaceAllString(s, "${1}[REDACTED]")
	s = reCookie.ReplaceAllString(s, "${1}[REDACTED]")
	s = reToken.ReplaceAllString(s, "${1}[REDACTED]")
	s = reAPIKey.ReplaceAllString(s, "${1}[REDACTED]")
	s = rePassword.ReplaceAllString(s, "${1}[REDACTED]")

	// Sanitization: replace non-printable characters (except \n, \r, \t) with space.
	var buf strings.Builder
	buf.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r != 127) {
			buf.WriteRune(r)
		} else {
			buf.WriteRune(' ')
		}
	}
	res := strings.TrimSpace(buf.String())
	if len(res) > maxEvidenceBytes {
		res = res[:maxEvidenceBytes]
	}
	return res
}

// extractEvidence builds raw evidence from extracted-results if present, or matcher-name.
func extractEvidence(extractedResults json.RawMessage, matcherName string) string {
	if len(extractedResults) > 0 {
		trimmed := strings.TrimSpace(string(extractedResults))
		if trimmed != "" && trimmed != "null" {
			// Try array of strings
			var arr []string
			if err := json.Unmarshal(extractedResults, &arr); err == nil && len(arr) > 0 {
				var valid []string
				for _, item := range arr {
					t := strings.TrimSpace(item)
					if t != "" {
						valid = append(valid, t)
					}
				}
				if len(valid) > 0 {
					return strings.Join(valid, "\n")
				}
			}
			// Try single string
			var single string
			if err := json.Unmarshal(extractedResults, &single); err == nil {
				t := strings.TrimSpace(single)
				if t != "" {
					return t
				}
			}
		}
	}
	return strings.TrimSpace(matcherName)
}

// parseCVEs parses CVE IDs from info.classification.
// Handled shapes: null, empty, object with cve-id as string or array, or missing.
// Always returns a non-nil []string (empty slice if no CVEs).
func parseCVEs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return []string{}
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		return []string{}
	}

	var classMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &classMap); err == nil {
		cveRaw, exists := classMap["cve-id"]
		if !exists {
			cveRaw = classMap["cve"]
		}
		if len(cveRaw) > 0 {
			return extractCVEList(cveRaw)
		}
		return []string{}
	}

	return extractCVEList(raw)
}

func extractCVEList(raw json.RawMessage) []string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return []string{}
	}

	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		res := make([]string, 0, len(arr))
		for _, s := range arr {
			s = strings.TrimSpace(s)
			if s != "" && !strings.EqualFold(s, "null") {
				res = append(res, strings.ToUpper(s))
			}
		}
		return res
	}

	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		single = strings.TrimSpace(single)
		if single != "" && !strings.EqualFold(single, "null") {
			parts := strings.Split(single, ",")
			res := make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					res = append(res, strings.ToUpper(p))
				}
			}
			return res
		}
	}

	return []string{}
}

var sensitiveQueryKeywords = []string{
	"token", "key", "secret", "password", "passwd", "auth", "session", "sid", "jwt", "signature", "sig",
}

// SanitizeMatchedAt strips userinfo and fragment from matched-at URL,
// and redacts the value of any query parameter whose name contains sensitive keywords.
func SanitizeMatchedAt(rawURL string) string {
	if strings.TrimSpace(rawURL) == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Remove userinfo
	u.User = nil
	// Remove fragment
	u.Fragment = ""
	u.RawFragment = ""

	// Redact sensitive query parameters
	if u.RawQuery != "" {
		q := u.Query()
		for paramName := range q {
			lower := strings.ToLower(paramName)
			for _, kw := range sensitiveQueryKeywords {
				if strings.Contains(lower, kw) {
					vals := q[paramName]
					for i := range vals {
						vals[i] = "REDACTED"
					}
					q[paramName] = vals
					break
				}
			}
		}
		u.RawQuery = q.Encode()
	}

	return u.String()
}

// ParseLine is a pure parsing function: it receives a single JSON line and produces
// a Finding without performing scope checks. Scope checks must be executed by the caller/engine.
func ParseLine(line string) (*Finding, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errors.New("empty nuclei output line")
	}

	var entry Entry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, fmt.Errorf("invalid nuclei JSON: %w", err)
	}

	if entry.TemplateID == "" {
		return nil, errors.New("nuclei entry missing template-id")
	}
	if entry.MatchedAt == "" {
		return nil, errors.New("nuclei entry missing matched-at")
	}

	// Sanitize matched-at: remove userinfo, fragments, and redact sensitive query params
	sanitizedMatchedAt := SanitizeMatchedAt(entry.MatchedAt)

	// Extract hostname and path from matched-at URL.
	var hostname, path string
	if u, err := url.Parse(sanitizedMatchedAt); err == nil {
		hostname = u.Hostname()
		path = u.Path
	}
	if hostname == "" {
		hostname = entry.Host
	}
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = h
	}
	if hostname == "" {
		return nil, errors.New("nuclei entry missing host in matched-at and host fields")
	}

	// Evidence built strictly from extracted-results or matcher-name, sanitized and redacted.
	rawEvidence := extractEvidence(entry.ExtractedResults, entry.MatcherName)
	evidence := RedactEvidence(rawEvidence)

	cves := parseCVEs(entry.Info.Classification)
	id := FindingID(hostname, entry.TemplateID, entry.MatcherName, path)

	return &Finding{
		ID:          id,
		TemplateID:  entry.TemplateID,
		Name:        entry.Info.Name,
		Severity:    entry.Info.Severity, // taken verbatim from tool, not modified
		CVEs:        cves,
		MatchedAt:   sanitizedMatchedAt,
		Evidence:    evidence,
		Tool:        "nuclei",
		ToolVersion: "", // populated by caller/engine from verified version
		Hostname:    hostname,
		Timestamp:   entry.Timestamp,
	}, nil
}

// CheckVersion runs nuclei -version to detect whether nuclei is available and check its version.
// It returns (version, warning, error). If the version does not match ExpectedVersion, a warning is returned.
func CheckVersion(ctx context.Context, binaryPath string) (string, string, error) {
	if binaryPath == "" {
		var err error
		binaryPath, err = exec.LookPath("nuclei")
		if err != nil {
			return "", "", fmt.Errorf("nuclei binary not found: %w", err)
		}
	}

	var buf strings.Builder
	res := runner.Run(ctx, binaryPath, []string{"-version"}, runner.Options{
		Timeout: 10 * time.Second,
		LineHandler: func(line string) {
			buf.WriteString(line + "\n")
		},
		StderrHandler: func(line string) {
			buf.WriteString(line + "\n")
		},
	})

	if res.Error != nil && res.ExitCode != 0 {
		return "", "", fmt.Errorf("nuclei -version failed (exit %d): %w", res.ExitCode, res.Error)
	}

	combined := buf.String()
	if combined == "" {
		combined = res.Stderr
	}

	version := ParseVersion(combined)
	if version == "" {
		return "", "", errors.New("unable to determine nuclei version from -version output")
	}

	var warning string
	if version != ExpectedVersion {
		warning = fmt.Sprintf("nuclei version %q differs from expected fixture version %q", version, ExpectedVersion)
	}

	return version, warning, nil
}

// ParseVersion extracts a version string like "v3.11.1" from nuclei banner/output.
func ParseVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "nuclei engine version") || strings.Contains(lower, "nuclei") {
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
