package scope

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope defines the explicit authorization and hostname boundaries for a run.
type Scope struct {
	Authorization string   `yaml:"authorization"`
	Allow         []string `yaml:"allow"`
	Deny          []string `yaml:"deny"`
	MaxRate       int      `yaml:"max_rate"`
	Timeout       int      `yaml:"timeout"`
}

type scopeFile struct {
	Authorization *string    `yaml:"authorization"`
	Allow         *[]*string `yaml:"allow"`
	Deny          *[]*string `yaml:"deny"`
	MaxRate       *int       `yaml:"max_rate"`
	Timeout       *int       `yaml:"timeout"`
}

// Load parses and validates a scope.yaml file.
func Load(path string) (Scope, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return Scope{}, fmt.Errorf("read scope: %w", err)
	}
	return Parse(contents)
}

// Parse parses and validates scope YAML.
func Parse(contents []byte) (Scope, error) {
	dec := yaml.NewDecoder(bytes.NewReader(contents))
	dec.KnownFields(true)

	var raw scopeFile
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return Scope{}, errors.New("scope authorization must not be empty")
		}
		return Scope{}, fmt.Errorf("parse scope.yaml: %w", err)
	}

	var extra struct{}
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Scope{}, errors.New("scope.yaml harus berisi tepat satu dokumen YAML")
	}

	if raw.Authorization == nil || strings.TrimSpace(*raw.Authorization) == "" {
		return Scope{}, errors.New("scope authorization must not be empty")
	}

	if raw.Allow == nil || len(*raw.Allow) == 0 {
		return Scope{}, errors.New("scope allow must contain at least one hostname pattern")
	}

	allowList := make([]string, 0, len(*raw.Allow))
	for i, entry := range *raw.Allow {
		if entry == nil {
			return Scope{}, fmt.Errorf("scope allow[%d] must not be null", i)
		}
		trimmed := strings.TrimSpace(*entry)
		if trimmed == "" {
			return Scope{}, fmt.Errorf("scope allow[%d] must not be empty", i)
		}
		if !validPattern(trimmed) {
			return Scope{}, fmt.Errorf("invalid hostname pattern %q", trimmed)
		}
		allowList = append(allowList, trimmed)
	}

	var denyList []string
	if raw.Deny != nil {
		denyList = make([]string, 0, len(*raw.Deny))
		for i, entry := range *raw.Deny {
			if entry == nil {
				return Scope{}, fmt.Errorf("scope deny[%d] must not be null", i)
			}
			trimmed := strings.TrimSpace(*entry)
			if trimmed == "" {
				return Scope{}, fmt.Errorf("scope deny[%d] must not be empty", i)
			}
			if !validPattern(trimmed) {
				return Scope{}, fmt.Errorf("invalid hostname pattern %q", trimmed)
			}
			denyList = append(denyList, trimmed)
		}
	}

	parsed := Scope{
		Authorization: strings.TrimSpace(*raw.Authorization),
		Allow:         allowList,
		Deny:          denyList,
		MaxRate:       50,
		Timeout:       600,
	}

	if raw.MaxRate != nil {
		if *raw.MaxRate <= 0 {
			return Scope{}, fmt.Errorf("scope max_rate must be greater than zero, got %d", *raw.MaxRate)
		}
		parsed.MaxRate = *raw.MaxRate
	}

	if raw.Timeout != nil {
		if *raw.Timeout <= 0 {
			return Scope{}, fmt.Errorf("scope timeout must be greater than zero, got %d", *raw.Timeout)
		}
		parsed.Timeout = *raw.Timeout
	}

	return parsed, nil
}

// Allows reports whether a valid hostname is allowed and not denied by scope.
func (scope Scope) Allows(hostname string) bool {
	normalized, ok := normalizeHostname(hostname)
	if !ok {
		return false
	}
	for _, pattern := range scope.Deny {
		if matches(pattern, normalized) {
			return false
		}
	}
	for _, pattern := range scope.Allow {
		if matches(pattern, normalized) {
			return true
		}
	}
	return false
}

func validPattern(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] > 127 {
			return false
		}
	}
	if strings.ContainsAny(pattern, " \t\r\n") {
		return false
	}
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		pattern = strings.TrimPrefix(pattern, "*.")
		if strings.Contains(pattern, "*") {
			return false
		}
	} else if strings.Contains(pattern, "*") {
		return false
	}
	_, ok := normalizeHostname(pattern)
	return ok
}

func matches(pattern, hostname string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	if strings.HasPrefix(pattern, "*.") {
		basePattern := strings.TrimPrefix(pattern, "*.")
		baseLabels := strings.Split(basePattern, ".")
		hostLabels := strings.Split(hostname, ".")

		if len(hostLabels) <= len(baseLabels) {
			return false
		}

		offset := len(hostLabels) - len(baseLabels)
		for i, label := range baseLabels {
			if hostLabels[offset+i] != label {
				return false
			}
		}
		return true
	}
	return hostname == pattern
}

func normalizeHostname(hostname string) (string, bool) {
	for i := 0; i < len(hostname); i++ {
		if hostname[i] > 127 {
			return "", false
		}
	}
	if strings.ContainsAny(hostname, " \t\r\n") {
		return "", false
	}
	hostname = strings.TrimSuffix(strings.ToLower(hostname), ".")
	if hostname == "" || len(hostname) > 253 {
		return "", false
	}
	if net.ParseIP(hostname) != nil {
		return "", false
	}
	labels := strings.Split(hostname, ".")
	lastLabel := labels[len(labels)-1]
	allNumericTLD := true
	for _, character := range lastLabel {
		if character < '0' || character > '9' {
			allNumericTLD = false
			break
		}
	}
	if allNumericTLD {
		return "", false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
				return "", false
			}
		}
	}
	return hostname, true
}
