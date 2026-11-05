package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

// Host represents a normalized host entry with deduplicated IPs and sources.
type Host struct {
	Hostname string   `json:"hostname"`
	IPs      []string `json:"ips,omitempty"`
	Sources  []string `json:"sources,omitempty"`
}

// HostID calculates a stable SHA256 hex digest for a normalized hostname per Design Freeze 6.2.
func HostID(hostname string) string {
	sum := sha256.Sum256([]byte(hostname))
	return hex.EncodeToString(sum[:])
}

// Hostname normalizes a raw hostname: trims whitespace, lowercases, removes trailing dot,
// converts IDN to punycode using golang.org/x/net/idna, and enforces strict RFC 1123 hostname rules.
func Hostname(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("hostname must not be empty")
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return "", errors.New("hostname must not contain whitespace")
	}

	raw = strings.TrimSuffix(strings.ToLower(raw), ".")
	if raw == "" {
		return "", errors.New("hostname must not be empty")
	}

	// Convert IDN to punycode ASCII
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil {
		return "", fmt.Errorf("convert IDN to ASCII: %w", err)
	}

	if len(ascii) > 253 {
		return "", fmt.Errorf("hostname length %d exceeds 253 characters", len(ascii))
	}

	if net.ParseIP(ascii) != nil {
		return "", errors.New("IP literals are not permitted as hostnames")
	}

	labels := strings.Split(ascii, ".")
	lastLabel := labels[len(labels)-1]
	allNumericTLD := true
	for _, character := range lastLabel {
		if character < '0' || character > '9' {
			allNumericTLD = false
			break
		}
	}
	if allNumericTLD {
		return "", errors.New("top-level domain must not be all-numeric")
	}

	for _, label := range labels {
		if label == "" {
			return "", errors.New("hostname must not contain empty labels")
		}
		if len(label) > 63 {
			return "", fmt.Errorf("label length %d exceeds 63 characters", len(label))
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("label must not start or end with a hyphen")
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
				return "", fmt.Errorf("label contains invalid character %q", character)
			}
		}
	}

	return ascii, nil
}

// MergeStrings combines multiple slices of strings, removes empty entries, deduplicates, and sorts them.
func MergeStrings(slices ...[]string) []string {
	seen := make(map[string]struct{})
	for _, slice := range slices {
		for _, item := range slice {
			item = strings.TrimSpace(item)
			if item != "" {
				seen[item] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	result := make([]string, 0, len(seen))
	for item := range seen {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

// MergeSources merges and deduplicates sources.
func MergeSources(existing, incoming []string) []string {
	return MergeStrings(existing, incoming)
}

// MergeIPs merges and deduplicates IP addresses.
func MergeIPs(existing, incoming []string) []string {
	return MergeStrings(existing, incoming)
}

// Deduplicate takes a list of Host entries, normalizes each hostname, and merges duplicates.
func Deduplicate(hosts []Host) ([]Host, error) {
	registry := NewRegistry()
	for _, h := range hosts {
		if _, _, err := registry.Add(h.Hostname, h.IPs, h.Sources); err != nil {
			return nil, err
		}
	}
	return registry.All(), nil
}

// Registry maintains an in-memory deduplicated collection of discovered hosts.
type Registry struct {
	mu    sync.Mutex
	order []string
	hosts map[string]*Host
}

// NewRegistry creates a new Host registry.
func NewRegistry() *Registry {
	return &Registry{
		hosts: make(map[string]*Host),
	}
}

// Add normalizes the hostname and adds or updates an entry in the registry.
// Returns the merged Host, whether it was newly added (true if new, false if merged), and any normalization error.
func (r *Registry) Add(rawHostname string, ips []string, sources []string) (*Host, bool, error) {
	normalized, err := Hostname(rawHostname)
	if err != nil {
		return nil, false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, found := r.hosts[normalized]
	if found {
		existing.IPs = MergeIPs(existing.IPs, ips)
		existing.Sources = MergeSources(existing.Sources, sources)
		return existing, false, nil
	}

	entry := &Host{
		Hostname: normalized,
		IPs:      MergeIPs(nil, ips),
		Sources:  MergeSources(nil, sources),
	}
	r.hosts[normalized] = entry
	r.order = append(r.order, normalized)
	return entry, true, nil
}

// All returns all deduplicated hosts in their order of first appearance.
func (r *Registry) All() []Host {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]Host, 0, len(r.order))
	for _, h := range r.order {
		if entry, found := r.hosts[h]; found {
			result = append(result, *entry)
		}
	}
	return result
}

// Count returns the number of unique hosts in the registry.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.order)
}
