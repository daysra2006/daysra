package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeHostnameTable(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	label64 := strings.Repeat("a", 64)
	total253 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 57) + ".com"
	total254 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 58) + ".com"

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "simple domain lowercase",
			input:   "example.com",
			want:    "example.com",
			wantErr: false,
		},
		{
			name:    "uppercase to lowercase",
			input:   "API.EXAMPLE.COM",
			want:    "api.example.com",
			wantErr: false,
		},
		{
			name:    "trailing dot removed",
			input:   "api.example.com.",
			want:    "api.example.com",
			wantErr: false,
		},
		{
			name:    "whitespace trimmed",
			input:   "  example.com  ",
			want:    "example.com",
			wantErr: false,
		},
		{
			name:    "nested subdomains",
			input:   "a.b.c.example.com",
			want:    "a.b.c.example.com",
			wantErr: false,
		},
		{
			name:    "hyphen in middle of label",
			input:   "my-api-server.example-domain.com",
			want:    "my-api-server.example-domain.com",
			wantErr: false,
		},
		{
			name:    "IDN German umlaut to punycode",
			input:   "münchen.de",
			want:    "xn--mnchen-3ya.de",
			wantErr: false,
		},
		{
			name:    "IDN German umlaut subdomain to punycode",
			input:   "sub.büt.example.com",
			want:    "sub.xn--bt-xka.example.com",
			wantErr: false,
		},
		{
			name:    "IDN French accent to punycode",
			input:   "café.fr",
			want:    "xn--caf-dma.fr",
			wantErr: false,
		},
		{
			name:    "already valid punycode",
			input:   "xn--mnchen-3ya.de",
			want:    "xn--mnchen-3ya.de",
			wantErr: false,
		},
		{
			name:    "label exactly 63 characters",
			input:   label63 + ".com",
			want:    label63 + ".com",
			wantErr: false,
		},
		{
			name:    "total hostname exactly 253 characters",
			input:   total253,
			want:    total253,
			wantErr: false,
		},
		// Error cases
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "space in hostname",
			input:   "bad host.com",
			wantErr: true,
		},
		{
			name:    "label exceeds 63 characters",
			input:   label64 + ".com",
			wantErr: true,
		},
		{
			name:    "total length exceeds 253 characters",
			input:   total254,
			wantErr: true,
		},
		{
			name:    "label starts with hyphen",
			input:   "-bad.example.com",
			wantErr: true,
		},
		{
			name:    "label ends with hyphen",
			input:   "bad-.example.com",
			wantErr: true,
		},
		{
			name:    "consecutive dots empty label",
			input:   "api..example.com",
			wantErr: true,
		},
		{
			name:    "leading dot empty label",
			input:   ".example.com",
			wantErr: true,
		},
		{
			name:    "trailing double dots empty label",
			input:   "example.com..",
			wantErr: true,
		},
		{
			name:    "IPv4 literal",
			input:   "192.168.1.1",
			wantErr: true,
		},
		{
			name:    "IPv6 literal",
			input:   "::1",
			wantErr: true,
		},
		{
			name:    "all numeric TLD",
			input:   "domain.123",
			wantErr: true,
		},
		{
			name:    "wildcard in hostname",
			input:   "*.example.com",
			wantErr: true,
		},
		{
			name:    "symbol in hostname",
			input:   "api@example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Hostname(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Hostname(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Hostname(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMergeSourcesAndIPs(t *testing.T) {
	sources1 := []string{"subfinder", "crtsh"}
	sources2 := []string{"crtsh", "alienvault", " "}
	mergedSources := MergeSources(sources1, sources2)

	wantSources := []string{"alienvault", "crtsh", "subfinder"}
	if !reflect.DeepEqual(mergedSources, wantSources) {
		t.Errorf("MergeSources = %v, want %v", mergedSources, wantSources)
	}

	ips1 := []string{"192.0.2.1", "192.0.2.2"}
	ips2 := []string{"192.0.2.2", "198.51.100.1"}
	mergedIPs := MergeIPs(ips1, ips2)

	wantIPs := []string{"192.0.2.1", "192.0.2.2", "198.51.100.1"}
	if !reflect.DeepEqual(mergedIPs, wantIPs) {
		t.Errorf("MergeIPs = %v, want %v", mergedIPs, wantIPs)
	}
}

func TestDeduplicateHosts(t *testing.T) {
	rawHosts := []Host{
		{
			Hostname: "api.example.com.",
			IPs:      []string{"192.0.2.1"},
			Sources:  []string{"subfinder"},
		},
		{
			Hostname: "API.EXAMPLE.COM",
			IPs:      []string{"192.0.2.2"},
			Sources:  []string{"crtsh"},
		},
		{
			Hostname: "web.example.com",
			IPs:      []string{"198.51.100.1"},
			Sources:  []string{"subfinder"},
		},
		{
			Hostname: "münchen.de",
			Sources:  []string{"subfinder"},
		},
		{
			Hostname: "xn--mnchen-3ya.de.",
			Sources:  []string{"alienvault"},
		},
	}

	deduped, err := Deduplicate(rawHosts)
	if err != nil {
		t.Fatalf("Deduplicate failed: %v", err)
	}

	if len(deduped) != 3 {
		t.Fatalf("expected 3 unique hosts, got %d", len(deduped))
	}

	// First host: api.example.com
	if deduped[0].Hostname != "api.example.com" {
		t.Errorf("deduped[0].Hostname = %q, want api.example.com", deduped[0].Hostname)
	}
	wantAPIIps := []string{"192.0.2.1", "192.0.2.2"}
	if !reflect.DeepEqual(deduped[0].IPs, wantAPIIps) {
		t.Errorf("deduped[0].IPs = %v, want %v", deduped[0].IPs, wantAPIIps)
	}
	wantAPISources := []string{"crtsh", "subfinder"}
	if !reflect.DeepEqual(deduped[0].Sources, wantAPISources) {
		t.Errorf("deduped[0].Sources = %v, want %v", deduped[0].Sources, wantAPISources)
	}

	// Second host: web.example.com
	if deduped[1].Hostname != "web.example.com" {
		t.Errorf("deduped[1].Hostname = %q, want web.example.com", deduped[1].Hostname)
	}

	// Third host: münchen.de normalized to punycode
	if deduped[2].Hostname != "xn--mnchen-3ya.de" {
		t.Errorf("deduped[2].Hostname = %q, want xn--mnchen-3ya.de", deduped[2].Hostname)
	}
	wantMünchenSources := []string{"alienvault", "subfinder"}
	if !reflect.DeepEqual(deduped[2].Sources, wantMünchenSources) {
		t.Errorf("deduped[2].Sources = %v, want %v", deduped[2].Sources, wantMünchenSources)
	}
}

func TestRegistryStreaming(t *testing.T) {
	registry := NewRegistry()

	// First insert
	h, isNew, err := registry.Add("API.example.com.", []string{"192.0.2.1"}, []string{"subfinder"})
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if !isNew {
		t.Errorf("expected isNew = true on first insert")
	}
	if h.Hostname != "api.example.com" {
		t.Errorf("got hostname %q, want api.example.com", h.Hostname)
	}

	// Second insert with duplicate hostname and new source
	h, isNew, err = registry.Add("api.example.com", []string{"192.0.2.2"}, []string{"crtsh"})
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if isNew {
		t.Errorf("expected isNew = false on duplicate insert")
	}
	if len(h.Sources) != 2 || h.Sources[0] != "crtsh" || h.Sources[1] != "subfinder" {
		t.Errorf("unexpected merged sources: %v", h.Sources)
	}
	if len(h.IPs) != 2 {
		t.Errorf("unexpected merged IPs: %v", h.IPs)
	}

	if registry.Count() != 1 {
		t.Errorf("registry count = %d, want 1", registry.Count())
	}
}

func TestHostID(t *testing.T) {
	hostname := "api.example.com"
	expectedSum := sha256.Sum256([]byte(hostname))
	expectedHex := hex.EncodeToString(expectedSum[:])

	if got := HostID(hostname); got != expectedHex {
		t.Errorf("HostID(%q) = %q, want %q", hostname, got, expectedHex)
	}
}
