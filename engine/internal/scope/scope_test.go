package scope

import (
	"os"
	"strings"
	"testing"
)

func TestParseRequiresAuthorization(t *testing.T) {
	_, err := Parse([]byte("allow: [example.com]\n" + "authorization: ''\n"))
	if err == nil || err.Error() != "scope authorization must not be empty" {
		t.Fatalf("expected clear authorization error, got %v", err)
	}
}

func TestScopeAllowsAndDeniesWildcardHostnames(t *testing.T) {
	scope, err := Parse([]byte("authorization: owned lab\n" + "allow: [example.com, '*.example.com']\n" + "deny: [admin.example.com]\n"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	for hostname, want := range map[string]bool{
		"example.com":        true,
		"api.example.com":    true,
		"ADMIN.example.com.": false,
		"example.org":        false,
		"bad host":           false,
	} {
		if got := scope.Allows(hostname); got != want {
			t.Errorf("Allows(%q) = %t, want %t", hostname, got, want)
		}
	}
}

func TestScopeWildcardSubdomainOnlyAndExplicitApex(t *testing.T) {
	tests := []struct {
		name      string
		scopeYAML string
		hostname  string
		want      bool
	}{
		{
			name:      "wildcard only rejects apex",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "example.com",
			want:      false,
		},
		{
			name:      "wildcard only allows single-level subdomain",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "sub.example.com",
			want:      true,
		},
		{
			name:      "wildcard only allows multi-level subdomain",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "a.b.example.com",
			want:      true,
		},
		{
			name:      "wildcard only rejects boundary prefix evilexample.com",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "evilexample.com",
			want:      false,
		},
		{
			name:      "wildcard only rejects inverted domain example.com.evil.net",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "example.com.evil.net",
			want:      false,
		},
		{
			name:      "apex only allows apex",
			scopeYAML: "authorization: lab\nallow: [example.com]\n",
			hostname:  "example.com",
			want:      true,
		},
		{
			name:      "apex only rejects subdomain",
			scopeYAML: "authorization: lab\nallow: [example.com]\n",
			hostname:  "sub.example.com",
			want:      false,
		},
		{
			name:      "apex only rejects multi-level subdomain",
			scopeYAML: "authorization: lab\nallow: [example.com]\n",
			hostname:  "a.b.example.com",
			want:      false,
		},
		{
			name:      "explicit apex and wildcard allows apex",
			scopeYAML: "authorization: lab\nallow: [example.com, '*.example.com']\n",
			hostname:  "example.com",
			want:      true,
		},
		{
			name:      "explicit apex and wildcard allows subdomain",
			scopeYAML: "authorization: lab\nallow: [example.com, '*.example.com']\n",
			hostname:  "api.example.com",
			want:      true,
		},
		{
			name:      "explicit apex and wildcard allows multi-level subdomain",
			scopeYAML: "authorization: lab\nallow: [example.com, '*.example.com']\n",
			hostname:  "a.b.example.com",
			want:      true,
		},
		{
			name:      "explicit apex and wildcard rejects unrelated domain",
			scopeYAML: "authorization: lab\nallow: [example.com, '*.example.com']\n",
			hostname:  "example.org",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Parse([]byte(tt.scopeYAML))
			if err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}
			if got := s.Allows(tt.hostname); got != tt.want {
				t.Errorf("Allows(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestScopeLabelMatchingNotStringSuffix(t *testing.T) {
	tests := []struct {
		name      string
		scopeYAML string
		hostname  string
		want      bool
	}{
		{
			name:      "reject evilexample.com for *.example.com",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "evilexample.com",
			want:      false,
		},
		{
			name:      "reject example.com.evil.net for *.example.com",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "example.com.evil.net",
			want:      false,
		},
		{
			name:      "reject evil.example.com.evil.net for *.example.com",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "evil.example.com.evil.net",
			want:      false,
		},
		{
			name:      "accept a.b.example.com for *.example.com",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "a.b.example.com",
			want:      true,
		},
		{
			name:      "accept a.b.example.com for *.b.example.com",
			scopeYAML: "authorization: lab\nallow: ['*.b.example.com']\n",
			hostname:  "a.b.example.com",
			want:      true,
		},
		{
			name:      "reject b.example.com for *.b.example.com (apex)",
			scopeYAML: "authorization: lab\nallow: ['*.b.example.com']\n",
			hostname:  "b.example.com",
			want:      false,
		},
		{
			name:      "reject ab.example.com for *.b.example.com (not label b)",
			scopeYAML: "authorization: lab\nallow: ['*.b.example.com']\n",
			hostname:  "ab.example.com",
			want:      false,
		},
		{
			name:      "accept x.y.b.example.com for *.b.example.com",
			scopeYAML: "authorization: lab\nallow: ['*.b.example.com']\n",
			hostname:  "x.y.b.example.com",
			want:      true,
		},
		{
			name:      "reject evilexample.com for exact example.com",
			scopeYAML: "authorization: lab\nallow: [example.com]\n",
			hostname:  "evilexample.com",
			want:      false,
		},
		{
			name:      "reject example.com.evil.net for exact example.com",
			scopeYAML: "authorization: lab\nallow: [example.com]\n",
			hostname:  "example.com.evil.net",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Parse([]byte(tt.scopeYAML))
			if err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}
			if got := s.Allows(tt.hostname); got != tt.want {
				t.Errorf("Allows(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestScopeCaseInsensitiveAndTrailingDot(t *testing.T) {
	tests := []struct {
		name      string
		scopeYAML string
		hostname  string
		want      bool
	}{
		{
			name:      "case-insensitive hostname uppercase",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "API.EXAMPLE.COM",
			want:      true,
		},
		{
			name:      "case-insensitive pattern uppercase",
			scopeYAML: "authorization: lab\nallow: ['*.EXAMPLE.COM']\n",
			hostname:  "api.example.com",
			want:      true,
		},
		{
			name:      "case-insensitive exact hostname and pattern uppercase",
			scopeYAML: "authorization: lab\nallow: [EXAMPLE.COM]\n",
			hostname:  "example.com",
			want:      true,
		},
		{
			name:      "trailing dot ignored in hostname",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\n",
			hostname:  "api.example.com.",
			want:      true,
		},
		{
			name:      "trailing dot ignored in exact hostname",
			scopeYAML: "authorization: lab\nallow: [example.com]\n",
			hostname:  "example.com.",
			want:      true,
		},
		{
			name:      "trailing dot ignored in wildcard pattern",
			scopeYAML: "authorization: lab\nallow: ['*.example.com.']\n",
			hostname:  "api.example.com",
			want:      true,
		},
		{
			name:      "trailing dot ignored in exact pattern",
			scopeYAML: "authorization: lab\nallow: ['example.com.']\n",
			hostname:  "example.com",
			want:      true,
		},
		{
			name:      "trailing dot ignored on both sides",
			scopeYAML: "authorization: lab\nallow: ['*.example.com.']\n",
			hostname:  "api.example.com.",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Parse([]byte(tt.scopeYAML))
			if err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}
			if got := s.Allows(tt.hostname); got != tt.want {
				t.Errorf("Allows(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestScopeDenyAlwaysWinsOverAllow(t *testing.T) {
	tests := []struct {
		name      string
		scopeYAML string
		hostname  string
		want      bool
	}{
		{
			name:      "explicit deny wins over wildcard allow",
			scopeYAML: "authorization: lab\nallow: [example.com, '*.example.com']\ndeny: [admin.example.com]\n",
			hostname:  "admin.example.com",
			want:      false,
		},
		{
			name:      "explicit deny with case and trailing dot wins",
			scopeYAML: "authorization: lab\nallow: [example.com, '*.example.com']\ndeny: [admin.example.com]\n",
			hostname:  "ADMIN.EXAMPLE.COM.",
			want:      false,
		},
		{
			name:      "non-denied subdomain under wildcard allow passes",
			scopeYAML: "authorization: lab\nallow: [example.com, '*.example.com']\ndeny: [admin.example.com]\n",
			hostname:  "api.example.com",
			want:      true,
		},
		{
			name:      "wildcard deny wins over broader wildcard allow",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\ndeny: ['*.corp.example.com']\n",
			hostname:  "app.corp.example.com",
			want:      false,
		},
		{
			name:      "wildcard deny wins for nested subdomain",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\ndeny: ['*.corp.example.com']\n",
			hostname:  "deep.nested.corp.example.com",
			want:      false,
		},
		{
			name:      "host outside wildcard deny passes under wildcard allow",
			scopeYAML: "authorization: lab\nallow: ['*.example.com']\ndeny: ['*.corp.example.com']\n",
			hostname:  "app.dev.example.com",
			want:      true,
		},
		{
			name:      "exact deny on apex wins over exact allow on apex",
			scopeYAML: "authorization: lab\nallow: [example.com, '*.example.com']\ndeny: [example.com]\n",
			hostname:  "example.com",
			want:      false,
		},
		{
			name:      "subdomain still allowed when apex is denied",
			scopeYAML: "authorization: lab\nallow: [example.com, '*.example.com']\ndeny: [example.com]\n",
			hostname:  "api.example.com",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Parse([]byte(tt.scopeYAML))
			if err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}
			if got := s.Allows(tt.hostname); got != tt.want {
				t.Errorf("Allows(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestScopeRejectsInvalidHostnames(t *testing.T) {
	scope, err := Parse([]byte("authorization: lab\nallow: [example.com, '*.example.com']\n"))
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	tests := []struct {
		name     string
		hostname string
	}{
		{name: "empty string", hostname: ""},
		{name: "whitespace only", hostname: "   "},
		{name: "space inside hostname", hostname: "bad host"},
		{name: "leading space", hostname: " api.example.com"},
		{name: "trailing space", hostname: "api.example.com "},
		{name: "space in label", hostname: "api .example.com"},
		{name: "underscore in label", hostname: "api_dev.example.com"},
		{name: "leading hyphen in label", hostname: "-api.example.com"},
		{name: "trailing hyphen in label", hostname: "api-.example.com"},
		{name: "empty label from consecutive dots", hostname: "api..example.com"},
		{name: "leading dot", hostname: ".api.example.com"},
		{name: "symbol @", hostname: "api@example.com"},
		{name: "scheme prefix", hostname: "http://api.example.com"},
		{name: "path suffix", hostname: "api.example.com/test"},
		{name: "port suffix", hostname: "api.example.com:443"},
		{name: "IPv4 loopback", hostname: "127.0.0.1"},
		{name: "IPv4 private", hostname: "192.168.1.1"},
		{name: "IPv4 ten dot", hostname: "10.0.0.1"},
		{name: "IPv4 zero", hostname: "0.0.0.0"},
		{name: "IPv4 broadcast", hostname: "255.255.255.255"},
		{name: "IPv4 with trailing dot", hostname: "192.168.1.1."},
		{name: "IPv6 loopback", hostname: "::1"},
		{name: "IPv6 link local", hostname: "fe80::1"},
		{name: "IPv6 documentation", hostname: "2001:db8::1"},
		{name: "all numeric TLD", hostname: "999.999.999.999"},
		{name: "wildcard in queried hostname", hostname: "*.example.com"},
		{name: "middle wildcard in queried hostname", hostname: "api.*.example.com"},
		{name: "bare wildcard in queried hostname", hostname: "*"},
		{name: "prefix wildcard in queried hostname", hostname: "*example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scope.Allows(tt.hostname); got {
				t.Errorf("Allows(%q) = true, want false (invalid hostname must be rejected)", tt.hostname)
			}
		})
	}
}

func TestParseRejectsInvalidPatterns(t *testing.T) {
	tests := []struct {
		name      string
		scopeYAML string
	}{
		{
			name:      "bare wildcard pattern",
			scopeYAML: "authorization: lab\nallow: ['*']\n",
		},
		{
			name:      "wildcard dot pattern",
			scopeYAML: "authorization: lab\nallow: ['*.']\n",
		},
		{
			name:      "wildcard in middle label",
			scopeYAML: "authorization: lab\nallow: ['foo.*.example.com']\n",
		},
		{
			name:      "wildcard in TLD position",
			scopeYAML: "authorization: lab\nallow: ['example.*']\n",
		},
		{
			name:      "wildcard embedded at start of label",
			scopeYAML: "authorization: lab\nallow: ['*foo.example.com']\n",
		},
		{
			name:      "wildcard embedded inside label",
			scopeYAML: "authorization: lab\nallow: ['foo*bar.example.com']\n",
		},
		{
			name:      "multiple wildcards at start",
			scopeYAML: "authorization: lab\nallow: ['*.*.example.com']\n",
		},
		{
			name:      "multiple wildcards start and end",
			scopeYAML: "authorization: lab\nallow: ['*.example.*']\n",
		},
		{
			name:      "wildcard in middle of deny pattern",
			scopeYAML: "authorization: lab\nallow: [example.com]\ndeny: ['sub.*.example.com']\n",
		},
		{
			name:      "wildcard in TLD of deny pattern",
			scopeYAML: "authorization: lab\nallow: [example.com]\ndeny: ['example.*']\n",
		},
		{
			name:      "IPv4 pattern in allow",
			scopeYAML: "authorization: lab\nallow: ['192.168.1.1']\n",
		},
		{
			name:      "IPv4 loopback in allow",
			scopeYAML: "authorization: lab\nallow: ['127.0.0.1']\n",
		},
		{
			name:      "IPv6 pattern in allow",
			scopeYAML: "authorization: lab\nallow: ['::1']\n",
		},
		{
			name:      "IPv6 link local in allow",
			scopeYAML: "authorization: lab\nallow: ['fe80::1']\n",
		},
		{
			name:      "wildcard on IPv4 in allow",
			scopeYAML: "authorization: lab\nallow: ['*.192.168.1.1']\n",
		},
		{
			name:      "IPv4 in deny",
			scopeYAML: "authorization: lab\nallow: [example.com]\ndeny: ['10.0.0.1']\n",
		},
		{
			name:      "empty pattern in allow",
			scopeYAML: "authorization: lab\nallow: ['']\n",
		},
		{
			name:      "space in pattern in allow",
			scopeYAML: "authorization: lab\nallow: ['bad host']\n",
		},
		{
			name:      "underscore in pattern in allow",
			scopeYAML: "authorization: lab\nallow: ['foo_bar.example.com']\n",
		},
		{
			name:      "leading hyphen in pattern",
			scopeYAML: "authorization: lab\nallow: ['-bad.com']\n",
		},
		{
			name:      "trailing hyphen in pattern",
			scopeYAML: "authorization: lab\nallow: ['bad-.com']\n",
		},
		{
			name:      "invalid character in deny pattern",
			scopeYAML: "authorization: lab\nallow: [example.com]\ndeny: ['bad host']\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.scopeYAML))
			if err == nil {
				t.Errorf("Parse() succeeded for invalid pattern %s, want error", tt.name)
			}
		})
	}
}

func TestParseYAMLFormats(t *testing.T) {
	t.Run("inline list format", func(t *testing.T) {
		yamlData := "authorization: owned lab\nallow: [example.com, '*.example.com']\ndeny: [admin.example.com]\n"
		s, err := Parse([]byte(yamlData))
		if err != nil {
			t.Fatalf("Parse() failed: %v", err)
		}
		if s.Authorization != "owned lab" {
			t.Errorf("got authorization %q, want 'owned lab'", s.Authorization)
		}
		if len(s.Allow) != 2 || s.Allow[0] != "example.com" || s.Allow[1] != "*.example.com" {
			t.Errorf("unexpected Allow: %v", s.Allow)
		}
		if len(s.Deny) != 1 || s.Deny[0] != "admin.example.com" {
			t.Errorf("unexpected Deny: %v", s.Deny)
		}
		if s.MaxRate != 50 {
			t.Errorf("got MaxRate %d, want default 50", s.MaxRate)
		}
		if s.Timeout != 600 {
			t.Errorf("got Timeout %d, want default 600", s.Timeout)
		}
	})

	t.Run("block list format with explicit rate and timeout", func(t *testing.T) {
		yamlData := `authorization: bug bounty program
allow:
  - example.com
  - '*.example.com'
deny:
  - admin.example.com
max_rate: 100
timeout: 300
`
		s, err := Parse([]byte(yamlData))
		if err != nil {
			t.Fatalf("Parse() failed: %v", err)
		}
		if s.Authorization != "bug bounty program" {
			t.Errorf("got authorization %q, want 'bug bounty program'", s.Authorization)
		}
		if len(s.Allow) != 2 || s.Allow[0] != "example.com" || s.Allow[1] != "*.example.com" {
			t.Errorf("unexpected Allow: %v", s.Allow)
		}
		if len(s.Deny) != 1 || s.Deny[0] != "admin.example.com" {
			t.Errorf("unexpected Deny: %v", s.Deny)
		}
		if s.MaxRate != 100 {
			t.Errorf("got MaxRate %d, want 100", s.MaxRate)
		}
		if s.Timeout != 300 {
			t.Errorf("got Timeout %d, want 300", s.Timeout)
		}
	})

	t.Run("comments at end of line", func(t *testing.T) {
		yamlData := `authorization: owned lab # izin resmi pengujian
allow: # daftar domain yang diizinkan
  - example.com # apex domain
  - '*.example.com' # seluruh subdomain
deny: # daftar yang dikecualikan
  - admin.example.com # domain admin
max_rate: 25 # batas kecepatan request
timeout: 120 # batas waktu detik
`
		s, err := Parse([]byte(yamlData))
		if err != nil {
			t.Fatalf("Parse() failed with end-of-line comments: %v", err)
		}
		if s.Authorization != "owned lab" {
			t.Errorf("got authorization %q, want 'owned lab'", s.Authorization)
		}
		if len(s.Allow) != 2 || s.Allow[0] != "example.com" || s.Allow[1] != "*.example.com" {
			t.Errorf("unexpected Allow: %v", s.Allow)
		}
		if len(s.Deny) != 1 || s.Deny[0] != "admin.example.com" {
			t.Errorf("unexpected Deny: %v", s.Deny)
		}
		if s.MaxRate != 25 {
			t.Errorf("got MaxRate %d, want 25", s.MaxRate)
		}
		if s.Timeout != 120 {
			t.Errorf("got Timeout %d, want 120", s.Timeout)
		}
	})

	t.Run("quote variations", func(t *testing.T) {
		yamlData := `authorization: 'single quoted authorization'
allow:
  - "double.quoted.example.com"
  - 'single.quoted.example.com'
  - unquoted.example.com
deny:
  - "admin.double.example.com"
  - 'admin.single.example.com'
  - admin.unquoted.example.com
`
		s, err := Parse([]byte(yamlData))
		if err != nil {
			t.Fatalf("Parse() failed with quotes: %v", err)
		}
		if s.Authorization != "single quoted authorization" {
			t.Errorf("got authorization %q", s.Authorization)
		}
		expectedAllow := []string{
			"double.quoted.example.com",
			"single.quoted.example.com",
			"unquoted.example.com",
		}
		for i, want := range expectedAllow {
			if s.Allow[i] != want {
				t.Errorf("Allow[%d] = %q, want %q", i, s.Allow[i], want)
			}
		}
		expectedDeny := []string{
			"admin.double.example.com",
			"admin.single.example.com",
			"admin.unquoted.example.com",
		}
		for i, want := range expectedDeny {
			if s.Deny[i] != want {
				t.Errorf("Deny[%d] = %q, want %q", i, s.Deny[i], want)
			}
		}
	})
}

func TestParseFailClosedAndStrictValidation(t *testing.T) {
	tests := []struct {
		name      string
		scopeYAML string
	}{
		{
			name:      "unknown field",
			scopeYAML: "authorization: lab\nallow: [example.com]\nextra_field: invalid\n",
		},
		{
			name:      "unknown nested field",
			scopeYAML: "authorization: lab\nallow: [example.com]\nfoo: bar\n",
		},
		{
			name:      "allow as string instead of list",
			scopeYAML: "authorization: lab\nallow: example.com\n",
		},
		{
			name:      "deny as string instead of list",
			scopeYAML: "authorization: lab\nallow: [example.com]\ndeny: admin.example.com\n",
		},
		{
			name:      "max_rate as string instead of int",
			scopeYAML: "authorization: lab\nallow: [example.com]\nmax_rate: fast\n",
		},
		{
			name:      "timeout as bool instead of int",
			scopeYAML: "authorization: lab\nallow: [example.com]\ntimeout: true\n",
		},
		{
			name:      "authorization as list instead of string",
			scopeYAML: "authorization: [not, a, string]\nallow: [example.com]\n",
		},
		{
			name:      "empty allow inline list",
			scopeYAML: "authorization: lab\nallow: []\n",
		},
		{
			name:      "missing allow field",
			scopeYAML: "authorization: lab\n",
		},
		{
			name:      "empty authorization string",
			scopeYAML: "authorization: ''\nallow: [example.com]\n",
		},
		{
			name:      "whitespace only authorization string",
			scopeYAML: "authorization: '   '\nallow: [example.com]\n",
		},
		{
			name:      "missing authorization field",
			scopeYAML: "allow: [example.com]\n",
		},
		{
			name:      "max_rate zero",
			scopeYAML: "authorization: lab\nallow: [example.com]\nmax_rate: 0\n",
		},
		{
			name:      "max_rate negative",
			scopeYAML: "authorization: lab\nallow: [example.com]\nmax_rate: -10\n",
		},
		{
			name:      "timeout zero",
			scopeYAML: "authorization: lab\nallow: [example.com]\ntimeout: 0\n",
		},
		{
			name:      "timeout negative",
			scopeYAML: "authorization: lab\nallow: [example.com]\ntimeout: -5\n",
		},
		{
			name:      "malformed YAML indentation",
			scopeYAML: "authorization: lab\n  allow:\n- example.com\n",
		},
		{
			name:      "unclosed quote",
			scopeYAML: "authorization: 'unclosed\nallow: [example.com]\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.scopeYAML))
			if err == nil {
				t.Errorf("Parse() succeeded for %s, want error", tt.name)
			}
		})
	}
}

func TestLoadScopeFile(t *testing.T) {
	tempDir := t.TempDir()
	validFile := tempDir + "/scope.yaml"
	content := []byte("authorization: lab\nallow: [example.com]\n")
	if err := os.WriteFile(validFile, content, 0600); err != nil {
		t.Fatalf("failed to write temp scope file: %v", err)
	}

	s, err := Load(validFile)
	if err != nil {
		t.Fatalf("Load() failed on valid file: %v", err)
	}
	if s.Authorization != "lab" || len(s.Allow) != 1 || s.Allow[0] != "example.com" {
		t.Errorf("unexpected loaded scope: %+v", s)
	}

	_, err = Load(tempDir + "/nonexistent.yaml")
	if err == nil {
		t.Error("Load() on non-existent file succeeded, want error")
	}
}

func TestParseRejectsMultipleDocumentsAndNullOrEmptyEntries(t *testing.T) {
	t.Run("rejects valid second document", func(t *testing.T) {
		yamlData := `authorization: lab
allow: [example.com]
---
authorization: second lab
allow: [second.com]
`
		_, err := Parse([]byte(yamlData))
		if err == nil || err.Error() != "scope.yaml harus berisi tepat satu dokumen YAML" {
			t.Fatalf("expected 'scope.yaml harus berisi tepat satu dokumen YAML', got %v", err)
		}
	})

	t.Run("rejects invalid second document", func(t *testing.T) {
		yamlData := `authorization: lab
allow: [example.com]
---
: invalid yaml syntax [
`
		_, err := Parse([]byte(yamlData))
		if err == nil || err.Error() != "scope.yaml harus berisi tepat satu dokumen YAML" {
			t.Fatalf("expected 'scope.yaml harus berisi tepat satu dokumen YAML', got %v", err)
		}
	})

	t.Run("rejects null entry in deny", func(t *testing.T) {
		yamlData := "authorization: lab\nallow: [example.com]\ndeny: [~]\n"
		_, err := Parse([]byte(yamlData))
		if err == nil || !strings.Contains(err.Error(), "deny[0]") || !strings.Contains(err.Error(), "null") {
			t.Fatalf("expected error mentioning deny[0] and null, got %v", err)
		}
	})

	t.Run("rejects empty entry in deny", func(t *testing.T) {
		yamlData := "authorization: lab\nallow: [example.com]\ndeny: ['']\n"
		_, err := Parse([]byte(yamlData))
		if err == nil || !strings.Contains(err.Error(), "deny[0]") || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("expected error mentioning deny[0] and empty, got %v", err)
		}
	})

	t.Run("rejects null entry in allow", func(t *testing.T) {
		yamlData := "authorization: lab\nallow: ['example.com', ~]\n"
		_, err := Parse([]byte(yamlData))
		if err == nil || !strings.Contains(err.Error(), "allow[1]") || !strings.Contains(err.Error(), "null") {
			t.Fatalf("expected error mentioning allow[1] and null, got %v", err)
		}
	})

	t.Run("rejects empty entry in allow", func(t *testing.T) {
		yamlData := "authorization: lab\nallow: ['example.com', '']\n"
		_, err := Parse([]byte(yamlData))
		if err == nil || !strings.Contains(err.Error(), "allow[1]") || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("expected error mentioning allow[1] and empty, got %v", err)
		}
	})
}

func TestScopeHostnameEdgeCases(t *testing.T) {
	scope, err := Parse([]byte("authorization: lab\nallow: [example.com, '*.example.com', '*.com']\n"))
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	label63 := strings.Repeat("a", 63)
	label64 := strings.Repeat("a", 64)

	// Construct exactly 253 chars: 63 + 1 + 63 + 1 + 63 + 1 + 57 + 1 + 3 = 253
	total253 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 57) + ".com"
	// Construct exactly 254 chars: 63 + 1 + 63 + 1 + 63 + 1 + 58 + 1 + 3 = 254
	total254 := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 58) + ".com"

	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		// Label length boundaries (max 63)
		{
			name:     "label exactly 63 characters accepted",
			hostname: label63 + ".com",
			want:     true,
		},
		{
			name:     "label 64 characters rejected",
			hostname: label64 + ".com",
			want:     false,
		},
		{
			name:     "subdomain label 64 characters rejected",
			hostname: "sub." + label64 + ".example.com",
			want:     false,
		},

		// Total hostname length boundaries (max 253)
		{
			name:     "total hostname exactly 253 characters accepted",
			hostname: total253,
			want:     true,
		},
		{
			name:     "total hostname 254 characters rejected",
			hostname: total254,
			want:     false,
		},
		{
			name:     "total hostname well over 253 characters rejected",
			hostname: strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + "." + strings.Repeat("e", 60) + ".com",
			want:     false,
		},

		// Hyphen at label boundaries
		{
			name:     "label starts with hyphen rejected",
			hostname: "-sub.example.com",
			want:     false,
		},
		{
			name:     "label ends with hyphen rejected",
			hostname: "sub-.example.com",
			want:     false,
		},
		{
			name:     "label starts and ends with hyphen rejected",
			hostname: "-sub-.example.com",
			want:     false,
		},
		{
			name:     "apex label starts with hyphen rejected",
			hostname: "-example.com",
			want:     false,
		},
		{
			name:     "apex label ends with hyphen rejected",
			hostname: "example-.com",
			want:     false,
		},
		{
			name:     "label is single hyphen rejected",
			hostname: "-.example.com",
			want:     false,
		},
		{
			name:     "hyphen in middle of label accepted",
			hostname: "valid-label.example.com",
			want:     true,
		},

		// Empty labels
		{
			name:     "empty label consecutive dots rejected",
			hostname: "a..example.com",
			want:     false,
		},
		{
			name:     "empty label middle consecutive dots rejected",
			hostname: "example..com",
			want:     false,
		},
		{
			name:     "empty label leading dot rejected",
			hostname: ".example.com",
			want:     false,
		},
		{
			name:     "empty label double leading dots rejected",
			hostname: "..example.com",
			want:     false,
		},
		{
			name:     "empty label triple dots rejected",
			hostname: "a...example.com",
			want:     false,
		},

		// Non-ASCII characters (fail-closed, no automatic punycode conversion)
		{
			name:     "non-ASCII umlaut ü rejected",
			hostname: "münchen.example.com",
			want:     false,
		},
		{
			name:     "non-ASCII accented letter é rejected",
			hostname: "éxample.com",
			want:     false,
		},
		{
			name:     "non-ASCII Cyrillic rejected",
			hostname: "домен.example.com",
			want:     false,
		},
		{
			name:     "non-ASCII Chinese rejected",
			hostname: "測試.example.com",
			want:     false,
		},
		{
			name:     "non-ASCII Hangul rejected",
			hostname: "테스트.example.com",
			want:     false,
		},
		{
			name:     "non-ASCII Kelvin sign Kelvin Kelvin rejected",
			hostname: "\u212A.example.com",
			want:     false,
		},
		{
			name:     "non-ASCII zero-width space rejected",
			hostname: "api\u200B.example.com",
			want:     false,
		},
		{
			name:     "non-ASCII emoji rejected",
			hostname: "api🔥.example.com",
			want:     false,
		},
		{
			name:     "ASCII Punycode representation of IDN accepted",
			hostname: "xn--mnchen-3ya.example.com",
			want:     true,
		},

		// Target as wildcard pattern input to Allows rejected
		{
			name:     "wildcard subdomain as Allows input rejected",
			hostname: "*.example.com",
			want:     false,
		},
		{
			name:     "wildcard TLD as Allows input rejected",
			hostname: "*.com",
			want:     false,
		},
		{
			name:     "bare wildcard as Allows input rejected",
			hostname: "*",
			want:     false,
		},
		{
			name:     "middle wildcard as Allows input rejected",
			hostname: "api.*.example.com",
			want:     false,
		},
		{
			name:     "trailing wildcard as Allows input rejected",
			hostname: "example.*",
			want:     false,
		},
		{
			name:     "prefix wildcard embedded as Allows input rejected",
			hostname: "*example.com",
			want:     false,
		},
		{
			name:     "suffix wildcard embedded as Allows input rejected",
			hostname: "example*.com",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scope.Allows(tt.hostname); got != tt.want {
				t.Errorf("Allows(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}
