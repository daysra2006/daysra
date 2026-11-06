package httpx

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildArgs(t *testing.T) {
	tests := []struct {
		name     string
		maxRate  int
		wantArgs []string
	}{
		{
			name:     "default options",
			maxRate:  0,
			wantArgs: []string{"-silent", "-json", "-sc", "-title", "-td", "-cl", "-timeout", "10"},
		},
		{
			name:     "with max rate",
			maxRate:  10,
			wantArgs: []string{"-silent", "-json", "-sc", "-title", "-td", "-cl", "-timeout", "10", "-rl", "10"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildArgs(tt.maxRate)
			if !reflect.DeepEqual(got, tt.wantArgs) {
				t.Errorf("BuildArgs = %v, want %v", got, tt.wantArgs)
			}
			// Rule 17: Follow redirects must never be passed
			for _, arg := range got {
				if arg == "-fr" || arg == "-follow-redirects" || arg == "-fhr" {
					t.Errorf("BuildArgs included forbidden redirect flag: %s", arg)
				}
			}
		})
	}
}

func TestBuildArgsUsesPerRequestTimeoutConstant(t *testing.T) {
	if RequestTimeout != 10 {
		t.Errorf("RequestTimeout = %d, want 10 (httpx v1.12.0 default)", RequestTimeout)
	}
	args := BuildArgs(10)
	got := flagValue(args, "-timeout")
	if got != "10" {
		t.Errorf("-timeout = %q, want %q", got, "10")
	}
}

func flagValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantHost    string
		wantURL     string
		wantCode    int
		wantTitle   string
		wantTechLen int
		wantErr     bool
	}{
		{
			name:        "complete entry",
			line:        `{"url":"https://api.example.com","host":"api.example.com","status_code":200,"title":"API Home","content_length":1024,"tech":["Go","Nginx"]}`,
			wantHost:    "api.example.com",
			wantURL:     "https://api.example.com",
			wantCode:    200,
			wantTitle:   "API Home",
			wantTechLen: 2,
			wantErr:     false,
		},
		{
			name:        "host extracted from url",
			line:        `{"url":"http://sub.example.com:8080/test","status_code":302,"title":"Redirect","content_length":0}`,
			wantHost:    "sub.example.com",
			wantURL:     "http://sub.example.com:8080/test",
			wantCode:    302,
			wantTitle:   "Redirect",
			wantTechLen: 0,
			wantErr:     false,
		},
		{
			name:        "host with port stripped",
			line:        `{"host":"app.example.com:8443","url":"https://app.example.com:8443","status_code":403,"title":"Forbidden"}`,
			wantHost:    "app.example.com",
			wantURL:     "https://app.example.com:8443",
			wantCode:    403,
			wantTitle:   "Forbidden",
			wantTechLen: 0,
			wantErr:     false,
		},
		{
			name:    "empty line",
			line:    "   ",
			wantErr: true,
		},
		{
			name:    "invalid json",
			line:    `{"url": broken`,
			wantErr: true,
		},
		{
			name:    "missing all host fields",
			line:    `{"status_code":200,"title":"Orphan"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ParseLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseLine() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if res.Hostname != tt.wantHost {
					t.Errorf("Hostname = %q, want %q", res.Hostname, tt.wantHost)
				}
				if res.URL != tt.wantURL {
					t.Errorf("URL = %q, want %q", res.URL, tt.wantURL)
				}
				if res.StatusCode != tt.wantCode {
					t.Errorf("StatusCode = %d, want %d", res.StatusCode, tt.wantCode)
				}
				if res.Title != tt.wantTitle {
					t.Errorf("Title = %q, want %q", res.Title, tt.wantTitle)
				}
				if len(res.Tech) != tt.wantTechLen {
					t.Errorf("Tech len = %d, want %d", len(res.Tech), tt.wantTechLen)
				}
			}
		})
	}
}

func TestParseLine_URLEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantHost string
		wantURL  string
		wantErr  bool
	}{
		{
			name:     "uppercase scheme and hostname",
			line:     `{"url":"HTTPS://API.EXAMPLE.COM/PATH","host":"API.EXAMPLE.COM","status_code":200}`,
			wantHost: "API.EXAMPLE.COM",
			wantURL:  "HTTPS://API.EXAMPLE.COM/PATH",
			wantErr:  false,
		},
		{
			name:     "trailing dot in host and url",
			line:     `{"url":"https://api.example.com./","host":"api.example.com.","status_code":200}`,
			wantHost: "api.example.com.",
			wantURL:  "https://api.example.com./",
			wantErr:  false,
		},
		{
			name:     "hostname with port in host and url",
			line:     `{"url":"https://api.example.com:8443/login","host":"api.example.com:8443","status_code":200}`,
			wantHost: "api.example.com",
			wantURL:  "https://api.example.com:8443/login",
			wantErr:  false,
		},
		{
			name:     "IDN unicode hostname",
			line:     `{"url":"https://münchen.example.com/","host":"münchen.example.com","status_code":200}`,
			wantHost: "münchen.example.com",
			wantURL:  "https://münchen.example.com/",
			wantErr:  false,
		},
		{
			name:     "empty URL with valid host",
			line:     `{"url":"","host":"example.com","status_code":200}`,
			wantHost: "example.com",
			wantURL:  "",
			wantErr:  false,
		},
		{
			name:     "malformed URL string with valid host",
			line:     `{"url":":::not-valid:::","host":"example.com","status_code":200}`,
			wantHost: "example.com",
			wantURL:  ":::not-valid:::",
			wantErr:  false,
		},
		{
			name:     "userinfo URL",
			line:     `{"url":"https://user:pass@example.com/secret","host":"example.com","status_code":200}`,
			wantHost: "example.com",
			wantURL:  "https://user:pass@example.com/secret",
			wantErr:  false,
		},
		{
			name:     "URL with fragment",
			line:     `{"url":"https://example.com/page#section","host":"example.com","status_code":200}`,
			wantHost: "example.com",
			wantURL:  "https://example.com/page#section",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ParseLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseLine() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if res.Hostname != tt.wantHost {
					t.Errorf("Hostname = %q, want %q", res.Hostname, tt.wantHost)
				}
				if res.URL != tt.wantURL {
					t.Errorf("URL = %q, want %q", res.URL, tt.wantURL)
				}
			}
		})
	}
}

func TestParseVersionFromRealFixture(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "..", "tests", "fixtures", "tools", "httpx", "v1.12.0", "version.stderr.txt")
	content, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read fixture file %s: %v", fixturePath, err)
	}

	version := ParseVersion(string(content))
	if version != "v1.12.0" {
		t.Errorf("ParseVersion = %q, want v1.12.0", version)
	}
}

func TestParseOutputFromRealFixture(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "..", "tests", "fixtures", "tools", "httpx", "v1.12.0", "output.jsonl")
	content, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read fixture file %s: %v", fixturePath, err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("expected non-empty fixture file")
	}

	for i, line := range lines {
		res, err := ParseLine(line)
		if err != nil {
			t.Fatalf("line %d: unexpected ParseLine error: %v", i, err)
		}
		if res.Hostname != "example.org" {
			t.Errorf("line %d: Hostname = %q, want 'example.org'", i, res.Hostname)
		}
		if res.URL != "https://example.org" {
			t.Errorf("line %d: URL = %q, want 'https://example.org'", i, res.URL)
		}
		if res.StatusCode != 200 {
			t.Errorf("line %d: StatusCode = %d, want 200", i, res.StatusCode)
		}
		if res.ContentLength != 1256 {
			t.Errorf("line %d: ContentLength = %d, want 1256", i, res.ContentLength)
		}
		if len(res.Tech) == 0 {
			t.Errorf("line %d: expected non-empty Tech slice", i)
		}
	}
}

// Helper process for httpx check version
func TestHttpxHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HTTPX_HELPER") != "1" {
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

	if len(args) == 0 {
		os.Exit(2)
	}

	switch args[0] {
	case "version-match":
		os.Stderr.WriteString("[INF] Current Version: v1.12.0\n")
	case "version-diff":
		os.Stderr.WriteString("[INF] Current Version: v1.11.0\n")
	case "version-fail":
		os.Stderr.WriteString("error: unable to initialize\n")
		os.Exit(1)
	default:
		os.Exit(2)
	}
}

func httpxHelper(cmd string) (string, []string) {
	return os.Args[0], []string{"-test.run=TestHttpxHelperProcess", "--", cmd}
}

func TestCheckVersion(t *testing.T) {
	t.Setenv("GO_WANT_HTTPX_HELPER", "1")

	t.Run("matching version", func(t *testing.T) {
		bin, args := httpxHelper("version-match")
		tempDir := t.TempDir()
		wrapper := filepath.Join(tempDir, "httpx")
		script := "#!/bin/sh\nexec " + bin + " " + args[0] + " " + args[1] + " " + args[2] + " \"$@\"\n"
		if err := os.WriteFile(wrapper, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}

		ver, warn, err := CheckVersion(context.Background(), wrapper)
		if err != nil {
			t.Fatalf("CheckVersion error: %v", err)
		}
		if ver != "v1.12.0" {
			t.Errorf("ver = %q, want v1.12.0", ver)
		}
		if warn != "" {
			t.Errorf("expected no warning, got %q", warn)
		}
	})

	t.Run("differing version produces warning", func(t *testing.T) {
		bin, args := httpxHelper("version-diff")
		tempDir := t.TempDir()
		wrapper := filepath.Join(tempDir, "httpx")
		script := "#!/bin/sh\nexec " + bin + " " + args[0] + " " + args[1] + " " + args[2] + " \"$@\"\n"
		if err := os.WriteFile(wrapper, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}

		ver, warn, err := CheckVersion(context.Background(), wrapper)
		if err != nil {
			t.Fatalf("CheckVersion error: %v", err)
		}
		if ver != "v1.11.0" {
			t.Errorf("ver = %q, want v1.11.0", ver)
		}
		if warn == "" {
			t.Error("expected warning for differing version, got empty")
		}
	})

	t.Run("missing binary returns error", func(t *testing.T) {
		_, _, err := CheckVersion(context.Background(), "/nonexistent/httpx")
		if err == nil {
			t.Error("expected error for nonexistent binary, got nil")
		}
	})
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name         string
		rawURL       string
		wantURL      string
		wantHostname string
		wantErr      bool
	}{
		{
			name:         "valid https url with path and query",
			rawURL:       "https://example.com/path?key=val",
			wantURL:      "https://example.com/path?key=val",
			wantHostname: "example.com",
			wantErr:      false,
		},
		{
			name:         "valid http url",
			rawURL:       "http://example.com",
			wantURL:      "http://example.com",
			wantHostname: "example.com",
			wantErr:      false,
		},
		{
			name:         "uppercase scheme and hostname normalized",
			rawURL:       "HTTPS://API.EXAMPLE.COM/Path?Q=1",
			wantURL:      "https://api.example.com/Path?Q=1",
			wantHostname: "api.example.com",
			wantErr:      false,
		},
		{
			name:         "trailing dot in hostname stripped",
			rawURL:       "https://api.example.com./test",
			wantURL:      "https://api.example.com/test",
			wantHostname: "api.example.com",
			wantErr:      false,
		},
		{
			name:         "valid custom port preserved",
			rawURL:       "https://api.example.com:8443/login",
			wantURL:      "https://api.example.com:8443/login",
			wantHostname: "api.example.com",
			wantErr:      false,
		},
		{
			name:         "fragment stripped",
			rawURL:       "https://example.com/page#section-one",
			wantURL:      "https://example.com/page",
			wantHostname: "example.com",
			wantErr:      false,
		},
		{
			name:         "IDN unicode hostname converted to punycode",
			rawURL:       "https://münchen.example.com/events",
			wantURL:      "https://xn--mnchen-3ya.example.com/events",
			wantHostname: "xn--mnchen-3ya.example.com",
			wantErr:      false,
		},
		{
			name:    "empty url rejected",
			rawURL:  "",
			wantErr: true,
		},
		{
			name:    "whitespace only url rejected",
			rawURL:  "   ",
			wantErr: true,
		},
		{
			name:    "relative url rejected",
			rawURL:  "/api/v1/status",
			wantErr: true,
		},
		{
			name:    "missing scheme rejected",
			rawURL:  "example.com/path",
			wantErr: true,
		},
		{
			name:    "ftp scheme rejected",
			rawURL:  "ftp://example.com/file",
			wantErr: true,
		},
		{
			name:    "javascript scheme rejected",
			rawURL:  "javascript:alert(1)",
			wantErr: true,
		},
		{
			name:    "file scheme rejected",
			rawURL:  "file:///etc/passwd",
			wantErr: true,
		},
		{
			name:    "missing hostname rejected",
			rawURL:  "http:///path",
			wantErr: true,
		},
		{
			name:    "userinfo with password rejected",
			rawURL:  "https://admin:secret@example.com/dashboard",
			wantErr: true,
		},
		{
			name:    "userinfo without password rejected",
			rawURL:  "https://target.com@attacker.test/phish",
			wantErr: true,
		},
		{
			name:    "invalid non-numeric port rejected",
			rawURL:  "https://example.com:abc/login",
			wantErr: true,
		},
		{
			name:    "invalid out-of-range port rejected",
			rawURL:  "https://example.com:99999/login",
			wantErr: true,
		},
		{
			name:    "port zero rejected",
			rawURL:  "https://example.com:0/login",
			wantErr: true,
		},
		{
			name:    "ipv4 literal rejected per scope policy",
			rawURL:  "https://192.168.1.1/admin",
			wantErr: true,
		},
		{
			name:    "ipv6 literal rejected per scope policy",
			rawURL:  "https://[::1]:8080/admin",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeURL(tt.rawURL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SanitizeURL(%q) error = %v, wantErr = %v", tt.rawURL, err, tt.wantErr)
			}
			if !tt.wantErr {
				if got.String() != tt.wantURL {
					t.Errorf("SanitizeURL().String() = %q, want %q", got.String(), tt.wantURL)
				}
				if got.Hostname() != tt.wantHostname {
					t.Errorf("SanitizeURL().Hostname() = %q, want %q", got.Hostname(), tt.wantHostname)
				}
			}
		})
	}
}

func TestSanitizeURL_ExplicitEmptyPortRejected(t *testing.T) {
	// Negative test cases: explicit empty port must be rejected (wantErr = true)
	emptyPortTests := []struct {
		name   string
		rawURL string
	}{
		{
			name:   "scheme host and trailing colon without port",
			rawURL: "https://api.example.com:",
		},
		{
			name:   "http scheme host and trailing colon with path",
			rawURL: "http://api.example.com:/login",
		},
		{
			name:   "https scheme host and trailing colon with path and query",
			rawURL: "https://api.example.com:/path?key=value",
		},
	}

	for _, tt := range emptyPortTests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeURL(tt.rawURL)
			if err == nil {
				t.Fatalf("SanitizeURL(%q) unexpectedly succeeded (got %q); explicit empty port must be rejected with error", tt.rawURL, got.String())
			}
		})
	}

	// Positive control: valid URLs with or without legitimate port must be accepted
	positiveControls := []struct {
		name         string
		rawURL       string
		wantURL      string
		wantHostname string
	}{
		{
			name:         "valid url without port",
			rawURL:       "https://api.example.com/login",
			wantURL:      "https://api.example.com/login",
			wantHostname: "api.example.com",
		},
		{
			name:         "valid url with explicit valid port",
			rawURL:       "https://api.example.com:8443/login",
			wantURL:      "https://api.example.com:8443/login",
			wantHostname: "api.example.com",
		},
	}

	for _, tt := range positiveControls {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeURL(tt.rawURL)
			if err != nil {
				t.Fatalf("positive control SanitizeURL(%q) failed: %v", tt.rawURL, err)
			}
			if got.String() != tt.wantURL {
				t.Errorf("SanitizeURL(%q).String() = %q, want %q", tt.rawURL, got.String(), tt.wantURL)
			}
			if got.Hostname() != tt.wantHostname {
				t.Errorf("SanitizeURL(%q).Hostname() = %q, want %q", tt.rawURL, got.Hostname(), tt.wantHostname)
			}
		})
	}
}
