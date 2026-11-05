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
		timeout  int
		wantArgs []string
	}{
		{
			name:     "default options",
			maxRate:  0,
			timeout:  0,
			wantArgs: []string{"-silent", "-json", "-sc", "-title", "-td", "-cl"},
		},
		{
			name:     "with max rate and timeout",
			maxRate:  10,
			timeout:  15,
			wantArgs: []string{"-silent", "-json", "-sc", "-title", "-td", "-cl", "-rl", "10", "-timeout", "15"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildArgs(tt.maxRate, tt.timeout)
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
