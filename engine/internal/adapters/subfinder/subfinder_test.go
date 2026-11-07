package subfinder

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBuildArgs(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		maxRate  int
		wantArgs []string
	}{
		{
			name:     "default options",
			target:   "example.com",
			maxRate:  0,
			wantArgs: []string{"-d", "example.com", "-silent", "-oJ", "-cs", "-timeout", "30"},
		},
		{
			name:     "with max rate",
			target:   "example.com",
			maxRate:  50,
			wantArgs: []string{"-d", "example.com", "-silent", "-oJ", "-cs", "-timeout", "30", "-rl", "50"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildArgs(tt.target, tt.maxRate)
			if !reflect.DeepEqual(got, tt.wantArgs) {
				t.Errorf("BuildArgs = %v, want %v", got, tt.wantArgs)
			}
		})
	}
}

func TestBuildArgsUsesPerRequestTimeoutConstant(t *testing.T) {
	if RequestTimeout != 30 {
		t.Errorf("RequestTimeout = %d, want 30 (subfinder v2.17.0 default)", RequestTimeout)
	}
	args := BuildArgs("example.com", 50)
	got := flagValue(args, "-timeout")
	if got != "30" {
		t.Errorf("-timeout = %q, want %q", got, "30")
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
		wantSources []string
		wantIPs     []string
		wantErr     bool
	}{
		{
			name:        "multiple sources array",
			line:        `{"host":"api.example.com","input":"example.com","sources":["crtsh","alienvault"]}`,
			wantHost:    "api.example.com",
			wantSources: []string{"alienvault", "crtsh"},
			wantErr:     false,
		},
		{
			name:        "single source field",
			line:        `{"host":"web.example.com","input":"example.com","source":"subfinder"}`,
			wantHost:    "web.example.com",
			wantSources: []string{"subfinder"},
			wantErr:     false,
		},
		{
			name:        "with ips",
			line:        `{"host":"mail.example.com","input":"example.com","source":"dns","ip":"192.0.2.1","ips":["192.0.2.2"]}`,
			wantHost:    "mail.example.com",
			wantSources: []string{"dns"},
			wantIPs:     []string{"192.0.2.1", "192.0.2.2"},
			wantErr:     false,
		},
		{
			name:    "empty line",
			line:    "   ",
			wantErr: true,
		},
		{
			name:    "invalid json",
			line:    `{"host": incomplete`,
			wantErr: true,
		},
		{
			name:    "missing host field",
			line:    `{"input":"example.com","source":"crtsh"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := ParseLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseLine() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if h.Hostname != tt.wantHost {
					t.Errorf("Hostname = %q, want %q", h.Hostname, tt.wantHost)
				}
				if len(tt.wantSources) > 0 && !reflect.DeepEqual(h.Sources, tt.wantSources) {
					t.Errorf("Sources = %v, want %v", h.Sources, tt.wantSources)
				}
				if len(tt.wantIPs) > 0 && !reflect.DeepEqual(h.IPs, tt.wantIPs) {
					t.Errorf("IPs = %v, want %v", h.IPs, tt.wantIPs)
				}
			}
		})
	}
}

func TestParseVersionFromRealFixture(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "..", "tests", "fixtures", "tools", "subfinder", "v2.17.0", "version.stderr.txt")
	content, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read fixture file %s: %v", fixturePath, err)
	}

	version := ParseVersion(string(content))
	if version != "v2.17.0" {
		t.Errorf("ParseVersion = %q, want v2.17.0", version)
	}
}

func TestParseOutputFromRealFixture(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "..", "tests", "fixtures", "tools", "subfinder", "v2.17.0", "output.jsonl")
	content, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read fixture file %s: %v", fixturePath, err)
	}

	lines := splitLines(string(content))
	if len(lines) == 0 {
		t.Fatal("expected non-empty fixture file")
	}

	for i, line := range lines {
		h, err := ParseLine(line)
		if err != nil {
			t.Fatalf("line %d: unexpected ParseLine error: %v", i, err)
		}
		if h.Hostname == "" {
			t.Fatalf("line %d: empty hostname", i)
		}
	}
}

func splitLines(s string) []string {
	var lines []string
	for _, l := range reflect.ValueOf(s).String() {
		_ = l
	}
	// Simple line split
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			trimmed := s[start:i]
			if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '\r' {
				trimmed = trimmed[:len(trimmed)-1]
			}
			if len(trimmed) > 0 {
				lines = append(lines, trimmed)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		trimmed := s[start:]
		if len(trimmed) > 0 {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// Helper process for subfinder check version
func TestSubfinderHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SUBFINDER_HELPER") != "1" {
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
		os.Stderr.WriteString("[INF] Current Version: v2.17.0\n[INF] Subfinder Config: /home/user/.config\n")
	case "version-diff":
		os.Stderr.WriteString("[INF] Current Version: v2.16.0\n")
	case "version-fail":
		os.Stderr.WriteString("error: unable to read config\n")
		os.Exit(1)
	default:
		os.Exit(2)
	}
}

func subfinderHelper(cmd string) (string, []string) {
	return os.Args[0], []string{"-test.run=TestSubfinderHelperProcess", "--", cmd}
}

func TestCheckVersion(t *testing.T) {
	t.Setenv("GO_WANT_SUBFINDER_HELPER", "1")

	t.Run("matching version", func(t *testing.T) {
		bin, args := subfinderHelper("version-match")
		// Wrapper script that forwards to helper command
		tempDir := t.TempDir()
		wrapper := filepath.Join(tempDir, "subfinder")
		script := "#!/bin/sh\nexec " + bin + " " + args[0] + " " + args[1] + " " + args[2] + " \"$@\"\n"
		if err := os.WriteFile(wrapper, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}

		ver, warn, err := CheckVersion(context.Background(), wrapper)
		if err != nil {
			t.Fatalf("CheckVersion error: %v", err)
		}
		if ver != "v2.17.0" {
			t.Errorf("ver = %q, want v2.17.0", ver)
		}
		if warn != "" {
			t.Errorf("expected no warning, got %q", warn)
		}
	})

	t.Run("differing version produces warning", func(t *testing.T) {
		bin, args := subfinderHelper("version-diff")
		tempDir := t.TempDir()
		wrapper := filepath.Join(tempDir, "subfinder")
		script := "#!/bin/sh\nexec " + bin + " " + args[0] + " " + args[1] + " " + args[2] + " \"$@\"\n"
		if err := os.WriteFile(wrapper, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}

		ver, warn, err := CheckVersion(context.Background(), wrapper)
		if err != nil {
			t.Fatalf("CheckVersion error: %v", err)
		}
		if ver != "v2.16.0" {
			t.Errorf("ver = %q, want v2.16.0", ver)
		}
		if warn == "" {
			t.Error("expected warning for differing version, got empty")
		}
	})

	t.Run("missing binary returns error", func(t *testing.T) {
		_, _, err := CheckVersion(context.Background(), "/nonexistent/subfinder")
		if err == nil {
			t.Error("expected error for nonexistent binary, got nil")
		}
	})
}
