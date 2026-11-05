package runner

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is used as a fake binary for runner testing.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
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

	cmd := args[0]
	switch cmd {
	case "normal":
		// Normal output on stdout, log on stderr
		os.Stderr.WriteString("[INF] Subfinder initialized\n")
		os.Stdout.WriteString("line1\nline2\n")
	case "noisy-stderr":
		os.Stderr.WriteString("warning: log line 1\nwarning: log line 2\n")
		os.Stdout.WriteString("data1\n")
	case "sleep":
		// Sleep for 2 seconds
		time.Sleep(2 * time.Second)
		os.Stdout.WriteString("done sleeping\n")
	case "fail":
		os.Stderr.WriteString("fatal error\n")
		os.Exit(1)
	case "echo-stdin":
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			os.Stdout.WriteString("got:" + scanner.Text() + "\n")
		}
	default:
		os.Exit(2)
	}
}

func helperCommand(args ...string) (string, []string, []string) {
	cs := []string{"-test.run=TestHelperProcess", "--"}
	cs = append(cs, args...)
	env := append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	return os.Args[0], cs, env
}

func TestRunnerNormalExecution(t *testing.T) {
	bin, args, env := helperCommand("normal")
	var stdoutLines []string
	var stderrLines []string

	res := Run(context.Background(), bin, args, Options{
		Timeout: 5 * time.Second,
		Env:     env,
		LineHandler: func(line string) {
			stdoutLines = append(stdoutLines, line)
		},
		StderrHandler: func(line string) {
			stderrLines = append(stderrLines, line)
		},
	})

	if res.Status != StatusComplete {
		t.Errorf("res.Status = %s, want complete", res.Status)
	}
	if res.ExitCode != 0 {
		t.Errorf("res.ExitCode = %d, want 0", res.ExitCode)
	}
	if len(stdoutLines) != 2 || stdoutLines[0] != "line1" || stdoutLines[1] != "line2" {
		t.Errorf("unexpected stdout: %v", stdoutLines)
	}
	if len(stderrLines) != 1 || !strings.Contains(stderrLines[0], "Subfinder initialized") {
		t.Errorf("unexpected stderr: %v", stderrLines)
	}
}

func TestRunnerNoisyStderrSeparation(t *testing.T) {
	bin, args, env := helperCommand("noisy-stderr")
	var stdoutLines []string

	res := Run(context.Background(), bin, args, Options{
		Timeout: 5 * time.Second,
		Env:     env,
		LineHandler: func(line string) {
			stdoutLines = append(stdoutLines, line)
		},
	})

	if res.Status != StatusComplete {
		t.Errorf("res.Status = %s, want complete", res.Status)
	}
	if len(stdoutLines) != 1 || stdoutLines[0] != "data1" {
		t.Errorf("stdout contaminated or missing: %v", stdoutLines)
	}
	if !strings.Contains(res.Stderr, "warning: log line 1") {
		t.Errorf("expected stderr to contain warning log, got %q", res.Stderr)
	}
}

func TestRunnerTimeout(t *testing.T) {
	bin, args, env := helperCommand("sleep")

	start := time.Now()
	res := Run(context.Background(), bin, args, Options{
		Timeout: 100 * time.Millisecond,
		Env:     env,
	})
	elapsed := time.Since(start)

	if elapsed > 1500*time.Millisecond {
		t.Errorf("command did not time out quickly: took %v", elapsed)
	}
	if res.Status != StatusPartial {
		t.Errorf("res.Status = %s, want partial on timeout", res.Status)
	}
	if res.ExitCode != 4 {
		t.Errorf("res.ExitCode = %d, want 4 on timeout", res.ExitCode)
	}
}

func TestRunnerCancel(t *testing.T) {
	bin, args, env := helperCommand("sleep")
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	res := Run(ctx, bin, args, Options{
		Timeout: 5 * time.Second,
		Env:     env,
	})

	if res.Status != StatusCancelled {
		t.Errorf("res.Status = %s, want cancelled", res.Status)
	}
	if res.ExitCode != 130 {
		t.Errorf("res.ExitCode = %d, want 130", res.ExitCode)
	}
}

func TestRunnerCommandNotFound(t *testing.T) {
	res := Run(context.Background(), "non-existent-binary-123456", []string{}, Options{})
	if res.Status != StatusFailed {
		t.Errorf("res.Status = %s, want failed", res.Status)
	}
	if res.ExitCode != 3 {
		t.Errorf("res.ExitCode = %d, want 3", res.ExitCode)
	}
}

func TestRunnerExitFailure(t *testing.T) {
	bin, args, env := helperCommand("fail")
	res := Run(context.Background(), bin, args, Options{
		Timeout: 5 * time.Second,
		Env:     env,
	})

	if res.Status != StatusPartial {
		t.Errorf("res.Status = %s, want partial on non-zero exit", res.Status)
	}
	if res.ExitCode != 1 {
		t.Errorf("res.ExitCode = %d, want 1", res.ExitCode)
	}
}

func TestRunnerStdin(t *testing.T) {
	bin, args, env := helperCommand("echo-stdin")
	var stdoutLines []string

	input := "host1.example.com\nhost2.example.com\n"
	res := Run(context.Background(), bin, args, Options{
		Timeout: 5 * time.Second,
		Env:     env,
		Stdin:   strings.NewReader(input),
		LineHandler: func(line string) {
			stdoutLines = append(stdoutLines, line)
		},
	})

	if res.Status != StatusComplete {
		t.Errorf("res.Status = %s, want complete", res.Status)
	}
	if len(stdoutLines) != 2 || stdoutLines[0] != "got:host1.example.com" || stdoutLines[1] != "got:host2.example.com" {
		t.Errorf("unexpected stdout: %v", stdoutLines)
	}
}
