package runner

import (
	"bufio"
	"context"
	"fmt"
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
	case "control-1k":
		os.Stdout.WriteString(strings.Repeat("C", 1024) + "\n")
	case "large-stdout-128k":
		os.Stdout.WriteString(strings.Repeat("A", 128*1024) + "\n")
	case "large-stdout-1m":
		os.Stdout.WriteString(strings.Repeat("B", 1024*1024) + "\n")
	case "large-stdout-3m":
		os.Stdout.WriteString(strings.Repeat("M", 3*1024*1024) + "\n")
	case "large-stderr-128k":
		os.Stderr.WriteString(strings.Repeat("E", 128*1024) + "\n")
	case "large-stdout-5m":
		os.Stdout.WriteString(strings.Repeat("X", 5*1024*1024) + "\n")
	case "large-stdout-66k-exit-zero":
		os.Stdout.WriteString(strings.Repeat("Z", 66*1024) + "\n")
		os.Exit(0)
	case "valid-before-large-stdout":
		os.Stdout.WriteString("first-valid-line\n")
		os.Stdout.WriteString(strings.Repeat("M", 128*1024) + "\n")
		os.Stdout.WriteString("second-valid-line\n")
	case "pipe-deadlock-evaluation":
		os.Stdout.WriteString(strings.Repeat("S", 128*1024) + "\n")
		os.Stderr.WriteString(strings.Repeat("R", 128*1024) + "\n")
		for i := 0; i < 500; i++ {
			fmt.Fprintf(os.Stdout, "subsequent stdout line %d\n", i)
			fmt.Fprintf(os.Stderr, "subsequent stderr line %d\n", i)
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

// -----------------------------------------------------------------------------
// STAGE 7F-B: FINDING-08 Scanner Reliability Regression Tests
// -----------------------------------------------------------------------------

func TestRunner_StdoutUnderScannerLimit_Control(t *testing.T) {
	bin, args, env := helperCommand("control-1k")
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
	if res.ExitCode != 0 {
		t.Errorf("res.ExitCode = %d, want 0", res.ExitCode)
	}
	if res.Error != nil {
		t.Errorf("res.Error = %v, want nil", res.Error)
	}
	if len(stdoutLines) != 1 || len(stdoutLines[0]) != 1024 {
		t.Errorf("expected 1 line of length 1024, got %d lines (len: %v)", len(stdoutLines), len(stdoutLines[0]))
	}
}

func TestRunner_StdoutLine128KB_ExceedsScannerLimit(t *testing.T) {
	bin, args, env := helperCommand("large-stdout-128k")
	var stdoutLines []string

	res := Run(context.Background(), bin, args, Options{
		Timeout: 500 * time.Millisecond,
		Env:     env,
		LineHandler: func(line string) {
			stdoutLines = append(stdoutLines, line)
		},
	})

	t.Logf("actual result on 128KB line: Status=%q, ExitCode=%d, Error=%v, linesCount=%d", res.Status, res.ExitCode, res.Error, len(stdoutLines))

	if len(stdoutLines) != 1 || len(stdoutLines[0]) != 128*1024 {
		t.Errorf("FINDING-08 reproduced: 128KB stdout line dropped by scanner (got %d lines, want 1 of length %d)", len(stdoutLines), 128*1024)
	}
}

func TestRunner_StdoutLine1MB_ExceedsScannerLimit(t *testing.T) {
	bin, args, env := helperCommand("large-stdout-1m")
	var stdoutLines []string

	res := Run(context.Background(), bin, args, Options{
		Timeout: 500 * time.Millisecond,
		Env:     env,
		LineHandler: func(line string) {
			stdoutLines = append(stdoutLines, line)
		},
	})

	t.Logf("actual result on 1MB line: Status=%q, ExitCode=%d, Error=%v, linesCount=%d", res.Status, res.ExitCode, res.Error, len(stdoutLines))

	if len(stdoutLines) != 1 || len(stdoutLines[0]) != 1024*1024 {
		t.Errorf("FINDING-08 reproduced: 1MB stdout line dropped by scanner (got %d lines, want 1 of length %d)", len(stdoutLines), 1024*1024)
	}
}

func TestRunner_StdoutLine66KB_FalseSuccessAndSilentDataLoss(t *testing.T) {
	bin, args, env := helperCommand("large-stdout-66k-exit-zero")
	var stdoutLines []string

	res := Run(context.Background(), bin, args, Options{
		Timeout: 500 * time.Millisecond,
		Env:     env,
		LineHandler: func(line string) {
			stdoutLines = append(stdoutLines, line)
		},
	})

	t.Logf("actual result on 66KB line with exit 0: Status=%q, ExitCode=%d, Error=%v, linesCount=%d", res.Status, res.ExitCode, res.Error, len(stdoutLines))

	// Under current implementation:
	// Child process exits 0 cleanly.
	// Scanner drops the 66KB line silently due to bufio.ErrTooLong.
	// runner.Run returns StatusComplete with ExitCode 0 and Error nil!
	// This proves FINDING-08: false success and silent data loss.
	if len(stdoutLines) != 1 || len(stdoutLines[0]) != 66*1024 {
		t.Errorf("FINDING-08 reproduced: 66KB line silently dropped by scanner (got %d lines, want 1)", len(stdoutLines))
	}
	if res.Status == StatusComplete && len(stdoutLines) == 0 {
		t.Errorf("FINDING-08 reproduced: runner returned StatusComplete (false success) despite dropping 66KB output line")
	}
}

func TestRunner_StderrLine128KB_ExceedsScannerLimit(t *testing.T) {
	bin, args, env := helperCommand("large-stderr-128k")
	var stderrLines []string

	res := Run(context.Background(), bin, args, Options{
		Timeout: 500 * time.Millisecond,
		Env:     env,
		StderrHandler: func(line string) {
			stderrLines = append(stderrLines, line)
		},
	})

	t.Logf("actual result on 128KB stderr: Status=%q, ExitCode=%d, Error=%v, StderrLen=%d, StderrLinesCount=%d", res.Status, res.ExitCode, res.Error, len(res.Stderr), len(stderrLines))

	if len(stderrLines) != 1 || len(stderrLines[0]) != 128*1024 {
		t.Errorf("FINDING-08 reproduced: 128KB stderr line dropped by StderrHandler (got %d lines, want 1 of length %d)", len(stderrLines), 128*1024)
	}
	if len(res.Stderr) < 128*1024 {
		t.Errorf("FINDING-08 reproduced: res.Stderr truncated by scanner (got %d bytes, want >= %d)", len(res.Stderr), 128*1024)
	}
	if res.Error == nil && len(res.Stderr) < 128*1024 {
		t.Errorf("FINDING-08 reproduced: stderr truncation occurred but runner returned nil error")
	}
}

func TestRunner_StdoutLine3MB_WithinMaxCapacity(t *testing.T) {
	bin, args, env := helperCommand("large-stdout-3m")
	var stdoutLines []string

	res := Run(context.Background(), bin, args, Options{
		Timeout: 2 * time.Second,
		Env:     env,
		LineHandler: func(line string) {
			stdoutLines = append(stdoutLines, line)
		},
	})

	if res.Status != StatusComplete {
		t.Errorf("res.Status = %s, want complete for 3MB line within 4MB capacity", res.Status)
	}
	if res.ExitCode != 0 {
		t.Errorf("res.ExitCode = %d, want 0", res.ExitCode)
	}
	if res.Error != nil {
		t.Errorf("res.Error = %v, want nil", res.Error)
	}
	if len(stdoutLines) != 1 || len(stdoutLines[0]) != 3*1024*1024 {
		t.Errorf("expected 1 line of length 3MB, got %d lines", len(stdoutLines))
	}
}

func TestRunner_StdoutLine5MB_TokenTooLong(t *testing.T) {
	bin, args, env := helperCommand("large-stdout-5m")
	var stdoutLines []string

	start := time.Now()
	res := Run(context.Background(), bin, args, Options{
		Timeout: 2 * time.Second,
		Env:     env,
		LineHandler: func(line string) {
			stdoutLines = append(stdoutLines, line)
		},
	})
	elapsed := time.Since(start)

	t.Logf("actual 5MB result: Status=%q, ExitCode=%d, Error=%v, linesCount=%d, elapsed=%v",
		res.Status, res.ExitCode, res.Error, len(stdoutLines), elapsed)

	// 1. Scanner error must be detected and propagated to caller
	if res.Error == nil {
		t.Fatalf("expected scanner error for line exceeding maxScanTokenSize (4MB), got nil")
	}
	if !strings.Contains(res.Error.Error(), "stdout scanner error") && !strings.Contains(res.Error.Error(), "token too long") {
		t.Errorf("expected error to identify stdout scanner error, got: %v", res.Error)
	}

	// 2. Status must be partial, not complete
	if res.Status != StatusPartial {
		t.Errorf("res.Status = %s, want partial for token exceeding maximum capacity", res.Status)
	}

	// 3. Exit code must be 4
	if res.ExitCode != 4 {
		t.Errorf("res.ExitCode = %d, want 4 for scanner failure", res.ExitCode)
	}

	// 4. Line was not emitted as oversized token
	if len(stdoutLines) != 0 {
		t.Errorf("expected 0 lines emitted for token exceeding max buffer, got %d", len(stdoutLines))
	}

	// 5. Runner did not deadlock: active draining allowed subprocess to exit cleanly well before timeout
	if elapsed >= 1800*time.Millisecond {
		t.Errorf("runner appears to have deadlocked/timed out: took %v", elapsed)
	}
}

func TestRunner_Stdout_ValidLineBeforeAndAfterLargeLine(t *testing.T) {
	bin, args, env := helperCommand("valid-before-large-stdout")
	var stdoutLines []string

	res := Run(context.Background(), bin, args, Options{
		Timeout: 500 * time.Millisecond,
		Env:     env,
		LineHandler: func(line string) {
			stdoutLines = append(stdoutLines, line)
		},
	})

	t.Logf("actual lines received: count=%d, values=%v, status=%s, error=%v", len(stdoutLines), stdoutLines, res.Status, res.Error)

	if len(stdoutLines) < 1 || stdoutLines[0] != "first-valid-line" {
		t.Errorf("expected first valid line before large line to be received, got: %v", stdoutLines)
	}
	if len(stdoutLines) < 3 || stdoutLines[len(stdoutLines)-1] != "second-valid-line" {
		t.Errorf("FINDING-08 reproduced: valid line following 128KB line was dropped by scanner (received %d lines: %v)", len(stdoutLines), stdoutLines)
	}
}

func TestRunner_PipeLifecycle_DeadlockEvaluation(t *testing.T) {
	bin, args, env := helperCommand("pipe-deadlock-evaluation")
	var stdoutLines []string
	var stderrLines []string

	start := time.Now()
	res := Run(context.Background(), bin, args, Options{
		Timeout: 2 * time.Second,
		Env:     env,
		LineHandler: func(line string) {
			stdoutLines = append(stdoutLines, line)
		},
		StderrHandler: func(line string) {
			stderrLines = append(stderrLines, line)
		},
	})
	elapsed := time.Since(start)

	t.Logf("pipe deadlock test completed in %v: Status=%q, ExitCode=%d, Error=%v, stdoutLines=%d, stderrLines=%d",
		elapsed, res.Status, res.ExitCode, res.Error, len(stdoutLines), len(stderrLines))

	if res.Status != StatusComplete || res.Error != nil {
		t.Errorf("FINDING-08 reproduced: runner failed or deadlocked/timed out on unconsumed pipe streams (status=%s, exitCode=%d, error=%v, elapsed=%v)",
			res.Status, res.ExitCode, res.Error, elapsed)
	}
}
