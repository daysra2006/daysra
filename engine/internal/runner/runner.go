package runner

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// Status represents the termination state of a command run.
type Status string

const (
	StatusComplete  Status = "complete"
	StatusPartial   Status = "partial"
	StatusCancelled Status = "cancelled"
	StatusFailed    Status = "failed"
)

// Options configures command execution.
type Options struct {
	Timeout       time.Duration
	Env           []string
	Stdin         io.Reader
	LineHandler   func(line string)
	StderrHandler func(line string)
}

// Result holds the outcome of running a subprocess command.
type Result struct {
	Status   Status
	ExitCode int
	Stderr   string
	Error    error
}

// Run executes a command with an explicit argument array (no shell), separating stdout and stderr.
// It handles timeouts and intercepts SIGINT to cancel the child process cleanly.
func Run(ctx context.Context, name string, args []string, opts Options) Result {
	if ctx == nil {
		ctx = context.Background()
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// Intercept SIGINT for graceful cancellation of the child process
	sigCtx, stopSig := signal.NotifyContext(runCtx, os.Interrupt, syscall.SIGINT)
	defer stopSig()

	cmd := exec.CommandContext(sigCtx, name, args...)
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(os.Interrupt)
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second

	if opts.Env != nil {
		cmd.Env = opts.Env
	}
	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return Result{
			Status:   StatusFailed,
			ExitCode: 3,
			Error:    fmt.Errorf("create stdout pipe: %w", err),
		}
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return Result{
			Status:   StatusFailed,
			ExitCode: 3,
			Error:    fmt.Errorf("create stderr pipe: %w", err),
		}
	}

	if err := cmd.Start(); err != nil {
		return Result{
			Status:   StatusFailed,
			ExitCode: 3,
			Error:    fmt.Errorf("start command %q: %w", name, err),
		}
	}

	var stderrBuf bytes.Buffer
	stdoutDone := make(chan struct{})
	stderrDone := make(chan struct{})

	// Read stdout line-by-line
	go func() {
		defer close(stdoutDone)
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			if opts.LineHandler != nil {
				opts.LineHandler(line)
			}
		}
	}()

	// Read stderr line-by-line / buffer
	go func() {
		defer close(stderrDone)
		r := io.TeeReader(stderrPipe, &stderrBuf)
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			if opts.StderrHandler != nil {
				opts.StderrHandler(line)
			}
		}
	}()

	<-stdoutDone
	<-stderrDone

	waitErr := cmd.Wait()

	// Check if context timed out or was interrupted
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return Result{
			Status:   StatusPartial,
			ExitCode: 4,
			Stderr:   stderrBuf.String(),
			Error:    runCtx.Err(),
		}
	}

	if errors.Is(sigCtx.Err(), context.Canceled) {
		return Result{
			Status:   StatusCancelled,
			ExitCode: 130,
			Stderr:   stderrBuf.String(),
			Error:    sigCtx.Err(),
		}
	}

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			if ok && (status.Signaled() && status.Signal() == syscall.SIGINT || exitErr.ExitCode() == 130) {
				return Result{
					Status:   StatusCancelled,
					ExitCode: 130,
					Stderr:   stderrBuf.String(),
					Error:    waitErr,
				}
			}
			return Result{
				Status:   StatusPartial,
				ExitCode: exitErr.ExitCode(),
				Stderr:   stderrBuf.String(),
				Error:    waitErr,
			}
		}
		return Result{
			Status:   StatusFailed,
			ExitCode: 3,
			Stderr:   stderrBuf.String(),
			Error:    waitErr,
		}
	}

	return Result{
		Status:   StatusComplete,
		ExitCode: 0,
		Stderr:   stderrBuf.String(),
		Error:    nil,
	}
}
