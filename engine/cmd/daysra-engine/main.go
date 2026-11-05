package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"daysra-engine/internal/adapters/httpx"
	"daysra-engine/internal/adapters/nuclei"
	"daysra-engine/internal/adapters/subfinder"
	"daysra-engine/internal/emit"
	"daysra-engine/internal/normalize"
	"daysra-engine/internal/runner"
	"daysra-engine/internal/scope"
)

const version = "0.0.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	return runWithIOStdin(context.Background(), args, os.Stdin, os.Stdout, os.Stderr)
}

func runWithIO(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithIOStdin(ctx, args, os.Stdin, stdout, stderr)
}

func runWithIOStdin(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "--version", "-version", "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "check-scope":
		return runCheckScope(args[1:], stderr)
	case "recon":
		return runRecon(ctx, args[1:], stdout, stderr)
	case "probe":
		return runProbe(ctx, args[1:], stdin, stdout, stderr)
	case "scan":
		return runScan(ctx, args[1:], stdin, stdout, stderr)
	default:
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: daysra-engine --version")
	fmt.Fprintln(w, "       daysra-engine check-scope --scope <file> --target <target>")
	fmt.Fprintln(w, "       daysra-engine recon --target <target> --scope <file> --run-id <run-id>")
	fmt.Fprintln(w, "       daysra-engine probe --scope <file> --run-id <run-id>")
	fmt.Fprintln(w, "       daysra-engine scan --scope <file> --run-id <run-id> [--include-tags <tags>]")
}

func runCheckScope(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("check-scope", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var scopePath, target string
	fs.StringVar(&scopePath, "scope", "", "path to scope.yaml")
	fs.StringVar(&target, "target", "", "target hostname")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "check-scope: %v\n", err)
		return 2
	}

	if scopePath == "" || target == "" {
		fmt.Fprintln(stderr, "check-scope: both --scope and --target are required")
		return 2
	}

	s, err := scope.Load(scopePath)
	if err != nil {
		fmt.Fprintf(stderr, "check-scope: failed to load scope: %v\n", err)
		return 2
	}

	normalizedTarget, err := normalize.Hostname(target)
	if err != nil {
		fmt.Fprintf(stderr, "check-scope: invalid target %q: %v\n", target, err)
		return 2
	}

	if !s.Allows(normalizedTarget) {
		fmt.Fprintf(stderr, "check-scope: target %q is out of scope\n", normalizedTarget)
		return 2
	}

	return 0
}

func runRecon(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}

	fs := flag.NewFlagSet("recon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var target, scopePath, runID, subfinderBin string
	fs.StringVar(&target, "target", "", "target domain")
	fs.StringVar(&scopePath, "scope", "", "path to scope.yaml")
	fs.StringVar(&runID, "run-id", "", "unique run ULID")
	fs.StringVar(&subfinderBin, "subfinder-bin", "", "custom subfinder binary (testing)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "recon: flag error: %v\n", err)
		return 2
	}

	if target == "" || scopePath == "" || runID == "" {
		fmt.Fprintln(stderr, "recon: --target, --scope, and --run-id are all required")
		return 2
	}

	s, err := scope.Load(scopePath)
	if err != nil {
		fmt.Fprintf(stderr, "recon: failed to load scope: %v\n", err)
		return 2
	}

	normalizedTarget, err := normalize.Hostname(target)
	if err != nil {
		fmt.Fprintf(stderr, "recon: invalid target %q: %v\n", target, err)
		return 2
	}

	if !s.Allows(normalizedTarget) {
		fmt.Fprintf(stderr, "recon: target %q is out of scope\n", normalizedTarget)
		return 2
	}

	// Resolve subfinder binary
	binaryPath := subfinderBin
	if binaryPath == "" {
		binaryPath = os.Getenv("DAYSRA_SUBFINDER_BIN")
	}
	if binaryPath == "" {
		var err error
		binaryPath, err = exec.LookPath("subfinder")
		if err != nil {
			fmt.Fprintf(stderr, "recon: subfinder not found in PATH: %v\n", err)
			return 3
		}
	}

	version, versionWarn, err := subfinder.CheckVersion(ctx, binaryPath)
	if err != nil {
		fmt.Fprintf(stderr, "recon: failed to verify subfinder: %v\n", err)
		return 3
	}

	emitter := emit.New(runID, stdout)
	defer emitter.Close()

	toolVersions := map[string]string{"subfinder": version}
	if err := emitter.EmitRunStart(map[string]any{
		"target":        normalizedTarget,
		"tool_versions": toolVersions,
	}); err != nil {
		fmt.Fprintf(stderr, "recon: emit run_start failed: %v\n", err)
	}

	if versionWarn != "" {
		_ = emitter.EmitWarning(map[string]any{
			"message": versionWarn,
		})
	}

	registry := normalize.NewRegistry()
	var outOfScopeCount int
	var corruptLinesCount int

	subfinderArgs := subfinder.BuildArgs(normalizedTarget, s.MaxRate, s.Timeout)

	timeout := time.Duration(s.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	runRes := runner.Run(ctx, binaryPath, subfinderArgs, runner.Options{
		Timeout: timeout,
		LineHandler: func(line string) {
			host, err := subfinder.ParseLine(line)
			if err != nil {
				corruptLinesCount++
				return
			}

			normHost, err := normalize.Hostname(host.Hostname)
			if err != nil {
				corruptLinesCount++
				return
			}

			// Pre-emit scope check: filtered hosts are not emitted
			if !s.Allows(normHost) {
				outOfScopeCount++
				return
			}

			entry, isNew, _ := registry.Add(normHost, host.IPs, host.Sources)
			if isNew {
				_ = emitter.EmitHost(map[string]any{
					"hostname": entry.Hostname,
					"sources":  entry.Sources,
					"ips":      entry.IPs,
				})
			}
		},
		StderrHandler: func(line string) {
			fmt.Fprintf(stderr, "[subfinder log] %s\n", line)
		},
	})

	if outOfScopeCount > 0 {
		_ = emitter.EmitWarning(map[string]any{
			"message": "hosts filtered out of scope",
			"count":   outOfScopeCount,
		})
	}

	if corruptLinesCount > 0 {
		_ = emitter.EmitWarning(map[string]any{
			"message": "corrupt output lines skipped",
			"count":   corruptLinesCount,
		})
	}

	var finalStatus string
	var exitCode int

	switch runRes.Status {
	case runner.StatusCancelled:
		finalStatus = "cancelled"
		exitCode = 130
	case runner.StatusPartial:
		finalStatus = "partial"
		exitCode = 4
	case runner.StatusFailed:
		finalStatus = "partial"
		exitCode = 4
	default:
		finalStatus = "complete"
		exitCode = 0
	}

	_ = emitter.EmitRunEnd(finalStatus, map[string]any{
		"total_hosts": registry.Count(),
	})

	return exitCode
}

func runProbe(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}

	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var scopePath, runID, httpxBin, target string
	fs.StringVar(&scopePath, "scope", "", "path to scope.yaml")
	fs.StringVar(&runID, "run-id", "", "unique run ULID")
	fs.StringVar(&target, "target", "", "target domain (optional)")
	fs.StringVar(&httpxBin, "httpx-bin", "", "custom httpx binary (testing)")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "probe: flag error: %v\n", err)
		return 2
	}

	if scopePath == "" || runID == "" {
		fmt.Fprintln(stderr, "probe: --scope and --run-id are both required")
		return 2
	}

	s, err := scope.Load(scopePath)
	if err != nil {
		fmt.Fprintf(stderr, "probe: failed to load scope: %v\n", err)
		return 2
	}

	// Resolve httpx binary
	binaryPath := httpxBin
	if binaryPath == "" {
		binaryPath = os.Getenv("DAYSRA_HTTPX_BIN")
	}
	if binaryPath == "" {
		var err error
		binaryPath, err = exec.LookPath("httpx")
		if err != nil {
			fmt.Fprintf(stderr, "probe: httpx not found in PATH: %v\n", err)
			return 3
		}
	}

	version, versionWarn, err := httpx.CheckVersion(ctx, binaryPath)
	if err != nil {
		fmt.Fprintf(stderr, "probe: failed to verify httpx: %v\n", err)
		return 3
	}

	// Read hostnames from stdin
	if stdin == nil {
		stdin = os.Stdin
	}

	var inScopeHosts []string
	var outOfScopeCount int
	var corruptLinesCount int

	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		normHost, err := normalize.Hostname(line)
		if err != nil {
			corruptLinesCount++
			continue
		}
		if !s.Allows(normHost) {
			outOfScopeCount++
			continue
		}
		inScopeHosts = append(inScopeHosts, normHost)
	}

	emitter := emit.New(runID, stdout)
	defer emitter.Close()

	toolVersions := map[string]string{"httpx": version}
	runStartData := map[string]any{
		"tool_versions": toolVersions,
	}
	if target != "" {
		runStartData["target"] = target
	}
	if err := emitter.EmitRunStart(runStartData); err != nil {
		fmt.Fprintf(stderr, "probe: emit run_start failed: %v\n", err)
	}

	if versionWarn != "" {
		_ = emitter.EmitWarning(map[string]any{
			"message": versionWarn,
		})
	}

	// If no in-scope hosts to probe, finish immediately
	if len(inScopeHosts) == 0 {
		if outOfScopeCount > 0 {
			_ = emitter.EmitWarning(map[string]any{
				"message": "hosts filtered out of scope",
				"count":   outOfScopeCount,
			})
		}
		if corruptLinesCount > 0 {
			_ = emitter.EmitWarning(map[string]any{
				"message": "corrupt output lines skipped",
				"count":   corruptLinesCount,
			})
		}
		_ = emitter.EmitRunEnd("complete", map[string]any{
			"total_http": 0,
		})
		return 0
	}

	httpxArgs := httpx.BuildArgs(s.MaxRate, s.Timeout)

	timeout := time.Duration(s.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	stdinPayload := strings.Join(inScopeHosts, "\n") + "\n"
	var totalHttpObs int

	runRes := runner.Run(ctx, binaryPath, httpxArgs, runner.Options{
		Timeout: timeout,
		Stdin:   strings.NewReader(stdinPayload),
		LineHandler: func(line string) {
			res, err := httpx.ParseLine(line)
			if err != nil {
				corruptLinesCount++
				return
			}

			normHost, err := normalize.Hostname(res.Hostname)
			if err != nil {
				corruptLinesCount++
				return
			}

			// Post-httpx scope check: verify hostname against scope
			if !s.Allows(normHost) {
				outOfScopeCount++
				return
			}

			totalHttpObs++
			_ = emitter.EmitHttp(map[string]any{
				"hostname":       normHost,
				"url":            res.URL,
				"status_code":    res.StatusCode,
				"title":          res.Title,
				"tech":           res.Tech,
				"content_length": res.ContentLength,
			})
		},
		StderrHandler: func(line string) {
			fmt.Fprintf(stderr, "[httpx log] %s\n", line)
		},
	})

	if outOfScopeCount > 0 {
		_ = emitter.EmitWarning(map[string]any{
			"message": "hosts filtered out of scope",
			"count":   outOfScopeCount,
		})
	}

	if corruptLinesCount > 0 {
		_ = emitter.EmitWarning(map[string]any{
			"message": "corrupt output lines skipped",
			"count":   corruptLinesCount,
		})
	}

	var finalStatus string
	var exitCode int

	switch runRes.Status {
	case runner.StatusCancelled:
		finalStatus = "cancelled"
		exitCode = 130
	case runner.StatusPartial:
		finalStatus = "partial"
		exitCode = 4
	case runner.StatusFailed:
		finalStatus = "partial"
		exitCode = 4
	default:
		finalStatus = "complete"
		exitCode = 0
	}

	_ = emitter.EmitRunEnd(finalStatus, map[string]any{
		"total_http": totalHttpObs,
	})

	return exitCode
}

// runScan runs nuclei against a list of live URLs read from stdin, emitting "finding" events.
// Rule 18 constraints are enforced via BuildArgs: -duc, -ni, no follow-redirect.
// Hostname from matched-at is re-verified against scope; out-of-scope findings are discarded.
func runScan(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var scopePath, runID, nucleiBin, includeTags string
	fs.StringVar(&scopePath, "scope", "", "path to scope.yaml")
	fs.StringVar(&runID, "run-id", "", "unique run ULID")
	fs.StringVar(&nucleiBin, "nuclei-bin", "", "custom nuclei binary (testing)")
	fs.StringVar(&includeTags, "include-tags", "", "comma-separated additional template tags")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "scan: flag error: %v\n", err)
		return 2
	}

	if scopePath == "" || runID == "" {
		fmt.Fprintln(stderr, "scan: --scope and --run-id are both required")
		return 2
	}

	s, err := scope.Load(scopePath)
	if err != nil {
		fmt.Fprintf(stderr, "scan: failed to load scope: %v\n", err)
		return 2
	}

	// Resolve nuclei binary
	binaryPath := nucleiBin
	if binaryPath == "" {
		binaryPath = os.Getenv("DAYSRA_NUCLEI_BIN")
	}
	if binaryPath == "" {
		var err error
		binaryPath, err = exec.LookPath("nuclei")
		if err != nil {
			fmt.Fprintf(stderr, "scan: nuclei not found in PATH: %v\n", err)
			return 3
		}
	}

	version, versionWarn, err := nuclei.CheckVersion(ctx, binaryPath)
	if err != nil {
		fmt.Fprintf(stderr, "scan: failed to verify nuclei: %v\n", err)
		return 3
	}

	// Read live URLs from stdin (one per line)
	if stdin == nil {
		stdin = os.Stdin
	}

	var inScopeURLs []string
	var outOfScopeCount int
	var corruptLinesCount int

	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Parse hostname from the URL for scope check
		u, parseErr := url.Parse(line)
		if parseErr != nil || u.Hostname() == "" {
			corruptLinesCount++
			continue
		}
		normHost, normErr := normalize.Hostname(u.Hostname())
		if normErr != nil {
			corruptLinesCount++
			continue
		}
		if !s.Allows(normHost) {
			outOfScopeCount++
			continue
		}
		inScopeURLs = append(inScopeURLs, line)
	}

	emitter := emit.New(runID, stdout)
	defer emitter.Close()

	toolVersions := map[string]string{"nuclei": version}
	if err := emitter.EmitRunStart(map[string]any{
		"tool_versions": toolVersions,
	}); err != nil {
		fmt.Fprintf(stderr, "scan: emit run_start failed: %v\n", err)
	}

	if versionWarn != "" {
		_ = emitter.EmitWarning(map[string]any{
			"message": versionWarn,
		})
	}

	if len(inScopeURLs) == 0 {
		if outOfScopeCount > 0 {
			_ = emitter.EmitWarning(map[string]any{
				"message": "urls filtered out of scope",
				"count":   outOfScopeCount,
			})
		}
		_ = emitter.EmitRunEnd("complete", map[string]any{
			"total_findings": 0,
		})
		return 0
	}

	// Resolve template tags: defaults to tech, exposure, misconfig.
	// Users can request additional tags with --include-tags.
	// Intrusive tags are strictly rejected, and default-login emits an explicit warning.
	var reqTags []string
	if includeTags != "" {
		for _, t := range strings.Split(includeTags, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				reqTags = append(reqTags, t)
			}
		}
	}

	activeTags, hasDefaultLogin, rejectedTags := nuclei.ResolveTags(reqTags)
	if hasDefaultLogin {
		fmt.Fprintln(stderr, "WARNING: tag 'default-login' attempts default credentials; requires explicit user awareness/confirmation")
		_ = emitter.EmitWarning(map[string]any{
			"message": "tag 'default-login' attempts default credentials; requires explicit user awareness/confirmation",
		})
	}
	for _, rej := range rejectedTags {
		fmt.Fprintf(stderr, "WARNING: tag %q is intrusive/forbidden and was ignored\n", rej)
		_ = emitter.EmitWarning(map[string]any{
			"message": fmt.Sprintf("tag %q is intrusive/forbidden and was ignored", rej),
		})
	}

	// Build nuclei args: use scope rate/timeout, safe active tags and severity.
	// -duc and -ni are always included (Rule 18).
	maxRate := s.MaxRate
	if maxRate <= 0 {
		maxRate = 10
	}
	scanTimeout := s.Timeout
	if scanTimeout <= 0 {
		scanTimeout = 10
	}

	nucleiArgs := nuclei.BuildArgs(
		maxRate,
		10, // concurrency capped at 10 for safety
		scanTimeout,
		activeTags,
		nuclei.ExcludedTags,
		[]string{"info", "low", "medium", "high", "critical"},
	)

	stdinPayload := strings.Join(inScopeURLs, "\n") + "\n"

	timeout := time.Duration(scanTimeout*len(inScopeURLs)+60) * time.Second
	if timeout < 2*time.Minute {
		timeout = 2 * time.Minute
	}

	var totalFindings int

	runRes := runner.Run(ctx, binaryPath, nucleiArgs, runner.Options{
		Timeout: timeout,
		Stdin:   strings.NewReader(stdinPayload),
		LineHandler: func(line string) {
			finding, err := nuclei.ParseLine(line)
			if err != nil {
				corruptLinesCount++
				return
			}
			finding.ToolVersion = version

			// Post-scan scope re-check on hostname from matched-at
			normHost, normErr := normalize.Hostname(finding.Hostname)
			if normErr != nil || !s.Allows(normHost) {
				outOfScopeCount++
				return
			}

			totalFindings++
			_ = emitter.EmitFinding(map[string]any{
				"id":           finding.ID,
				"template_id":  finding.TemplateID,
				"name":         finding.Name,
				"severity":     finding.Severity,
				"cve":          finding.CVEs,
				"matched_at":   nuclei.SanitizeMatchedAt(finding.MatchedAt),
				"evidence":     finding.Evidence,
				"tool":         finding.Tool,
				"tool_version": finding.ToolVersion,
				"hostname":     normHost,
			})
		},
		StderrHandler: func(line string) {
			fmt.Fprintf(stderr, "[nuclei log] %s\n", line)
		},
	})

	if outOfScopeCount > 0 {
		_ = emitter.EmitWarning(map[string]any{
			"message": "findings filtered out of scope",
			"count":   outOfScopeCount,
		})
	}
	if corruptLinesCount > 0 {
		_ = emitter.EmitWarning(map[string]any{
			"message": "corrupt output lines skipped",
			"count":   corruptLinesCount,
		})
	}

	var finalStatus string
	var exitCode int

	switch runRes.Status {
	case runner.StatusCancelled:
		finalStatus = "cancelled"
		exitCode = 130
	case runner.StatusPartial:
		finalStatus = "partial"
		exitCode = 4
	case runner.StatusFailed:
		finalStatus = "partial"
		exitCode = 4
	default:
		finalStatus = "complete"
		exitCode = 0
	}

	_ = emitter.EmitRunEnd(finalStatus, map[string]any{
		"total_findings": totalFindings,
	})

	return exitCode
}
