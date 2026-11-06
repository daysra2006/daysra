package nuclei_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"daysra-engine/internal/adapters/nuclei"
)

// fixtureFile is the raw nuclei v3.11.1 output fixture (with literal IPs).
const fixtureFile = "../../../../tests/fixtures/tools/nuclei/v3.11.1/output.jsonl"

// TestParseLine_FromFixture parses every line of the real raw fixture without scope check.
// Verifies that required fields are extracted and request/response are not leaked.
func TestParseLine_FromFixture(t *testing.T) {
	data, err := os.ReadFile(fixtureFile)
	if err != nil {
		t.Fatalf("cannot read fixture %s: %v", fixtureFile, err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("fixture is empty")
	}

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f, err := nuclei.ParseLine(line)
		if err != nil {
			t.Errorf("line %d: ParseLine error: %v", i+1, err)
			continue
		}
		if f.TemplateID == "" {
			t.Errorf("line %d: empty template_id", i+1)
		}
		if f.Name == "" {
			t.Errorf("line %d: empty name", i+1)
		}
		if f.Severity == "" {
			t.Errorf("line %d: empty severity", i+1)
		}
		if f.MatchedAt == "" {
			t.Errorf("line %d: empty matched_at", i+1)
		}
		if f.ID == "" {
			t.Errorf("line %d: empty id", i+1)
		}
		if f.Tool != "nuclei" {
			t.Errorf("line %d: tool = %q, want %q", i+1, f.Tool, "nuclei")
		}
		if f.Hostname == "" {
			t.Errorf("line %d: empty hostname", i+1)
		}
		if len(f.Evidence) > 2048 {
			t.Errorf("line %d: evidence too large: %d bytes", i+1, len(f.Evidence))
		}
		if f.CVEs == nil {
			t.Errorf("line %d: cve slice is nil (want empty slice, not nil)", i+1)
		}
	}
}

// TestParseLine_NoClassification verifies that a line with missing or null classification parses without panic.
func TestParseLine_NoClassification(t *testing.T) {
	line := `{"template-id":"no-class","info":{"name":"No Class Test","severity":"info","classification":null},"matched-at":"http://app.example.com/test","matcher-name":"test-matcher"}`
	f, err := nuclei.ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.CVEs == nil || len(f.CVEs) != 0 {
		t.Errorf("cve = %v, want []", f.CVEs)
	}
	if f.Evidence != "test-matcher" {
		t.Errorf("evidence = %q, want %q", f.Evidence, "test-matcher")
	}

	// Line completely omitting the classification key
	lineNoKey := `{"template-id":"no-class-key","info":{"name":"No Key","severity":"low"},"matched-at":"http://app.example.com/test"}`
	f2, err := nuclei.ParseLine(lineNoKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f2.CVEs == nil || len(f2.CVEs) != 0 {
		t.Errorf("cve = %v, want []", f2.CVEs)
	}
}

// TestParseLine_MultipleCVEs verifies that multiple CVEs in classification are parsed correctly.
func TestParseLine_MultipleCVEs(t *testing.T) {
	// Array of CVEs
	lineArr := `{"template-id":"multi-cve","info":{"name":"Multi CVE","severity":"high","classification":{"cve-id":["cve-2021-44228","CVE-2021-45046"]}},"matched-at":"http://app.example.com/path"}`
	f, err := nuclei.ParseLine(lineArr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.CVEs) != 2 {
		t.Fatalf("got %d cves, want 2: %v", len(f.CVEs), f.CVEs)
	}
	if f.CVEs[0] != "CVE-2021-44228" || f.CVEs[1] != "CVE-2021-45046" {
		t.Errorf("unexpected cve content: %v", f.CVEs)
	}

	// Comma-separated string of CVEs
	lineComma := `{"template-id":"comma-cve","info":{"name":"Comma CVE","severity":"medium","classification":{"cve-id":"cve-2020-1000, cve-2020-2000"}},"matched-at":"http://app.example.com/path"}`
	f2, err := nuclei.ParseLine(lineComma)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f2.CVEs) != 2 {
		t.Fatalf("got %d cves, want 2: %v", len(f2.CVEs), f2.CVEs)
	}
	if f2.CVEs[0] != "CVE-2020-1000" || f2.CVEs[1] != "CVE-2020-2000" {
		t.Errorf("unexpected cve content: %v", f2.CVEs)
	}
}

// TestParseLine_RedactSensitiveData ensures sensitive values like "Authorization: Bearer abc123"
// do NOT appear in the output, whether in response (which is never read) or extracted-results/matcher-name.
func TestParseLine_RedactSensitiveData(t *testing.T) {
	lineWithSensitive := `{
		"template-id": "leak-test",
		"info": {"name": "Leak Test", "severity": "critical"},
		"matched-at": "http://app.example.com/secret",
		"request": "GET /secret HTTP/1.1\r\nAuthorization: Bearer supersecret123\r\n\r\n",
		"response": "HTTP/1.1 200 OK\r\nAuthorization: Bearer abc123\r\nSet-Cookie: session=xyz789; Path=/\r\n\r\n",
		"curl-command": "curl -H 'Authorization: Bearer abc123' http://app.example.com",
		"template-path": "/secret/path/to/template.yaml",
		"extracted-results": ["Authorization: Bearer abc123", "password: secretpassword123", "api-key: secretkey999"]
	}`

	f, err := nuclei.ParseLine(lineWithSensitive)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Marshal finding to JSON to verify nothing sensitive leaks to serialized output
	rawJSON, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	output := string(rawJSON)

	forbiddenStrings := []string{
		"supersecret123",
		"abc123",
		"xyz789",
		"secretpassword123",
		"secretkey999",
		"template-path",
		"curl-command",
	}

	for _, forbidden := range forbiddenStrings {
		if strings.Contains(output, forbidden) {
			t.Errorf("sensitive value %q leaked in finding output: %s", forbidden, output)
		}
	}
}

// TestParseLine_CorruptJSON verifies that invalid JSON returns an error without panicking.
func TestParseLine_CorruptJSON(t *testing.T) {
	corruptInputs := []string{
		"",
		"   ",
		"{not-valid-json",
		`{"template-id":`,
		`{"template-id": ""}`,
		`{"info":{"name":"x"}}`,
	}

	for _, input := range corruptInputs {
		f, err := nuclei.ParseLine(input)
		if err == nil {
			t.Errorf("expected error for input %q, got finding: %+v", input, f)
		}
	}
}

// TestBuildArgs ensures no follow-redirect, -duc, and -ni are always present.
func TestBuildArgs(t *testing.T) {
	args := nuclei.BuildArgs(10, 10,
		[]string{"tech", "exposure"},
		[]string{"intrusive", "fuzz"},
		[]string{"info", "medium", "high", "critical"},
	)

	argStr := strings.Join(args, " ")

	// Rule 18: -duc and -ni must always be present.
	for _, required := range []string{"-duc", "-ni", "-j", "-silent", "-nc"} {
		if !strings.Contains(argStr, required) {
			t.Errorf("BuildArgs missing required flag %q in: %v", required, args)
		}
	}

	// Per-request timeout comes from the adapter constant, never from scope.
	if got := buildArgsFlagValue(args, "-timeout"); got != "10" {
		t.Errorf("-timeout = %q, want %q", got, "10")
	}
	if nuclei.RequestTimeout != 10 {
		t.Errorf("RequestTimeout = %d, want 10 (nuclei v3.11.1 default)", nuclei.RequestTimeout)
	}

	// Follow-redirect must NOT be present.
	for _, forbidden := range []string{"-fr", "-follow-redirects", "-follow-host-redirects"} {
		if strings.Contains(argStr, forbidden) {
			t.Errorf("BuildArgs contains forbidden follow-redirect flag %q in: %v", forbidden, args)
		}
	}

	// Tags and etags must be present.
	if !strings.Contains(argStr, "-tags") {
		t.Errorf("BuildArgs missing -tags flag")
	}
	if !strings.Contains(argStr, "-etags") {
		t.Errorf("BuildArgs missing -etags flag")
	}

	// Rule 18: Custom template paths (-t, -w) must NEVER be present.
	for _, forbidden := range []string{"-t ", "-t=", "-target-templates", "-w ", "-workflows"} {
		if strings.Contains(argStr, forbidden) {
			t.Errorf("BuildArgs contains forbidden custom template flag %q in: %v", forbidden, args)
		}
	}
}

func buildArgsFlagValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

// TestDefaultTags_NoDefaultLogin verifies that DefaultTags strictly contains only safe tags
// and excludes default-login.
func TestDefaultTags_NoDefaultLogin(t *testing.T) {
	expected := []string{"tech", "exposure", "misconfig"}
	if len(nuclei.DefaultTags) != len(expected) {
		t.Fatalf("DefaultTags length = %d, want %d: %v", len(nuclei.DefaultTags), len(expected), nuclei.DefaultTags)
	}
	for i, tag := range expected {
		if nuclei.DefaultTags[i] != tag {
			t.Errorf("DefaultTags[%d] = %q, want %q", i, nuclei.DefaultTags[i], tag)
		}
	}
	for _, tag := range nuclei.DefaultTags {
		if tag == "default-login" {
			t.Errorf("DefaultTags must NOT contain 'default-login'")
		}
	}
}

// TestResolveTags verifies resolution of default tags, rejection of forbidden tags,
// and flagging of default-login.
func TestResolveTags(t *testing.T) {
	// Case 1: Default with no include tags
	tags, hasDefaultLogin, rejected := nuclei.ResolveTags(nil)
	if hasDefaultLogin {
		t.Errorf("hasDefaultLogin should be false for default tags")
	}
	if len(rejected) != 0 {
		t.Errorf("rejected should be empty, got %v", rejected)
	}
	if strings.Join(tags, ",") != "tech,exposure,misconfig" {
		t.Errorf("got tags %v, want [tech exposure misconfig]", tags)
	}

	// Case 2: Include safe tags
	tags2, hasLogin2, rejected2 := nuclei.ResolveTags([]string{"cve", "network"})
	if hasLogin2 {
		t.Errorf("hasLogin2 should be false")
	}
	if len(rejected2) != 0 {
		t.Errorf("rejected2 should be empty, got %v", rejected2)
	}
	if strings.Join(tags2, ",") != "tech,exposure,misconfig,cve,network" {
		t.Errorf("got tags %v", tags2)
	}

	// Case 3: Forbidden tags rejected
	tags3, _, rejected3 := nuclei.ResolveTags([]string{"intrusive", "fuzz", "dos", "fuzzing", "custom"})
	if len(rejected3) != 4 {
		t.Errorf("expected 4 rejected tags, got %d: %v", len(rejected3), rejected3)
	}
	for _, forbidden := range []string{"intrusive", "fuzz", "dos", "fuzzing"} {
		for _, tag := range tags3 {
			if tag == forbidden {
				t.Errorf("forbidden tag %q was not rejected and is in final tags: %v", forbidden, tags3)
			}
		}
	}

	// Case 4: default-login flags warning
	tags4, hasLogin4, rejected4 := nuclei.ResolveTags([]string{"default-login"})
	if !hasLogin4 {
		t.Errorf("expected hasLogin4 to be true when default-login is requested")
	}
	if len(rejected4) != 0 {
		t.Errorf("default-login should not be rejected, got rejected: %v", rejected4)
	}
	var foundLogin bool
	for _, t := range tags4 {
		if t == "default-login" {
			foundLogin = true
		}
	}
	if !foundLogin {
		t.Errorf("default-login was requested but not found in final tags: %v", tags4)
	}
}

// TestFindingID_Stable verifies that FindingID produces the same hash for the same inputs.
func TestFindingID_Stable(t *testing.T) {
	id1 := nuclei.FindingID("app.example.com", "swagger-api", "", "/api-docs/swagger.json")
	id2 := nuclei.FindingID("app.example.com", "swagger-api", "", "/api-docs/swagger.json")
	if id1 != id2 {
		t.Errorf("FindingID not stable: %q != %q", id1, id2)
	}
	if len(id1) != 64 {
		t.Errorf("FindingID length = %d, want 64 (sha256 hex)", len(id1))
	}

	id3 := nuclei.FindingID("other.com", "swagger-api", "", "/api-docs/swagger.json")
	if id1 == id3 {
		t.Errorf("FindingID collision for different hostname: %q == %q", id1, id3)
	}
}

// TestParseVersion verifies version extraction from nuclei -version output.
func TestParseVersion(t *testing.T) {
	output := `WARNING: sonic/ast only supports...
[INF] Nuclei Engine Version: v3.11.1
[INF] Nuclei Config Directory: /home/user/.config/nuclei`

	got := nuclei.ParseVersion(output)
	if got != "v3.11.1" {
		t.Errorf("ParseVersion = %q, want %q", got, "v3.11.1")
	}
}

// TestFixtureSerializedEventsLeakAndStats verifies no leaks of request/response/paths and verifies stats
func TestFixtureSerializedEventsLeakAndStats(t *testing.T) {
	data, err := os.ReadFile(fixtureFile)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var findings []*nuclei.Finding
	severityCounts := make(map[string]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f, err := nuclei.ParseLine(line)
		if err != nil {
			t.Fatalf("parse line: %v", err)
		}
		f.ToolVersion = "v3.11.1"
		findings = append(findings, f)
		severityCounts[f.Severity]++

		ev := map[string]any{
			"schema_version": "1",
			"type":           "finding",
			"run_id":         "01JTESTSERIALIZE0000000000",
			"ts":             "2026-11-05T08:24:50Z",
			"data": map[string]any{
				"id":           f.ID,
				"template_id":  f.TemplateID,
				"name":         f.Name,
				"severity":     f.Severity,
				"cve":          f.CVEs,
				"matched_at":   f.MatchedAt,
				"evidence":     f.Evidence,
				"tool":         f.Tool,
				"tool_version": f.ToolVersion,
				"hostname":     f.Hostname,
			},
		}

		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		serialized := string(raw)

		forbiddenSubstrings := []string{"/home/", "request", "response", "curl", "Authorization", "Cookie"}
		for _, forbidden := range forbiddenSubstrings {
			if strings.Contains(serialized, forbidden) {
				t.Errorf("finding %q contains forbidden substring %q in serialized event: %s", f.ID, forbidden, serialized)
			}
		}
	}

	if len(findings) != 13 {
		t.Fatalf("expected 13 findings, got %d", len(findings))
	}
	if severityCounts["info"] != 12 {
		t.Errorf("expected 12 info findings, got %d", severityCounts["info"])
	}
	if severityCounts["medium"] != 1 {
		t.Errorf("expected 1 medium finding, got %d", severityCounts["medium"])
	}
}

func TestSanitizeMatchedAt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean url untouched",
			input:    "https://example.com/api/v1/users",
			expected: "https://example.com/api/v1/users",
		},
		{
			name:     "strip userinfo",
			input:    "http://admin:supersecret@example.com/admin",
			expected: "http://example.com/admin",
		},
		{
			name:     "strip fragment",
			input:    "https://example.com/page#section-two",
			expected: "https://example.com/page",
		},
		{
			name:     "redact sensitive query parameters lowercase",
			input:    "https://example.com/test?token=abc123xyz&normal=hello&api_key=98765",
			expected: "https://example.com/test?api_key=REDACTED&normal=hello&token=REDACTED",
		},
		{
			name:     "redact uppercase and mixed-case sensitive query params",
			input:    "https://example.com/oauth?ACCESS_TOKEN=secret&Session_ID=sess456&JWT=myjwt&SIG=mysig",
			expected: "https://example.com/oauth?ACCESS_TOKEN=REDACTED&JWT=REDACTED&SIG=REDACTED&Session_ID=REDACTED",
		},
		{
			name:     "all combined: userinfo, fragment, multiple params with uppercase and sensitive keywords",
			input:    "http://user:pass123@api.example.com:8443/v1/auth?API_SECRET=s3cr3t&PASSWORD=pwd&PASSWD=p1&auth_code=c0de&sid=s99&signature=sig99&page=2#token-fragment",
			expected: "http://api.example.com:8443/v1/auth?API_SECRET=REDACTED&PASSWD=REDACTED&PASSWORD=REDACTED&auth_code=REDACTED&page=2&sid=REDACTED&signature=REDACTED",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nuclei.SanitizeMatchedAt(tc.input)
			if got != tc.expected {
				t.Errorf("SanitizeMatchedAt(%q)\n  got:  %q\n  want: %q", tc.input, got, tc.expected)
			}
		})
	}
}
