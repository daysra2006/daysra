package emit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEmitAllTypesMatchSchema(t *testing.T) {
	var buf bytes.Buffer
	emitter := New("01JTEST0000000000000000000", &buf)

	if err := emitter.EmitRunStart(map[string]any{"target": "example.com"}); err != nil {
		t.Fatalf("EmitRunStart failed: %v", err)
	}
	if err := emitter.EmitHost(map[string]any{"hostname": "api.example.com", "sources": []string{"subfinder"}}); err != nil {
		t.Fatalf("EmitHost failed: %v", err)
	}
	if err := emitter.EmitHttp(map[string]any{"hostname": "api.example.com", "url": "https://api.example.com", "status_code": 200}); err != nil {
		t.Fatalf("EmitHttp failed: %v", err)
	}
	if err := emitter.EmitProgress(map[string]any{"stage": "subfinder", "message": "scanning"}); err != nil {
		t.Fatalf("EmitProgress failed: %v", err)
	}
	if err := emitter.EmitWarning(map[string]any{"message": "rate limit reached", "count": 1}); err != nil {
		t.Fatalf("EmitWarning failed: %v", err)
	}
	if err := emitter.EmitRunEnd("complete", map[string]any{"total_hosts": 1}); err != nil {
		t.Fatalf("EmitRunEnd failed: %v", err)
	}

	if err := emitter.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 JSONL lines, got %d", len(lines))
	}

	expectedTypes := []EventType{EventRunStart, EventHost, EventHttp, EventProgress, EventWarning, EventRunEnd}
	for i, line := range lines {
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatalf("line %d: invalid JSON: %v", i, err)
		}

		if raw["schema_version"] != "1" {
			t.Errorf("line %d: schema_version = %v, want '1'", i, raw["schema_version"])
		}
		if raw["type"] != string(expectedTypes[i]) {
			t.Errorf("line %d: type = %v, want %s", i, raw["type"], expectedTypes[i])
		}
		if raw["run_id"] != "01JTEST0000000000000000000" {
			t.Errorf("line %d: run_id = %v", i, raw["run_id"])
		}
		tsStr, ok := raw["ts"].(string)
		if !ok || tsStr == "" {
			t.Errorf("line %d: invalid ts: %v", i, raw["ts"])
		} else {
			if _, err := time.Parse(time.RFC3339, tsStr); err != nil {
				t.Errorf("line %d: ts %q not RFC3339: %v", i, tsStr, err)
			}
		}
		data, ok := raw["data"].(map[string]any)
		if !ok || data == nil {
			t.Errorf("line %d: data must be a JSON object, got %T: %v", i, raw["data"], raw["data"])
		}
	}
}

func TestEmitConcurrentSafety(t *testing.T) {
	var buf bytes.Buffer
	emitter := New("01JCONCURRENT0000000000000", &buf)

	const goroutines = 20
	const eventsPerGoroutine = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				_ = emitter.EmitHost(map[string]any{
					"hostname": fmt.Sprintf("host-%d-%d.example.com", gid, i),
				})
			}
		}(g)
	}

	wg.Wait()
	if err := emitter.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	expectedCount := goroutines * eventsPerGoroutine
	if len(lines) != expectedCount {
		t.Fatalf("expected %d events, got %d", expectedCount, len(lines))
	}

	for i, line := range lines {
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d: invalid JSON: %v", i, err)
		}
		if ev.Type != EventHost {
			t.Errorf("line %d: type = %s, want host", i, ev.Type)
		}
	}
}

func TestEmitRejectsInvalidEventType(t *testing.T) {
	var buf bytes.Buffer
	emitter := New("01JTEST0000000000000000000", &buf)
	defer emitter.Close()

	err := emitter.Emit(Event{Type: "invalid_type", Data: map[string]any{}})
	if err == nil {
		t.Error("Emit with invalid event type succeeded, want error")
	}
}

func TestEmitAfterCloseReturnsError(t *testing.T) {
	var buf bytes.Buffer
	emitter := New("01JTEST0000000000000000000", &buf)
	if err := emitter.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	err := emitter.EmitHost(map[string]any{"hostname": "example.com"})
	if err == nil {
		t.Error("Emit after Close succeeded, want error")
	}

	// Double Close should also be safe
	if err := emitter.Close(); err != nil {
		t.Errorf("Second Close returned error: %v", err)
	}
}
