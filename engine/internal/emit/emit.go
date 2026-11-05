package emit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// EventType defines valid event types in DAYSRA event v1 schema.
type EventType string

const (
	EventRunStart EventType = "run_start"
	EventHost     EventType = "host"
	EventHttp     EventType = "http"
	EventFinding  EventType = "finding"
	EventProgress EventType = "progress"
	EventWarning  EventType = "warning"
	EventRunEnd   EventType = "run_end"
)

// Event represents a single line in JSONL event stream matching schema/event.v1.json.
type Event struct {
	SchemaVersion string    `json:"schema_version"`
	Type          EventType `json:"type"`
	RunID         string    `json:"run_id"`
	Timestamp     string    `json:"ts"`
	Data          any       `json:"data"`
}

// Emitter writes JSONL events to a writer using a single dedicated writer goroutine.
type Emitter struct {
	runID   string
	writer  io.Writer
	events  chan Event
	errChan chan error
	done    chan struct{}
	mu      sync.RWMutex
	closed  bool
}

// New creates an Emitter that serializes JSONL events via a single writer goroutine.
func New(runID string, writer io.Writer) *Emitter {
	if writer == nil {
		writer = os.Stdout
	}
	e := &Emitter{
		runID:   runID,
		writer:  writer,
		events:  make(chan Event, 256),
		errChan: make(chan error, 1),
		done:    make(chan struct{}),
	}
	go e.writerLoop()
	return e
}

func (e *Emitter) isValidType(t EventType) bool {
	switch t {
	case EventRunStart, EventHost, EventHttp, EventFinding, EventProgress, EventWarning, EventRunEnd:
		return true
	default:
		return false
	}
}

func (e *Emitter) writerLoop() {
	var firstErr error
	encoder := json.NewEncoder(e.writer)
	for ev := range e.events {
		if firstErr != nil {
			continue
		}
		if ev.SchemaVersion == "" {
			ev.SchemaVersion = "1"
		}
		if ev.RunID == "" {
			ev.RunID = e.runID
		}
		if ev.Timestamp == "" {
			ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
		}
		if ev.Data == nil {
			ev.Data = map[string]any{}
		}
		if err := encoder.Encode(ev); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		e.errChan <- firstErr
	}
	close(e.done)
}

// Emit sends an event to the emitter channel in a concurrency-safe manner.
func (e *Emitter) Emit(ev Event) error {
	if !e.isValidType(ev.Type) {
		return fmt.Errorf("invalid event type %q", ev.Type)
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return errors.New("emitter is closed")
	}
	e.events <- ev
	return nil
}

// EmitRunStart emits a run_start event.
func (e *Emitter) EmitRunStart(data any) error {
	return e.Emit(Event{Type: EventRunStart, Data: data})
}

// EmitHost emits a host event.
func (e *Emitter) EmitHost(data any) error {
	return e.Emit(Event{Type: EventHost, Data: data})
}

// EmitHttp emits an http event.
func (e *Emitter) EmitHttp(data any) error {
	return e.Emit(Event{Type: EventHttp, Data: data})
}

// EmitFinding emits a finding event.
func (e *Emitter) EmitFinding(data any) error {
	return e.Emit(Event{Type: EventFinding, Data: data})
}

// EmitProgress emits a progress event.
func (e *Emitter) EmitProgress(data any) error {
	return e.Emit(Event{Type: EventProgress, Data: data})
}

// EmitWarning emits a warning event.
func (e *Emitter) EmitWarning(data any) error {
	return e.Emit(Event{Type: EventWarning, Data: data})
}

// EmitRunEnd emits a run_end event.
func (e *Emitter) EmitRunEnd(status string, extra map[string]any) error {
	data := map[string]any{"status": status}
	for k, v := range extra {
		data[k] = v
	}
	return e.Emit(Event{Type: EventRunEnd, Data: data})
}

// Close closes the event channel and waits for the writer goroutine to flush all events.
func (e *Emitter) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		<-e.done
		return nil
	}
	e.closed = true
	close(e.events)
	e.mu.Unlock()

	<-e.done
	select {
	case err := <-e.errChan:
		return err
	default:
		return nil
	}
}
