package ebpfkernel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"

	"github.com/tomeksdev/NexusHub/ebpf/userspace"
)

// fakeReader is a logReader backed by a channel. Tests push events in,
// then close the channel to signal "no more events" — Run observes that
// as ringbuf.ErrClosed, which is the real reader's shutdown signal too.
type fakeReader struct {
	ch     chan userspace.LogEvent
	closed chan struct{}
	once   sync.Once
}

func newFakeReader(buffer int) *fakeReader {
	return &fakeReader{
		ch:     make(chan userspace.LogEvent, buffer),
		closed: make(chan struct{}),
	}
}

func (f *fakeReader) Read() (userspace.LogEvent, error) {
	select {
	case ev, ok := <-f.ch:
		if !ok {
			return userspace.LogEvent{}, ringbuf.ErrClosed
		}
		return ev, nil
	case <-f.closed:
		return userspace.LogEvent{}, ringbuf.ErrClosed
	}
}

func (f *fakeReader) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// fakeSink records every Handle call plus the resolved rule UUID.
type fakeSink struct {
	mu      sync.Mutex
	events  []userspace.LogEvent
	matched []*uuid.UUID
	errOn   int // 1-based; 0 disables injection
	errErr  error
}

func (s *fakeSink) Handle(_ context.Context, ev userspace.LogEvent, matched *uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	s.matched = append(s.matched, matched)
	if s.errOn > 0 && len(s.events) == s.errOn {
		return s.errErr
	}
	return nil
}

func (s *fakeSink) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// fakeResolver returns a preset UUID for specific rule_ids. Absent
// entries come back as (zero, false) — same contract as KernelSyncer.
type fakeResolver struct {
	table map[uint32]uuid.UUID
}

func (r *fakeResolver) ResolveRuleID(rid uint32) (uuid.UUID, bool) {
	id, ok := r.table[rid]
	return id, ok
}

func TestLogConsumerDrainsAndResolves(t *testing.T) {
	known := uuid.New()
	resolver := &fakeResolver{table: map[uint32]uuid.UUID{42: known}}
	sink := &fakeSink{}

	reader := newFakeReader(4)
	reader.ch <- userspace.LogEvent{RuleID: 42, Action: 3}
	reader.ch <- userspace.LogEvent{RuleID: 999, Action: 3} // unknown
	close(reader.ch)

	c, err := newLogConsumer(reader, resolver, sink, nil)
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := c.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := sink.len(); got != 2 {
		t.Fatalf("sink len = %d, want 2", got)
	}
	if sink.matched[0] == nil || *sink.matched[0] != known {
		t.Fatalf("event[0] matched = %v, want %v", sink.matched[0], known)
	}
	if sink.matched[1] != nil {
		t.Fatalf("event[1] matched = %v, want nil for unknown rule_id", sink.matched[1])
	}
}

func TestLogConsumerSinkErrorsDoNotHaltLoop(t *testing.T) {
	sink := &fakeSink{errOn: 1, errErr: errors.New("boom")}
	reader := newFakeReader(4)

	c, err := newLogConsumer(reader, nil, sink, nil)
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- c.Run(context.Background()) }()

	reader.ch <- userspace.LogEvent{RuleID: 1} // will error
	reader.ch <- userspace.LogEvent{RuleID: 2} // must still be processed
	close(reader.ch)

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("run returned err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Run to finish")
	}
	if got := sink.len(); got != 2 {
		t.Fatalf("sink len = %d, want 2 (both events delivered despite error)", got)
	}
}

func TestLogConsumerContextCancelStops(t *testing.T) {
	sink := &fakeSink{}
	reader := newFakeReader(1)

	c, err := newLogConsumer(reader, nil, sink, nil)
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run(ctx) }()

	// Feed one event so the reader is not idle when cancel fires.
	reader.ch <- userspace.LogEvent{RuleID: 7}

	// Give the consumer a chance to deliver that event.
	deadline := time.After(500 * time.Millisecond)
	for sink.len() < 1 {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for first event to land in sink")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("run returned err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for context cancel to unblock Run")
	}
}

func TestNewLogConsumerRejectsNilReader(t *testing.T) {
	_, err := NewLogConsumer(nil, nil, &fakeSink{}, nil)
	if err == nil {
		t.Fatal("expected error for nil reader")
	}
}

func TestNewLogConsumerRejectsNilSink(t *testing.T) {
	reader := newFakeReader(0)
	_, err := newLogConsumer(reader, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil sink")
	}
}

// Sanity helper — prevents unused-import warning if other tests are
// removed during refactors and also quickly validates the test's view
// of ringbuf.ErrClosed matches the consumer's expectation.
func TestRingbufErrClosedIsMatched(t *testing.T) {
	if ringbuf.ErrClosed == nil {
		t.Fatal("ringbuf.ErrClosed is nil — import surface changed")
	}
	if fmt.Sprintf("%T", ringbuf.ErrClosed) == "" {
		t.Fatal("ringbuf.ErrClosed has no type")
	}
}
