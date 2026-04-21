package ebpfkernel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"

	"github.com/tomeksdev/NexusHub/ebpf/userspace"
)

// ruleResolver lifts the KernelSyncer's ResolveRuleID so the consumer
// can be tested with a stub.
type ruleResolver interface {
	ResolveRuleID(rid uint32) (uuid.UUID, bool)
}

// logReader is the narrow view of userspace.LogReader the consumer
// uses — defined here so tests can substitute a fake without taking
// a dependency on the ringbuf map.
type logReader interface {
	Read() (userspace.LogEvent, error)
	Close() error
}

// LogSink is the write-side dependency of the consumer. It receives
// fully-assembled LogEvents plus the resolved rule UUID; implementers
// typically wrap a ConnectionLogRepo.Insert call.
//
// Keeping this narrow (one method, plain types) lets the consumer
// avoid importing repository here while still being trivially testable.
type LogSink interface {
	Handle(ctx context.Context, ev userspace.LogEvent, matchedRuleID *uuid.UUID) error
}

// LogConsumer drains the ringbuf produced by ACTION_LOG hits on the
// datapath and pushes each event through a sink. One consumer owns
// one reader; spawning multiple consumers on the same loader would
// race on the Reader cursor.
//
// Run blocks until the context is cancelled or the reader is closed.
// Its error return is nil on clean shutdown (ringbuf.ErrClosed or
// ctx.Err). Sink errors are logged and counted but not returned —
// one bad insert can't halt the consumer, or the datapath would back
// up against a full ringbuf in seconds under load.
type LogConsumer struct {
	reader   logReader
	resolver ruleResolver
	sink     LogSink
	logger   *slog.Logger
}

// NewLogConsumer wires a consumer around an already-open reader. The
// reader's lifetime belongs to the consumer once handed over — Run
// will Close it on exit.
func NewLogConsumer(reader *userspace.LogReader, resolver ruleResolver, sink LogSink, logger *slog.Logger) (*LogConsumer, error) {
	if reader == nil {
		return nil, errors.New("nil reader")
	}
	return newLogConsumer(reader, resolver, sink, logger)
}

// newLogConsumer is the test-friendly construction path: it accepts any
// logReader implementation so unit tests can drive Run with a channel
// instead of a kernel ringbuf.
func newLogConsumer(reader logReader, resolver ruleResolver, sink LogSink, logger *slog.Logger) (*LogConsumer, error) {
	if sink == nil {
		return nil, errors.New("nil sink")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &LogConsumer{
		reader:   reader,
		resolver: resolver,
		sink:     sink,
		logger:   logger,
	}, nil
}

// Run pumps the ringbuf. Context cancellation asks the goroutine to
// exit; it does so by closing the reader which unblocks the pending
// Read() call with ringbuf.ErrClosed. Run waits for the close-driven
// exit before returning so callers can synchronise on its return.
func (c *LogConsumer) Run(ctx context.Context) error {
	// Closer goroutine: translate ctx.Done into a reader close. We
	// don't select directly on Read because it blocks on the kernel
	// fd; closing is the only clean way to unblock it.
	closed := make(chan struct{})
	go func() {
		<-ctx.Done()
		_ = c.reader.Close()
		close(closed)
	}()

	defer func() {
		// If Run exits on a read error rather than cancellation, make
		// sure the reader is closed and the goroutine is released.
		_ = c.reader.Close()
		// Drain the closer goroutine. ctx.Done fires on shutdown so
		// this select always terminates — the default handles the
		// case where the reader closed first and the closer is still
		// waiting on ctx.
		select {
		case <-closed:
		default:
		}
	}()

	for {
		ev, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ringbuf read: %w", err)
		}

		var matched *uuid.UUID
		if c.resolver != nil {
			if id, ok := c.resolver.ResolveRuleID(ev.RuleID); ok {
				matched = &id
			}
		}
		if err := c.sink.Handle(ctx, ev, matched); err != nil {
			// Don't bail the loop — one bad sink call mustn't backlog
			// the ringbuf. Log and drop.
			c.logger.WarnContext(ctx, "log sink handle",
				"rule_id_kernel", ev.RuleID,
				"err", err)
		}
	}
}
