package ebpf

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestNoopSyncer(t *testing.T) {
	var s Syncer = NoopSyncer{}
	if err := s.Apply(context.Background(), Rule{ID: uuid.New()}); err != nil {
		t.Errorf("Apply: %v", err)
	}
	if err := s.Delete(context.Background(), uuid.New()); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if err := s.Reconcile(context.Background(), nil); err != nil {
		t.Errorf("Reconcile: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestFakeSyncerRecordsCalls(t *testing.T) {
	f := &FakeSyncer{}
	r1 := Rule{ID: uuid.New(), Action: "deny"}
	r2 := Rule{ID: uuid.New(), Action: "allow"}
	ctx := context.Background()

	if err := f.Apply(ctx, r1); err != nil {
		t.Fatalf("Apply r1: %v", err)
	}
	if err := f.Apply(ctx, r2); err != nil {
		t.Fatalf("Apply r2: %v", err)
	}
	if err := f.Delete(ctx, r1.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	applied, deleted := f.Snapshot()
	if len(applied) != 2 {
		t.Fatalf("applied len: got %d, want 2", len(applied))
	}
	if applied[0].ID != r1.ID || applied[1].ID != r2.ID {
		t.Errorf("applied order wrong: got %v,%v", applied[0].ID, applied[1].ID)
	}
	if len(deleted) != 1 || deleted[0] != r1.ID {
		t.Errorf("deleted: got %v, want [%v]", deleted, r1.ID)
	}
}

func TestFakeSyncerReconcileDefensiveCopy(t *testing.T) {
	f := &FakeSyncer{}
	input := []Rule{{ID: uuid.New(), Action: "deny"}}
	if err := f.Reconcile(context.Background(), input); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// Mutate caller slice — the recorded copy must not change.
	input[0].Action = "allow"
	if f.Reconciled[0][0].Action != "deny" {
		t.Error("Reconcile did not defensively copy input")
	}
}

func TestFakeSyncerInjectedErrors(t *testing.T) {
	wantErr := errors.New("boom")
	f := &FakeSyncer{ApplyErr: wantErr, DeleteErr: wantErr, ReconcileErr: wantErr}
	ctx := context.Background()

	if err := f.Apply(ctx, Rule{}); !errors.Is(err, wantErr) {
		t.Errorf("Apply: got %v, want %v", err, wantErr)
	}
	if err := f.Delete(ctx, uuid.New()); !errors.Is(err, wantErr) {
		t.Errorf("Delete: got %v, want %v", err, wantErr)
	}
	if err := f.Reconcile(ctx, nil); !errors.Is(err, wantErr) {
		t.Errorf("Reconcile: got %v, want %v", err, wantErr)
	}
	// Errors must not record the call.
	applied, deleted := f.Snapshot()
	if len(applied) != 0 || len(deleted) != 0 {
		t.Errorf("calls recorded despite error: applied=%d deleted=%d", len(applied), len(deleted))
	}
}

func TestFakeSyncerReset(t *testing.T) {
	f := &FakeSyncer{}
	_ = f.Apply(context.Background(), Rule{ID: uuid.New()})
	_ = f.Delete(context.Background(), uuid.New())
	f.Reset()
	applied, deleted := f.Snapshot()
	if len(applied) != 0 || len(deleted) != 0 || len(f.Reconciled) != 0 {
		t.Error("Reset did not clear recorded calls")
	}
}
