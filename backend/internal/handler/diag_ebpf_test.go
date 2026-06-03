package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tomeksdev/NexusHub/backend/internal/diag"
)

// fakeEBPFInventory satisfies EBPFInventory for tests, letting us
// pin LoaderStatus to a known value and inspect what /diag/ebpf
// returns. AttachedPrograms is empty + PinPath blank — the loader
// section is the one #86 cares about. (#86 T2)
type fakeEBPFInventory struct {
	status diag.EBPFLoaderStatus
}

func (f *fakeEBPFInventory) AttachedPrograms() []diag.EBPFAttachment { return nil }
func (f *fakeEBPFInventory) PinPath() string                         { return "" }
func (f *fakeEBPFInventory) LoaderStatus() diag.EBPFLoaderStatus     { return f.status }

func doDiagEBPF(t *testing.T, h *DiagHandler) ebpfStateResponse {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/diag/ebpf", h.EBPFState)
	req := httptest.NewRequest(http.MethodGet, "/diag/ebpf", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	var resp ebpfStateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

// When the loader healthily came up the operator sees loaded=true,
// capabilities_ok=true, no error, no missing features. This is the
// happy-path control for the degraded cases below.
func TestDiagEBPFLoaderHealthy(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	h := &DiagHandler{EBPF: &fakeEBPFInventory{
		status: diag.EBPFLoaderStatus{
			Loaded:          true,
			CapabilitiesOK:  true,
			MissingFeatures: []string{},
			LastAttemptAt:   now,
		},
	}}
	resp := doDiagEBPF(t, h)
	if !resp.Loader.Loaded {
		t.Errorf("expected loaded=true")
	}
	if !resp.Loader.CapabilitiesOK {
		t.Errorf("expected capabilities_ok=true")
	}
	if resp.Loader.Error != "" {
		t.Errorf("expected empty error, got %q", resp.Loader.Error)
	}
	if !resp.Loader.LastAttemptAt.Equal(now) {
		t.Errorf("expected last_attempt_at preserved")
	}
}

// The #86 case: loader init failed (verifier complaint). loaded=false
// + a non-empty error tells the Rules page banner what to show
// instead of letting every per-rule badge say "NOT LOADED" with no
// reason.
func TestDiagEBPFLoaderDegradedShowsError(t *testing.T) {
	h := &DiagHandler{EBPF: &fakeEBPFInventory{
		status: diag.EBPFLoaderStatus{
			Loaded:          false,
			CapabilitiesOK:  true,
			Error:           "loader init failed: program xdp_rules: R7 pointer -= pointer prohibited",
			MissingFeatures: []string{},
			LastAttemptAt:   time.Now().UTC(),
		},
	}}
	resp := doDiagEBPF(t, h)
	if resp.Loader.Loaded {
		t.Errorf("expected loaded=false")
	}
	if resp.Loader.Error == "" {
		t.Errorf("expected error message, got empty")
	}
}

// Docker / lacks-CAP_BPF case: permission_denied=true flips the
// banner copy so the operator fixes the container capabilities, not
// the kernel version. Routes through the existing PermissionDenied
// field that round-23 added to Capabilities.
func TestDiagEBPFLoaderPermissionDenied(t *testing.T) {
	h := &DiagHandler{EBPF: &fakeEBPFInventory{
		status: diag.EBPFLoaderStatus{
			Loaded:           false,
			CapabilitiesOK:   false,
			PermissionDenied: true,
			MissingFeatures:  []string{"BPF_MAP_TYPE_RINGBUF (kernel 5.8+)"},
		},
	}}
	resp := doDiagEBPF(t, h)
	if !resp.Loader.PermissionDenied {
		t.Errorf("expected permission_denied=true")
	}
	if len(resp.Loader.MissingFeatures) != 1 {
		t.Errorf("expected one missing feature, got %v", resp.Loader.MissingFeatures)
	}
}

// Endpoint must not 500 when the eBPF inventory isn't wired (dev /
// test deployments). Returns a zero-status payload that the
// frontend's "no loader info" branch can render.
func TestDiagEBPFNilInventory(t *testing.T) {
	h := &DiagHandler{}
	resp := doDiagEBPF(t, h)
	if resp.Loader.Loaded {
		t.Errorf("expected loaded=false with nil inventory")
	}
	if resp.Loader.MissingFeatures == nil {
		t.Errorf("expected non-nil MissingFeatures slice (so json encodes [] not null)")
	}
}
