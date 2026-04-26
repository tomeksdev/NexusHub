package openapi

import (
	"strings"
	"testing"
)

// TestSpecEmbedded verifies the build actually inlined the YAML. Without
// this, a refactor that accidentally drops openapi.yaml would compile
// cleanly (Spec would just be empty bytes) and only surface at runtime
// as a blank /openapi.yaml response.
func TestSpecEmbedded(t *testing.T) {
	if len(Spec) == 0 {
		t.Fatal("embedded spec is empty — openapi.yaml missing from embed")
	}
	s := string(Spec)
	for _, want := range []string{
		"openapi: 3.0.3", "NexusHub API",
		"/peers/{id}/rotate-psk",
		"/peers/events", "/users:", "/audit-log:",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("spec missing %q", want)
		}
	}
}
