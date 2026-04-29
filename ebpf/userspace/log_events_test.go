package userspace

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestLogEventMarshalRoundTrip(t *testing.T) {
	in := LogEvent{
		TsNs:      0x1122334455667788,
		RuleID:    0x01020304,
		SrcPort:   0x0506,
		DstPort:   0x0708,
		Bytes:     0x090A0B0C,
		Action:    3, // LOG
		Protocol:  6, // TCP
		Family:    AFInet,
		Direction: 0,
		SrcAddr:   [16]byte{10, 0, 0, 1},
		DstAddr:   [16]byte{192, 168, 1, 1},
	}
	b, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) != logEventSize {
		t.Fatalf("length = %d, want %d", len(b), logEventSize)
	}

	var out LogEvent
	if err := out.UnmarshalBinary(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch:\n got  %+v\n want %+v", out, in)
	}
}

func TestLogEventUnmarshalWrongSize(t *testing.T) {
	var ev LogEvent
	if err := ev.UnmarshalBinary(make([]byte, logEventSize-1)); err == nil {
		t.Fatal("expected error on short buffer")
	}
	if err := ev.UnmarshalBinary(make([]byte, logEventSize+1)); err == nil {
		t.Fatal("expected error on long buffer")
	}
}

func TestLogEventSrcDstIP_V4(t *testing.T) {
	ev := LogEvent{
		Family:  AFInet,
		SrcAddr: [16]byte{10, 0, 0, 1},
		DstAddr: [16]byte{8, 8, 8, 8},
	}
	if got, want := ev.SrcIP(), netip.MustParseAddr("10.0.0.1"); got != want {
		t.Fatalf("SrcIP = %v, want %v", got, want)
	}
	if got, want := ev.DstIP(), netip.MustParseAddr("8.8.8.8"); got != want {
		t.Fatalf("DstIP = %v, want %v", got, want)
	}
}

func TestLogEventSrcDstIP_V6(t *testing.T) {
	a := netip.MustParseAddr("2001:db8::1")
	ev := LogEvent{
		Family:  AFInet6,
		SrcAddr: a.As16(),
		DstAddr: a.As16(),
	}
	if got := ev.SrcIP(); got != a {
		t.Fatalf("SrcIP = %v, want %v", got, a)
	}
	if got := ev.DstIP(); got != a {
		t.Fatalf("DstIP = %v, want %v", got, a)
	}
}

func TestLogEventSrcIP_UnknownFamily(t *testing.T) {
	ev := LogEvent{Family: 99}
	if ev.SrcIP().IsValid() {
		t.Fatal("expected invalid Addr for unknown family")
	}
}

func TestProtocolString(t *testing.T) {
	cases := map[uint8]string{
		6:   "TCP",
		17:  "UDP",
		1:   "ICMP",
		58:  "ICMP",
		132: "", // SCTP — not modeled
		0:   "",
	}
	for in, want := range cases {
		ev := LogEvent{Protocol: in}
		if got := ev.ProtocolString(); got != want {
			t.Errorf("ProtocolString(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestActionString(t *testing.T) {
	cases := map[uint8]string{
		0: "ALLOW",
		1: "DENY",
		2: "RATE_LIMIT",
		3: "LOG",
		7: "",
	}
	for in, want := range cases {
		ev := LogEvent{Action: in}
		if got := ev.ActionString(); got != want {
			t.Errorf("ActionString(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestLogEventFieldOffsets guards the exact on-wire layout. If someone
// rearranges the struct in C without bumping logEventSize or updating
// MarshalBinary, this test catches the drift.
func TestLogEventFieldOffsets(t *testing.T) {
	ev := LogEvent{
		TsNs:      0x0102030405060708,
		RuleID:    0x090A0B0C,
		SrcPort:   0x0D0E,
		DstPort:   0x0F10,
		Bytes:     0x11121314,
		Action:    0x15,
		Protocol:  0x16,
		Family:    0x17,
		Direction: 0x18,
	}
	// Fill addr slots with ascending bytes for visibility.
	for i := range ev.SrcAddr {
		ev.SrcAddr[i] = byte(0x20 + i)
	}
	for i := range ev.DstAddr {
		ev.DstAddr[i] = byte(0x40 + i)
	}
	b, err := ev.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{
		// ts_ns (LE u64)
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		// rule_id (LE u32)
		0x0C, 0x0B, 0x0A, 0x09,
		// src_port, dst_port (LE u16)
		0x0E, 0x0D,
		0x10, 0x0F,
		// bytes (LE u32)
		0x14, 0x13, 0x12, 0x11,
		// action, protocol, family, direction
		0x15, 0x16, 0x17, 0x18,
		// src_addr
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		// dst_addr
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("byte layout drift:\n got  %x\n want %x", b, want)
	}
}
