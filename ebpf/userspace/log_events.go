package userspace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf/ringbuf"
)

// LogEvent mirrors struct log_event in ebpf/headers/nexushub.h. It's
// the unit of telemetry the datapath emits for ACTION_LOG rule hits.
//
// Field semantics:
//   - TsNs is bpf_ktime_get_ns() at emit time — monotonic nanoseconds
//     since boot, not wall clock. Callers that insert to Postgres
//     should rebase with (wall_now - mono_now) + TsNs.
//   - RuleID is the kernel-side rule_id (KernelSyncer assigns these).
//   - SrcPort/DstPort are host byte order; the emitter already called
//     ntohs. Zero when the packet wasn't TCP/UDP or had no usable L4.
//   - Bytes is XDP frame length or skb->len, depending on hook.
//   - Action will be ACTION_LOG (3) today; leaving it on the wire
//     keeps the struct useful if we ever tee drop/ratelimit events.
//   - Protocol is the IPPROTO_* value straight off the packet, not
//     the NexusHub PROTO_* enum. IPv4 logs report IPPROTO_ICMP (1);
//     IPv6 logs report IPPROTO_ICMPV6 (58).
//   - Family is AF_INET (2) or AF_INET6 (10).
//   - Direction is 0=ingress, 1=egress (currently always 0 — wg0 and
//     eth0 both attach to ingress hooks).
//   - SrcAddr/DstAddr are raw on-wire bytes: IPv4 occupies the first
//     4 bytes and the rest are zero; IPv6 fills all 16.
type LogEvent struct {
	TsNs      uint64
	RuleID    uint32
	SrcPort   uint16
	DstPort   uint16
	Bytes     uint32
	Action    uint8
	Protocol  uint8
	Family    uint8
	Direction uint8
	SrcAddr   [16]byte
	DstAddr   [16]byte
}

// logEventSize is the on-wire length of struct log_event.
//
//	u64 ts_ns                         = 8
//	u32 rule_id                       = 4
//	u16 src_port + u16 dst_port       = 4
//	u32 bytes                         = 4
//	u8 action/protocol/family/dir     = 4
//	u8[16] src_addr + u8[16] dst_addr = 32
//	                                 total = 56
//
// Struct is naturally aligned (u64 at offset 0, every u32 at a
// 4-byte boundary) — no compiler-inserted padding on either target.
const logEventSize = 56

// Address families as emitted by the kernel side. Mirrors <sys/socket.h>.
const (
	AFInet  uint8 = 2
	AFInet6 uint8 = 10
)

// UnmarshalBinary parses a raw ringbuf sample. The kernel writes
// little-endian on both supported targets (amd64, arm64) — if we
// ever add a big-endian target this needs per-arch handling, same
// as the RuleMeta path.
func (e *LogEvent) UnmarshalBinary(b []byte) error {
	if len(b) != logEventSize {
		return fmt.Errorf("log_event: expected %d bytes, got %d", logEventSize, len(b))
	}
	e.TsNs = binary.LittleEndian.Uint64(b[0:8])
	e.RuleID = binary.LittleEndian.Uint32(b[8:12])
	e.SrcPort = binary.LittleEndian.Uint16(b[12:14])
	e.DstPort = binary.LittleEndian.Uint16(b[14:16])
	e.Bytes = binary.LittleEndian.Uint32(b[16:20])
	e.Action = b[20]
	e.Protocol = b[21]
	e.Family = b[22]
	e.Direction = b[23]
	copy(e.SrcAddr[:], b[24:40])
	copy(e.DstAddr[:], b[40:56])
	return nil
}

// MarshalBinary is the inverse — used by tests that seed the ringbuf
// via a userspace writer, and potentially by future offline replay
// tools. Production code only ever reads.
func (e LogEvent) MarshalBinary() ([]byte, error) {
	b := make([]byte, logEventSize)
	binary.LittleEndian.PutUint64(b[0:8], e.TsNs)
	binary.LittleEndian.PutUint32(b[8:12], e.RuleID)
	binary.LittleEndian.PutUint16(b[12:14], e.SrcPort)
	binary.LittleEndian.PutUint16(b[14:16], e.DstPort)
	binary.LittleEndian.PutUint32(b[16:20], e.Bytes)
	b[20] = e.Action
	b[21] = e.Protocol
	b[22] = e.Family
	b[23] = e.Direction
	copy(b[24:40], e.SrcAddr[:])
	copy(b[40:56], e.DstAddr[:])
	return b, nil
}

// SrcIP returns the source address as a netip.Addr. For AFInet it
// reads only the first 4 bytes; for AFInet6 it reads all 16. Returns
// the zero Addr when the family byte is unrecognized — callers should
// check with Addr.IsValid() before using.
func (e LogEvent) SrcIP() netip.Addr {
	return addrFromBytes(e.Family, e.SrcAddr)
}

// DstIP is the destination-side counterpart to SrcIP.
func (e LogEvent) DstIP() netip.Addr {
	return addrFromBytes(e.Family, e.DstAddr)
}

func addrFromBytes(family uint8, buf [16]byte) netip.Addr {
	switch family {
	case AFInet:
		var a [4]byte
		copy(a[:], buf[:4])
		return netip.AddrFrom4(a)
	case AFInet6:
		return netip.AddrFrom16(buf)
	default:
		return netip.Addr{}
	}
}

// ProtocolString maps the raw IPPROTO_* byte into the short uppercase
// token connection_logs.protocol stores ("TCP", "UDP", "ICMP", or "").
// Unknown values return "" — the NULLIF in the repo insert turns that
// into a SQL NULL rather than an invalid check-constraint value.
func (e LogEvent) ProtocolString() string {
	switch e.Protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1, 58:
		return "ICMP"
	default:
		return ""
	}
}

// ActionString maps the action byte into the uppercase token used in
// connection_logs.action.
func (e LogEvent) ActionString() string {
	switch e.Action {
	case 0:
		return "ALLOW"
	case 1:
		return "DENY"
	case 2:
		return "RATE_LIMIT"
	case 3:
		return "LOG"
	default:
		return ""
	}
}

// LogReader wraps a cilium/ebpf ringbuf.Reader so callers can iterate
// log events without touching the underlying map. It is *not* safe
// for concurrent Read — one reader goroutine per reader instance.
// Close unblocks an in-flight Read by signaling the kernel-side
// epoll waiter, so graceful shutdown is "Close then wait for Read
// to return ringbuf.ErrClosed".
type LogReader struct {
	r *ringbuf.Reader
}

// ErrLogRingbufUnavailable is returned by OpenLogReader when the
// loaded collection doesn't declare the log_events map — typically
// tests using a maps-only spec.
var ErrLogRingbufUnavailable = errors.New("log_events ringbuf not present in collection")

// OpenLogReader opens a single reader on the log_events ringbuf.
// Only one reader should be open at a time: the kernel ringbuf
// supports multiple consumers but the Go wrapper's cursor state is
// per-Reader and fan-out is not our use case. The caller must Close
// the returned reader to release the epoll fd.
func (l *RulesLoader) OpenLogReader() (*LogReader, error) {
	if l == nil || l.logEvents == nil {
		return nil, ErrLogRingbufUnavailable
	}
	r, err := ringbuf.NewReader(l.logEvents)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}
	return &LogReader{r: r}, nil
}

// Read blocks until a log_event is available, then decodes it. The
// err returned when the reader is closed is the wrapped
// ringbuf.ErrClosed — callers use errors.Is to detect shutdown.
func (r *LogReader) Read() (LogEvent, error) {
	rec, err := r.r.Read()
	if err != nil {
		return LogEvent{}, err
	}
	var ev LogEvent
	if err := ev.UnmarshalBinary(rec.RawSample); err != nil {
		return LogEvent{}, fmt.Errorf("decode ringbuf sample: %w", err)
	}
	return ev, nil
}

// Close releases the reader. Idempotent-ish: calling Close twice on
// an already-closed ringbuf.Reader returns an error, so we swallow it.
func (r *LogReader) Close() error {
	if r == nil || r.r == nil {
		return nil
	}
	err := r.r.Close()
	r.r = nil
	return err
}
