package repository

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ConnectionLogRepo writes datapath telemetry rows into the partitioned
// connection_logs table. Inserts are single-row and hot: the log
// consumer calls one Insert per ringbuf event on the drain goroutine.
//
// The table is PARTITION BY RANGE (recorded_at) with monthly
// partitions; a default catch-all absorbs writes that miss the managed
// window. That means Insert never needs to know which partition
// applies — Postgres routes by recorded_at.
//
// Foreign-key columns (peer_id, interface_id, matched_rule_id) are
// logical-only (no FK constraint) per migration 006 — the eBPF
// pipeline produces rule UUIDs the DB may not know about yet, and
// we'd rather keep the log than block on FK validation.
type ConnectionLogRepo struct {
	pool *pgxpool.Pool
}

func NewConnectionLogRepo(pool *pgxpool.Pool) *ConnectionLogRepo {
	return &ConnectionLogRepo{pool: pool}
}

// ConnectionLogEntry is the repo-facing shape for a single log row.
// Optional fields are pointers so the caller can distinguish "unknown"
// from "zero value". The datapath emits host-order ports and cooked
// IPs; this struct takes them in the same shape so the consumer
// doesn't need to convert twice.
type ConnectionLogEntry struct {
	RecordedAt    time.Time
	PeerID        *uuid.UUID
	InterfaceID   *uuid.UUID
	SrcIP         netip.Addr  // required
	DstIP         netip.Addr  // optional: zero Addr => NULL
	SrcPort       *int        // nil => NULL (non-TCP/UDP or unknown)
	DstPort       *int
	Protocol      string // "TCP", "UDP", "ICMP", or "" for NULL
	BytesIn       int64
	BytesOut      int64
	PacketsIn     int64
	PacketsOut    int64
	Action        string     // "ALLOW"/"DENY"/"RATE_LIMIT"/"LOG" or ""
	MatchedRuleID *uuid.UUID // the application-level rule UUID, not kernel rule_id
}

// Insert writes one row. Returns an error on DB failure; callers on
// the ringbuf drain log these and move on rather than failing the
// consumer — the datapath keeps running regardless.
func (r *ConnectionLogRepo) Insert(ctx context.Context, e ConnectionLogEntry) error {
	if !e.SrcIP.IsValid() {
		return fmt.Errorf("connection_log: src_ip is required")
	}
	if e.RecordedAt.IsZero() {
		e.RecordedAt = time.Now().UTC()
	}

	// netip.Addr's String() for IPv4 produces "1.2.3.4" and for IPv6
	// "::1" — both valid INET literals. The zero Addr stringifies to
	// "invalid IP" which we never send; dst gets NULLIF-gated below.
	srcStr := e.SrcIP.String()
	var dstStr string
	if e.DstIP.IsValid() {
		dstStr = e.DstIP.String()
	}

	_, err := r.pool.Exec(ctx,
		`INSERT INTO connection_logs
		   (recorded_at, peer_id, interface_id, src_ip, dst_ip,
		    src_port, dst_port, protocol, bytes_in, bytes_out,
		    packets_in, packets_out, action, matched_rule_id)
		 VALUES ($1, $2, $3, $4::inet, NULLIF($5, '')::inet,
		         $6, $7, NULLIF($8, ''), $9, $10,
		         $11, $12, NULLIF($13, ''), $14)`,
		e.RecordedAt, e.PeerID, e.InterfaceID, srcStr, dstStr,
		e.SrcPort, e.DstPort, e.Protocol, e.BytesIn, e.BytesOut,
		e.PacketsIn, e.PacketsOut, e.Action, e.MatchedRuleID,
	)
	if err != nil {
		return fmt.Errorf("insert connection_log: %w", err)
	}
	return nil
}
