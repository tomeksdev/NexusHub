package repository

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrPeerNotFound is returned when a lookup matches no row.
var ErrPeerNotFound = errors.New("peer not found")

type PeerRepo struct {
	pool *pgxpool.Pool
}

func NewPeerRepo(pool *pgxpool.Pool) *PeerRepo {
	return &PeerRepo{pool: pool}
}

// Peer mirrors the wg_peers row. PrivateKey may be nil (peer keys can be
// generated client-side and never reach the server). When present it is
// the encrypted blob; callers must Open before exporting.
type Peer struct {
	ID                  uuid.UUID
	InterfaceID         uuid.UUID
	OwnerUserID         *uuid.UUID
	Name                string
	Description         *string
	PublicKey           string
	PrivateKey          []byte // encrypted; may be nil
	AllowedIPs          []netip.Prefix
	AssignedIP          netip.Addr
	Endpoint            *string
	PersistentKeepalive *int
	DNS                 []string
	Status              string
	LastHandshake       *time.Time
	RxBytes             int64
	TxBytes             int64
	ExpiresAt           *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type CreatePeerParams struct {
	InterfaceID         uuid.UUID
	OwnerUserID         *uuid.UUID
	Name                string
	Description         *string
	PublicKey           string
	PrivateKey          []byte // encrypted; may be nil
	AllowedIPs          []netip.Prefix
	AssignedIP          netip.Addr
	Endpoint            *string
	PersistentKeepalive *int
	DNS                 []string
	ExpiresAt           *time.Time
}

func (r *PeerRepo) Create(ctx context.Context, p CreatePeerParams) (*Peer, error) {
	const q = `
		INSERT INTO wg_peers
		   (interface_id, owner_user_id, name, description,
		    public_key, private_key, allowed_ips, assigned_ip,
		    endpoint, persistent_keepalive, dns, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::cidr[], $8::inet,
		        $9, $10, $11, $12)
		RETURNING id, status::text, created_at, updated_at,
		          rx_bytes, tx_bytes`
	allowed := prefixesToStrings(p.AllowedIPs)
	out := Peer{
		InterfaceID: p.InterfaceID, OwnerUserID: p.OwnerUserID,
		Name: p.Name, Description: p.Description,
		PublicKey: p.PublicKey, PrivateKey: p.PrivateKey,
		AllowedIPs: p.AllowedIPs, AssignedIP: p.AssignedIP,
		Endpoint: p.Endpoint, PersistentKeepalive: p.PersistentKeepalive,
		DNS: p.DNS, ExpiresAt: p.ExpiresAt,
	}
	err := r.pool.QueryRow(ctx, q,
		p.InterfaceID, p.OwnerUserID, p.Name, p.Description,
		p.PublicKey, p.PrivateKey, allowed, p.AssignedIP.String(),
		p.Endpoint, p.PersistentKeepalive, p.DNS, p.ExpiresAt,
	).Scan(&out.ID, &out.Status, &out.CreatedAt, &out.UpdatedAt,
		&out.RxBytes, &out.TxBytes)
	if err != nil {
		return nil, fmt.Errorf("insert peer: %w", err)
	}
	return &out, nil
}

func (r *PeerRepo) GetByID(ctx context.Context, id uuid.UUID) (*Peer, error) {
	return r.scanOne(ctx, `WHERE id = $1`, id)
}

func (r *PeerRepo) ListByInterface(ctx context.Context, ifaceID uuid.UUID) ([]Peer, error) {
	rows, err := r.pool.Query(ctx, selectPeer+` WHERE interface_id = $1 ORDER BY name`, ifaceID)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()

	var out []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// PeerSortField is the allow-list of columns exposed to ?sort=. Kept here
// (alongside the query builder) rather than in the handler so tests and
// SDK-gen consumers have a single source of truth.
var PeerSortFields = []string{"name", "assigned_ip", "created_at", "last_handshake"}

// ListPage is the paginated + sortable list. The ORDER BY clause is
// built from a whitelist (see PeerSortFields) so no caller string ever
// reaches SQL directly. Returns (items, total) so callers can emit the
// response envelope in one shot.
func (r *PeerRepo) ListPage(ctx context.Context, ifaceID uuid.UUID, limit, offset int, sortField string, sortDesc bool) ([]Peer, int, error) {
	if !contains(PeerSortFields, sortField) {
		sortField = "name"
	}
	dir := "ASC"
	if sortDesc {
		dir = "DESC"
	}
	query := fmt.Sprintf("%s WHERE interface_id = $1 ORDER BY %s %s NULLS LAST LIMIT $2 OFFSET $3",
		selectPeer, sortField, dir)

	rows, err := r.pool.Query(ctx, query, ifaceID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list peers page: %w", err)
	}
	defer rows.Close()

	var items []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM wg_peers WHERE interface_id = $1`, ifaceID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count peers: %w", err)
	}
	return items, total, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// AssignedIPsByInterface returns just the assigned IPs — feeds the
// IP-pool allocator without dragging the rest of every peer row.
func (r *PeerRepo) AssignedIPsByInterface(ctx context.Context, ifaceID uuid.UUID) ([]netip.Addr, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT assigned_ip::text FROM wg_peers WHERE interface_id = $1`, ifaceID)
	if err != nil {
		return nil, fmt.Errorf("list assigned ips: %w", err)
	}
	defer rows.Close()

	var out []netip.Addr
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("parse assigned ip %q: %w", s, err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *PeerRepo) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	cmd, err := r.pool.Exec(ctx,
		`UPDATE wg_peers SET status = $2::wg_peer_status WHERE id = $1`,
		id, status)
	if err != nil {
		return fmt.Errorf("update peer status: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrPeerNotFound
	}
	return nil
}

func (r *PeerRepo) Delete(ctx context.Context, id uuid.UUID) error {
	cmd, err := r.pool.Exec(ctx, `DELETE FROM wg_peers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrPeerNotFound
	}
	return nil
}

// ActivePSK returns the sealed bytes of the peer's current preshared key, or
// (nil, nil) when no PSK is configured. The caller decrypts via crypto.AEAD.
func (r *PeerRepo) ActivePSK(ctx context.Context, peerID uuid.UUID) ([]byte, error) {
	var psk []byte
	err := r.pool.QueryRow(ctx,
		`SELECT preshared_key FROM wg_peer_preshared_keys
		 WHERE peer_id = $1 AND retired_at IS NULL`, peerID).Scan(&psk)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get active psk: %w", err)
	}
	return psk, nil
}

// RotatePSK retires the current active PSK (if any) and inserts a new one in
// a single transaction. The partial unique index wg_psk_active_unique means
// we MUST retire before inserting — doing both in one tx keeps the invariant
// that a peer has at most one non-retired row.
func (r *PeerRepo) RotatePSK(ctx context.Context, peerID uuid.UUID, sealedPSK []byte) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin psk rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE wg_peer_preshared_keys
		    SET retired_at = now()
		  WHERE peer_id = $1 AND retired_at IS NULL`, peerID); err != nil {
		return fmt.Errorf("retire old psk: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO wg_peer_preshared_keys (peer_id, preshared_key)
		 VALUES ($1, $2)`, peerID, sealedPSK); err != nil {
		return fmt.Errorf("insert new psk: %w", err)
	}
	return tx.Commit(ctx)
}

const selectPeer = `
	SELECT id, interface_id, owner_user_id, name, description,
	       public_key, private_key,
	       allowed_ips::text[], assigned_ip::text,
	       endpoint, persistent_keepalive, dns, status::text,
	       last_handshake, rx_bytes, tx_bytes, expires_at,
	       created_at, updated_at
	  FROM wg_peers`

func (r *PeerRepo) scanOne(ctx context.Context, where string, args ...any) (*Peer, error) {
	row := r.pool.QueryRow(ctx, selectPeer+" "+where, args...)
	p, err := scanPeer(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPeerNotFound
	}
	return p, err
}

func scanPeer(s scannable) (*Peer, error) {
	var (
		p           Peer
		allowedStrs []string
		assignedStr string
	)
	err := s.Scan(
		&p.ID, &p.InterfaceID, &p.OwnerUserID, &p.Name, &p.Description,
		&p.PublicKey, &p.PrivateKey,
		&allowedStrs, &assignedStr,
		&p.Endpoint, &p.PersistentKeepalive, &p.DNS, &p.Status,
		&p.LastHandshake, &p.RxBytes, &p.TxBytes, &p.ExpiresAt,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	p.AllowedIPs = make([]netip.Prefix, 0, len(allowedStrs))
	for _, s := range allowedStrs {
		pfx, perr := netip.ParsePrefix(s)
		if perr != nil {
			return nil, fmt.Errorf("parse allowed_ip %q: %w", s, perr)
		}
		p.AllowedIPs = append(p.AllowedIPs, pfx)
	}
	a, perr := netip.ParseAddr(assignedStr)
	if perr != nil {
		return nil, fmt.Errorf("parse assigned_ip %q: %w", assignedStr, perr)
	}
	p.AssignedIP = a
	return &p, nil
}

func prefixesToStrings(in []netip.Prefix) []string {
	out := make([]string, len(in))
	for i, p := range in {
		out[i] = p.String()
	}
	return out
}
