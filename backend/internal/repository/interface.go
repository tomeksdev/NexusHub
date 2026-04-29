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

// ErrInterfaceNotFound is returned when a lookup matches no row.
var ErrInterfaceNotFound = errors.New("interface not found")

type InterfaceRepo struct {
	pool *pgxpool.Pool
}

func NewInterfaceRepo(pool *pgxpool.Pool) *InterfaceRepo {
	return &InterfaceRepo{pool: pool}
}

// Interface mirrors the wg_interfaces row. PrivateKey is the encrypted
// blob (sealed with internal/crypto); callers must Open before handing it
// to the kernel.
type Interface struct {
	ID         uuid.UUID
	Name       string
	ListenPort int
	Address    netip.Prefix
	DNS        []string
	MTU        *int
	Endpoint   *string
	PrivateKey []byte
	PublicKey  string
	PostUp     *string
	PostDown   *string
	IsActive   bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// CreateInterfaceParams is the write-side input. Address takes a prefix so
// callers must commit to the netmask up front; we don't synthesize one.
type CreateInterfaceParams struct {
	Name       string
	ListenPort int
	Address    netip.Prefix
	DNS        []string
	MTU        *int
	Endpoint   *string
	PrivateKey []byte // encrypted
	PublicKey  string
	PostUp     *string
	PostDown   *string
}

func (r *InterfaceRepo) Create(ctx context.Context, p CreateInterfaceParams) (*Interface, error) {
	const q = `
		INSERT INTO wg_interfaces
		   (name, listen_port, address, dns, mtu, endpoint,
		    private_key, public_key, post_up, post_down)
		VALUES ($1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at, updated_at, is_active`
	out := Interface{
		Name: p.Name, ListenPort: p.ListenPort, Address: p.Address,
		DNS: p.DNS, MTU: p.MTU, Endpoint: p.Endpoint,
		PrivateKey: p.PrivateKey, PublicKey: p.PublicKey,
		PostUp: p.PostUp, PostDown: p.PostDown,
	}
	err := r.pool.QueryRow(ctx, q,
		p.Name, p.ListenPort, p.Address.String(), p.DNS, p.MTU, p.Endpoint,
		p.PrivateKey, p.PublicKey, p.PostUp, p.PostDown,
	).Scan(&out.ID, &out.CreatedAt, &out.UpdatedAt, &out.IsActive)
	if err != nil {
		return nil, fmt.Errorf("insert interface: %w", err)
	}
	return &out, nil
}

func (r *InterfaceRepo) GetByID(ctx context.Context, id uuid.UUID) (*Interface, error) {
	return r.scanOne(ctx, `WHERE id = $1`, id)
}

func (r *InterfaceRepo) GetByName(ctx context.Context, name string) (*Interface, error) {
	return r.scanOne(ctx, `WHERE name = $1`, name)
}

func (r *InterfaceRepo) List(ctx context.Context) ([]Interface, error) {
	rows, err := r.pool.Query(ctx, selectInterface+` ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	defer rows.Close()

	var out []Interface
	for rows.Next() {
		i, err := scanInterface(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *i)
	}
	return out, rows.Err()
}

// InterfaceSortFields exposes the columns a client may request via ?sort=.
var InterfaceSortFields = []string{"name", "listen_port", "created_at"}

// ListPage is the paginated variant. See PeerRepo.ListPage for rationale.
func (r *InterfaceRepo) ListPage(ctx context.Context, limit, offset int, sortField string, sortDesc bool) ([]Interface, int, error) {
	allowed := false
	for _, s := range InterfaceSortFields {
		if s == sortField {
			allowed = true
			break
		}
	}
	if !allowed {
		sortField = "name"
	}
	dir := "ASC"
	if sortDesc {
		dir = "DESC"
	}
	query := fmt.Sprintf("%s ORDER BY %s %s LIMIT $1 OFFSET $2", selectInterface, sortField, dir)
	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list interfaces page: %w", err)
	}
	defer rows.Close()

	var items []Interface
	for rows.Next() {
		i, err := scanInterface(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *i)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM wg_interfaces`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count interfaces: %w", err)
	}
	return items, total, nil
}

func (r *InterfaceRepo) Delete(ctx context.Context, id uuid.UUID) error {
	cmd, err := r.pool.Exec(ctx, `DELETE FROM wg_interfaces WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete interface: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrInterfaceNotFound
	}
	return nil
}

const selectInterface = `
	SELECT id, name, listen_port, address::text, dns, mtu, endpoint,
	       private_key, public_key, post_up, post_down,
	       is_active, created_at, updated_at
	  FROM wg_interfaces`

func (r *InterfaceRepo) scanOne(ctx context.Context, where string, args ...any) (*Interface, error) {
	row := r.pool.QueryRow(ctx, selectInterface+" "+where, args...)
	i, err := scanInterface(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInterfaceNotFound
	}
	return i, err
}

// scannable is satisfied by both *pgx.Row and pgx.Rows.
type scannable interface {
	Scan(dest ...any) error
}

func scanInterface(s scannable) (*Interface, error) {
	var (
		i       Interface
		addrStr string
	)
	err := s.Scan(
		&i.ID, &i.Name, &i.ListenPort, &addrStr, &i.DNS, &i.MTU, &i.Endpoint,
		&i.PrivateKey, &i.PublicKey, &i.PostUp, &i.PostDown,
		&i.IsActive, &i.CreatedAt, &i.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	pfx, perr := netip.ParsePrefix(addrStr)
	if perr != nil {
		return nil, fmt.Errorf("parse address %q: %w", addrStr, perr)
	}
	i.Address = pfx
	return &i, nil
}
