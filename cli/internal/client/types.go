package client

import "time"

// PageEnvelope mirrors the backend pagination shape.
type PageEnvelope[T any] struct {
	Items  []T    `json:"items"`
	Total  int    `json:"total"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
	Sort   string `json:"sort,omitempty"`
}

type Interface struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Address    string `json:"address"`
	ListenPort int    `json:"listen_port"`
	IsActive   bool   `json:"is_active"`
}

type Peer struct {
	ID            string    `json:"id"`
	InterfaceID   string    `json:"interface_id"`
	Name          string    `json:"name"`
	PublicKey     string    `json:"public_key"`
	AssignedIP    string    `json:"assigned_ip"`
	Status        string    `json:"status"`
	LastHandshake *string   `json:"last_handshake,omitempty"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	CreatedAt     time.Time `json:"created_at"`
}

type Rule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Action    string `json:"action"`
	Direction string `json:"direction"`
	Protocol  string `json:"protocol"`
	SrcCIDR   string `json:"src_cidr,omitempty"`
	DstCIDR   string `json:"dst_cidr,omitempty"`
	Priority  int    `json:"priority"`
	IsActive  bool   `json:"is_active"`
}

type User struct {
	ID           string  `json:"id"`
	Email        string  `json:"email"`
	Username     string  `json:"username"`
	Role         string  `json:"role"`
	IsActive     bool    `json:"is_active"`
	TOTPEnabled  bool    `json:"totp_enabled"`
	LastLoginAt  *string `json:"last_login_at,omitempty"`
	FailedLogins int     `json:"failed_logins"`
}

type AuditEntry struct {
	ID           string    `json:"id"`
	OccurredAt   time.Time `json:"occurred_at"`
	ActorEmail   *string   `json:"actor_email,omitempty"`
	ActorIP      *string   `json:"actor_ip,omitempty"`
	Action       string    `json:"action"`
	TargetType   string    `json:"target_type"`
	TargetID     string    `json:"target_id"`
	Result       string    `json:"result"`
	ErrorMessage *string   `json:"error_message,omitempty"`
}

type Health struct {
	Status string `json:"status"`
	Time   string `json:"time,omitempty"`
}
