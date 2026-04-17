// Package config loads runtime configuration from the environment.
package config

import (
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	DatabaseURL string `envconfig:"DATABASE_URL" required:"true"`

	Port    int    `envconfig:"PORT" default:"8080"`
	GinMode string `envconfig:"GIN_MODE" default:"release"`

	JWTSecret        string        `envconfig:"JWT_SECRET" required:"true"`
	JWTAccessExpiry  time.Duration `envconfig:"JWT_ACCESS_EXPIRY" default:"15m"`
	JWTRefreshExpiry time.Duration `envconfig:"JWT_REFRESH_EXPIRY" default:"168h"`

	// Rate limits are per client IP per minute, with a burst matching the
	// typical cluster of retries a reasonable client makes. Set to 0 to
	// disable (tests + operators troubleshooting lockouts).
	RateLimitLoginPerMinute   int `envconfig:"RATELIMIT_LOGIN_PER_MINUTE"   default:"10"`
	RateLimitLoginBurst       int `envconfig:"RATELIMIT_LOGIN_BURST"        default:"5"`
	RateLimitRefreshPerMinute int `envconfig:"RATELIMIT_REFRESH_PER_MINUTE" default:"60"`
	RateLimitRefreshBurst     int `envconfig:"RATELIMIT_REFRESH_BURST"      default:"20"`

	SMTPHost string `envconfig:"SMTP_HOST"`
	SMTPPort int    `envconfig:"SMTP_PORT" default:"587"`
	SMTPUser string `envconfig:"SMTP_USER"`
	SMTPPass string `envconfig:"SMTP_PASS"`
	SMTPFrom string `envconfig:"SMTP_FROM" default:"noreply@example.com"`

	WGInterface  string `envconfig:"WG_INTERFACE" default:"wg0"`
	WGListenPort int    `envconfig:"WG_LISTEN_PORT" default:"51820"`
	WGEndpoint   string `envconfig:"WG_ENDPOINT"`

	// Master key used to encrypt wg_peers.private_key at rest. 32 bytes, base64.
	PeerKeyEncryptionKey string `envconfig:"PEER_KEY_ENCRYPTION_KEY" required:"true"`
}

func Load() (*Config, error) {
	var c Config
	if err := envconfig.Process("", &c); err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return &c, nil
}
