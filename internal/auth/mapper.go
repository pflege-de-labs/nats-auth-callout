package auth

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/pflege-de-labs/nats-auth-callout/internal/config"
)

// ErrNoRoles is returned when a token carries no role known to the mapping.
var ErrNoRoles = errors.New("no NATS role assigned")

// Mapper turns token roles into a target account and NATS permissions.
type Mapper struct {
	cfg *config.Config
}

// NewMapper creates a mapper for the given config.
func NewMapper(cfg *config.Config) *Mapper {
	return &Mapper{cfg: cfg}
}

// Resolve merges the permissions of all known roles; all must target the same account.
func (m *Mapper) Resolve(roles []string) (string, jwt.Permissions, error) {
	var (
		perms   jwt.Permissions
		account string
		matched []string
	)
	for _, name := range roles {
		r, ok := m.cfg.Roles[name]
		if !ok {
			continue
		}
		acc := m.cfg.AccountFor(r)
		if account != "" && acc != account {
			return "", perms, fmt.Errorf("roles %v target different accounts (%s, %s)", append(matched, name), account, acc)
		}
		account = acc
		matched = append(matched, name)

		perms.Pub.Allow.Add(r.Pub.Allow...)
		perms.Pub.Deny.Add(r.Pub.Deny...)
		perms.Sub.Allow.Add(r.Sub.Allow...)
		perms.Sub.Deny.Add(r.Sub.Deny...)
		if err := mergeResp(&perms, r.Resp); err != nil {
			return "", perms, fmt.Errorf("role %s: %w", name, err)
		}
	}
	if account == "" {
		return "", perms, ErrNoRoles
	}
	slices.Sort(perms.Pub.Allow)
	slices.Sort(perms.Sub.Allow)
	return account, perms, nil
}

// mergeResp keeps the most permissive response settings across roles.
func mergeResp(p *jwt.Permissions, r *config.Response) error {
	if r == nil {
		return nil
	}
	var ttl time.Duration
	if r.TTL != "" {
		d, err := time.ParseDuration(r.TTL)
		if err != nil {
			return fmt.Errorf("resp.ttl: %w", err)
		}
		ttl = d
	}
	if p.Resp == nil {
		p.Resp = &jwt.ResponsePermission{MaxMsgs: r.MaxMsgs, Expires: ttl}
		return nil
	}
	p.Resp.MaxMsgs = max(p.Resp.MaxMsgs, r.MaxMsgs)
	p.Resp.Expires = max(p.Resp.Expires, ttl)
	return nil
}
