package auth

import (
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/pflege-de-labs/nats-auth-callout/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveMergesRoles(t *testing.T) {
	m := NewMapper(&config.Config{
		DefaultAccount: config.GlobalAccount,
		Roles: map[string]config.Role{
			"a": {
				Pub:  config.Permission{Allow: []string{"z.>"}, Deny: []string{"z.secret"}},
				Resp: &config.Response{MaxMsgs: 1, TTL: "1m"},
			},
			"b": {
				Pub:  config.Permission{Allow: []string{"a.>", "z.>"}},
				Sub:  config.Permission{Allow: []string{"s.>"}, Deny: []string{"s.x"}},
				Resp: &config.Response{MaxMsgs: 5, TTL: "10s"},
			},
		},
	})

	acc, p, err := m.Resolve([]string{"a", "unknown", "b"})
	require.NoError(t, err)
	assert.Equal(t, config.GlobalAccount, acc)
	assert.Equal(t, jwt.StringList{"a.>", "z.>"}, p.Pub.Allow)
	assert.Equal(t, jwt.StringList{"z.secret"}, p.Pub.Deny)
	assert.Equal(t, jwt.StringList{"s.>"}, p.Sub.Allow)
	assert.Equal(t, jwt.StringList{"s.x"}, p.Sub.Deny)
	assert.Equal(t, &jwt.ResponsePermission{MaxMsgs: 5, Expires: time.Minute}, p.Resp)
}

func TestResolveErrors(t *testing.T) {
	m := NewMapper(&config.Config{
		DefaultAccount: config.GlobalAccount,
		Roles: map[string]config.Role{
			"global": {},
			"other":  {Account: "APP"},
			"badttl": {Resp: &config.Response{TTL: "soon"}},
		},
	})

	_, _, err := m.Resolve(nil)
	assert.ErrorIs(t, err, ErrNoRoles)
	_, _, err = m.Resolve([]string{"global", "other"})
	assert.ErrorContains(t, err, "different accounts")
	_, _, err = m.Resolve([]string{"badttl"})
	assert.ErrorContains(t, err, "resp.ttl")
}
