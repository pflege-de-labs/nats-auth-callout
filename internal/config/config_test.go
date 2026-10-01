package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDevcontainerExample(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", ".devcontainer", "callout", "permissions.yaml"))
	require.NoError(t, err)
	assert.Equal(t, GlobalAccount, c.DefaultAccount)
	assert.Equal(t, "nats", c.Issuers[0].Audience)
	assert.Equal(t, GlobalAccount, c.AccountFor(c.Roles["events-read"]))
	assert.Equal(t, "APP", c.AccountFor(Role{Account: "APP"}))
}

func TestParseDefaultsAccount(t *testing.T) {
	c, err := Parse([]byte(`
issuers: [{url: https://kc/realms/a, audience: nats}]
roles: {r: {}}
`))
	require.NoError(t, err)
	assert.Equal(t, GlobalAccount, c.DefaultAccount)
}

func TestParseInvalid(t *testing.T) {
	_, err := Parse([]byte("issuers: ["))
	assert.ErrorContains(t, err, "parse")

	_, err = Parse([]byte("issuers: [{}]"))
	assert.ErrorContains(t, err, "url required")
	assert.ErrorContains(t, err, "audience required")
	assert.ErrorContains(t, err, "at least one role")

	_, err = Parse([]byte("roles: {r: {}}"))
	assert.ErrorContains(t, err, "at least one issuer")
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}
