package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/pflege-de-labs/nats-auth-callout/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeIssuer is a minimal OIDC provider serving discovery and JWKS.
type fakeIssuer struct {
	srv    *httptest.Server
	signer jose.Signer
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}}, nil)
	require.NoError(t, err)

	f := &fakeIssuer{signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"jwks_uri":                              f.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	c := map[string]any{
		"iss": f.srv.URL,
		"aud": "nats",
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range claims {
		c[k] = v
	}
	b, err := json.Marshal(c)
	require.NoError(t, err)
	obj, err := f.signer.Sign(b)
	require.NoError(t, err)
	s, err := obj.CompactSerialize()
	require.NoError(t, err)
	return s
}

func testConfig(issuerURL string) *config.Config {
	return &config.Config{
		Issuers:        []config.Issuer{{URL: issuerURL, Audience: "nats", RoleClient: "nats"}},
		DefaultAccount: config.GlobalAccount,
		Roles: map[string]config.Role{
			"events-read": {Sub: config.Permission{Allow: []string{"events.>"}}},
			"realm-admin": {Account: "ADMIN", Pub: config.Permission{Allow: []string{">"}}},
		},
	}
}

func authRequest(t *testing.T, token string) *jwt.AuthorizationRequestClaims {
	t.Helper()
	ukp, err := nkeys.CreateUser()
	require.NoError(t, err)
	pub, _ := ukp.PublicKey()
	rc := jwt.NewAuthorizationRequestClaims(pub)
	rc.UserNkey = pub
	rc.ConnectOptions.Token = token
	return rc
}

func TestAuthorize(t *testing.T) {
	f := newFakeIssuer(t)
	o := NewOIDC(testConfig(f.srv.URL))
	require.NoError(t, o.Ready(context.Background()))

	exp := time.Now().Add(30 * time.Minute).Unix()
	tok := f.token(t, map[string]any{
		"exp":                exp,
		"preferred_username": "alice",
		"resource_access":    map[string]any{"nats": map[string]any{"roles": []string{"events-read", "unknown"}}},
	})
	uc, err := o.Authorize(context.Background(), authRequest(t, tok))
	require.NoError(t, err)
	assert.Equal(t, config.GlobalAccount, uc.Audience)
	assert.Equal(t, "alice", uc.Name)
	assert.Equal(t, exp, uc.Expires)
	assert.Equal(t, jwt.StringList{"events.>"}, uc.Sub.Allow)
}

func TestAuthorizeRealmRoleAndSubjectName(t *testing.T) {
	f := newFakeIssuer(t)
	o := NewOIDC(testConfig(f.srv.URL))
	tok := f.token(t, map[string]any{"realm_access": map[string]any{"roles": []string{"realm-admin"}}})

	uc, err := o.Authorize(context.Background(), authRequest(t, tok))
	require.NoError(t, err)
	assert.Equal(t, "ADMIN", uc.Audience)
	assert.Equal(t, "user-1", uc.Name)
}

func TestAuthorizeRejects(t *testing.T) {
	f := newFakeIssuer(t)
	other := newFakeIssuer(t)
	o := NewOIDC(testConfig(f.srv.URL))
	roles := map[string]any{"resource_access": map[string]any{"nats": map[string]any{"roles": []string{"events-read"}}}}

	withAud := map[string]any{"aud": "other"}
	for k, v := range roles {
		withAud[k] = v
	}
	expired := map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}
	for k, v := range roles {
		expired[k] = v
	}
	valid := f.token(t, roles)

	for name, tc := range map[string]struct {
		token string
		want  error
	}{
		"no token":         {token: ""},
		"not a jwt":        {token: "a.b"},
		"bad payload":      {token: "a.!!!.c"},
		"payload not json": {token: "a.bm90LWpzb24.c"},
		"untrusted issuer": {token: other.token(t, roles)},
		"wrong audience":   {token: f.token(t, withAud)},
		"expired":          {token: f.token(t, expired)},
		"bad signature":    {token: valid[:len(valid)-4] + "AAAA"},
		"no roles":         {token: f.token(t, nil), want: ErrNoRoles},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := o.Authorize(context.Background(), authRequest(t, tc.token))
			require.Error(t, err)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
			}
		})
	}
}

func TestDiscoveryURLOverride(t *testing.T) {
	f := newFakeIssuer(t)
	cfg := testConfig("https://keycloak.example/realms/test")
	cfg.Issuers[0].DiscoveryURL = f.srv.URL
	o := NewOIDC(cfg)
	// Discovery reports a different issuer; the configured URL wins.
	assert.NoError(t, o.Ready(context.Background()))
}

func TestReadyFailsForUnreachableIssuer(t *testing.T) {
	o := NewOIDC(testConfig("http://127.0.0.1:1/realms/none"))
	assert.Error(t, o.Ready(context.Background()))

	tok := "e30." + "eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjEvcmVhbG1zL25vbmUifQ" + ".sig"
	_, err := o.Authorize(context.Background(), authRequest(t, tok))
	assert.ErrorContains(t, err, "discover issuer")
}
