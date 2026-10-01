package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nats-io/jwt/v2"
	"github.com/pflege-de-labs/nats-auth-callout/internal/config"
)

// ErrNoToken is returned when the client connected without a token.
var ErrNoToken = errors.New("no token in connect options")

// OIDC authorizes NATS connections carrying an OIDC access token.
type OIDC struct {
	issuers map[string]*issuer
	mapper  *Mapper
}

type issuer struct {
	cfg config.Issuer

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

// tokenClaims are the Keycloak claims used for mapping.
type tokenClaims struct {
	PreferredUsername string `json:"preferred_username"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

// NewOIDC creates an authorizer; issuer discovery happens lazily on first use or Ready.
func NewOIDC(cfg *config.Config) *OIDC {
	o := &OIDC{issuers: map[string]*issuer{}, mapper: NewMapper(cfg)}
	for _, is := range cfg.Issuers {
		o.issuers[is.URL] = &issuer{cfg: is}
	}
	return o
}

// Ready succeeds once discovery for every issuer has been loaded.
func (o *OIDC) Ready(ctx context.Context) error {
	var errs []error
	for _, is := range o.issuers {
		if _, err := is.get(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (i *issuer) get(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.verifier != nil {
		return i.verifier, nil
	}

	discovery := i.cfg.URL
	if i.cfg.DiscoveryURL != "" {
		discovery = i.cfg.DiscoveryURL
		ctx = oidc.InsecureIssuerURLContext(ctx, i.cfg.URL)
	}
	// Provider keeps ctx for later JWKS fetches, so it must not be request scoped.
	p, err := oidc.NewProvider(context.WithoutCancel(ctx), discovery)
	if err != nil {
		return nil, fmt.Errorf("discover issuer %s: %w", i.cfg.URL, err)
	}
	i.verifier = p.Verifier(&oidc.Config{ClientID: i.cfg.Audience})
	return i.verifier, nil
}

// Authorize verifies the connect token and builds the NATS user claims.
func (o *OIDC) Authorize(ctx context.Context, req *jwt.AuthorizationRequestClaims) (*jwt.UserClaims, error) {
	token := req.ConnectOptions.Token
	if token == "" {
		return nil, ErrNoToken
	}

	iss, err := unverifiedIssuer(token)
	if err != nil {
		return nil, err
	}
	is, ok := o.issuers[iss]
	if !ok {
		return nil, fmt.Errorf("untrusted issuer %q", iss)
	}
	v, err := is.get(ctx)
	if err != nil {
		return nil, err
	}
	idt, err := v.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	var tc tokenClaims
	if err := idt.Claims(&tc); err != nil {
		return nil, fmt.Errorf("decode token claims: %w", err)
	}

	account, perms, err := o.mapper.Resolve(tc.roles(is.cfg.RoleClient))
	if err != nil {
		return nil, err
	}

	uc := jwt.NewUserClaims(req.UserNkey)
	uc.Audience = account
	uc.Name = tc.PreferredUsername
	if uc.Name == "" {
		uc.Name = idt.Subject
	}
	// NATS disconnects the client once the token expires.
	uc.Expires = idt.Expiry.Unix()
	uc.Permissions = perms
	return uc, nil
}

func (c tokenClaims) roles(client string) []string {
	roles := append([]string{}, c.RealmAccess.Roles...)
	if client != "" {
		roles = append(roles, c.ResourceAccess[client].Roles...)
	}
	return roles
}

// unverifiedIssuer reads "iss" to pick the verifier; the signature is checked afterwards.
func unverifiedIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode token payload: %w", err)
	}
	var c struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("parse token payload: %w", err)
	}
	return c.Issuer, nil
}
