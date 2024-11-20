package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

type OIDC struct {
	*oidc.IDTokenVerifier
}

var DefaultScopes = []string{oidc.ScopeOpenID, "profile", "email"}

func NewOIDC(providerURL, clientID string) (*OIDC, error) {
	p, err := oidc.NewProvider(context.Background(), providerURL)
	if err != nil {
		return nil, err
	}

	verifier := p.Verifier(&oidc.Config{ClientID: clientID})
	oidcAuth := OIDC{
		IDTokenVerifier: verifier,
	}

	return &oidcAuth, nil
}

type Claims struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func (v *OIDC) VerifyGoogleJWT(token string) (*Claims, error) {
	claims := &Claims{}

	idToken, err := v.Verify(context.Background(), token)
	if err != nil {
		return nil, err
	}

	if err := idToken.Claims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// func (o *OIDC) HandleAuthRequest(req *jwt.AuthorizationRequestClaims) (*jwt.UserClaims, error) {
// 	_ = req
// 	return nil, fmt.Errorf("not implemented")
// }

// func (o *OIDC) handleRedirect(w http.ResponseWriter, r *http.Request) {
// 	state, err := randString(16)
// 	if err != nil {
// 		http.Error(w, "Internal error", http.StatusInternalServerError)
// 		return
// 	}
// 	nonce, err := randString(16)
// 	if err != nil {
// 		http.Error(w, "Internal error", http.StatusInternalServerError)
// 		return
// 	}
// 	setCallbackCookie(w, r, "state", state)
// 	setCallbackCookie(w, r, "nonce", nonce)
// 	http.Redirect(w, r, o.cfg.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
// }

// func (o *OIDC) handleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
// 	// Verify state and errors.
// 	ctx := r.Context()
// 	oauth2Token, err := o.cfg.Exchange(ctx, r.URL.Query().Get("code"))
// 	if err != nil {
// 		// handle error
// 	}

// 	// Extract the ID Token from OAuth2 token.
// 	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
// 	if !ok {
// 		// handle missing token
// 	}

// 	verifier := o.p.VerifierContext(&oidc.Config{ClientID: o.cfg.ClientID})

// 	// Parse and verify ID Token payload.
// 	idToken, err := verifier.Verify(ctx, rawIDToken)
// 	if err != nil {
// 		// handle error
// 	}

// 	// Extract custom claims
// 	var claims struct {
// 		Email    string `json:"email"`
// 		Verified bool   `json:"email_verified"`
// 	}
// 	if err := idToken.Claims(&claims); err != nil {
// 		// handle error
// 	}
// }
