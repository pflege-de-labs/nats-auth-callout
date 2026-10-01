// Package auth implements the NATS auth callout responder.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/micro"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"
)

// serverXKeyHeader carries the server's curve key when the request is encrypted.
const serverXKeyHeader = "Nats-Server-Xkey"

// Authorizer turns an authorization request into user claims.
type Authorizer interface {
	Authorize(context.Context, *jwt.AuthorizationRequestClaims) (*jwt.UserClaims, error)
}

// Result classifies a handled request for metrics.
type Result string

// Possible request outcomes.
const (
	ResultAllowed Result = "allowed"
	ResultDenied  Result = "denied"
	ResultError   Result = "error"
)

// Observer is notified about each handled request.
type Observer func(ctx context.Context, r Result, d time.Duration)

// Service answers auth callout requests on $SYS.REQ.USER.AUTH.
type Service struct {
	issuer  nkeys.KeyPair
	xkey    nkeys.KeyPair
	authz   Authorizer
	observe Observer
	timeout time.Duration
}

// NewService creates a responder. xkeySeed may be empty if the server does not encrypt requests.
func NewService(issuerSeed, xkeySeed []byte, authz Authorizer, observe Observer) (*Service, error) {
	issuer, err := nkeys.FromSeed(issuerSeed)
	if err != nil {
		return nil, fmt.Errorf("issuer seed: %w", err)
	}
	if p, _ := issuer.PublicKey(); !nkeys.IsValidPublicAccountKey(p) {
		return nil, errors.New("issuer seed must be an account key (SA...)")
	}

	s := &Service{issuer: issuer, authz: authz, observe: observe, timeout: 5 * time.Second}
	if len(xkeySeed) > 0 {
		xkey, err := nkeys.FromCurveSeed(xkeySeed)
		if err != nil {
			return nil, fmt.Errorf("xkey seed: %w", err)
		}
		s.xkey = xkey
	}
	if s.observe == nil {
		s.observe = func(context.Context, Result, time.Duration) {}
	}
	return s, nil
}

// IssuerPublicKey is the value for auth_callout.issuer in the server config.
func (s *Service) IssuerPublicKey() string {
	p, _ := s.issuer.PublicKey()
	return p
}

// Handle implements micro.Handler.
func (s *Service) Handle(req micro.Request) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	result := s.handle(ctx, req)
	s.observe(ctx, result, time.Since(start))
}

func (s *Service) handle(ctx context.Context, req micro.Request) Result {
	serverXKey := req.Headers().Get(serverXKeyHeader)
	data := req.Data()
	if serverXKey != "" {
		if s.xkey == nil {
			log.Error().Msg("server encrypts auth requests but no xkey is configured")
			_ = req.Error("500", "xkey not configured", nil)
			return ResultError
		}
		plain, err := s.xkey.Open(data, serverXKey)
		if err != nil {
			log.Error().Err(err).Msg("decrypt auth request")
			_ = req.Error("400", "cannot decrypt request", nil)
			return ResultError
		}
		data = plain
	}

	rc, err := jwt.DecodeAuthorizationRequestClaims(string(data))
	if err != nil {
		log.Error().Err(err).Msg("decode auth request")
		_ = req.Error("400", "invalid authorization request", nil)
		return ResultError
	}

	logger := log.With().Str("client", rc.ClientInformation.Name).Str("host", rc.ClientInformation.Host).Logger()
	uc, err := s.authz.Authorize(ctx, rc)
	var userJWT string
	if err == nil {
		userJWT, err = s.sign(uc)
	}
	if err != nil {
		logger.Info().Err(err).Msg("connection denied")
	} else {
		logger.Debug().Str("user", uc.Name).Str("account", uc.Audience).Msg("connection allowed")
	}

	if rerr := s.respond(req, rc, serverXKey, userJWT, err); rerr != nil {
		logger.Error().Err(rerr).Msg("send auth response")
		return ResultError
	}
	if err != nil {
		return ResultDenied
	}
	return ResultAllowed
}

func (s *Service) sign(uc *jwt.UserClaims) (string, error) {
	// jwt validation accepts an empty audience, but the server needs a target account.
	if uc.Audience == "" {
		return "", errors.New("user claims have no target account")
	}
	vr := jwt.CreateValidationResults()
	uc.Validate(vr)
	if errs := vr.Errors(); len(errs) > 0 {
		return "", errors.Join(errs...)
	}
	return uc.Encode(s.issuer)
}

func (s *Service) respond(req micro.Request, rc *jwt.AuthorizationRequestClaims, serverXKey, userJWT string, authErr error) error {
	resp := jwt.NewAuthorizationResponseClaims(rc.UserNkey)
	resp.Audience = rc.Server.ID
	resp.Jwt = userJWT
	if authErr != nil {
		// Details stay in our logs; clients only see a generic reason.
		resp.Error = "not authorized"
	}
	token, err := resp.Encode(s.issuer)
	if err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	out := []byte(token)
	if serverXKey != "" {
		if out, err = s.xkey.Seal(out, serverXKey); err != nil {
			return fmt.Errorf("encrypt response: %w", err)
		}
	}
	return req.Respond(out)
}
