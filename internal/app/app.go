// Package app wires NATS, the callout responder, probes and metrics together.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/pflege-de-labs/nats-auth-callout/internal/auth"
	"github.com/pflege-de-labs/nats-auth-callout/internal/config"
	"github.com/pflege-de-labs/nats-auth-callout/internal/health"
	"github.com/pflege-de-labs/nats-auth-callout/internal/telemetry"
	"github.com/rs/zerolog/log"
)

// AuthSubject is where nats-server sends auth callout requests.
const AuthSubject = "$SYS.REQ.USER.AUTH"

// Version is reported by the micro service; set via ldflags.
var Version = "0.0.0-dev"

// Options configure a callout instance.
type Options struct {
	NatsURL      string
	AuthUser     string
	AuthPassword string
	IssuerSeed   []byte
	XKeySeed     []byte
	Permissions  *config.Config
	// Listener serves probes and metrics; Listen is used when nil.
	Listener net.Listener
	Listen   string
}

// Run serves auth callout requests until ctx is cancelled.
func Run(ctx context.Context, o Options) error {
	metrics, err := telemetry.New()
	if err != nil {
		return err
	}
	authz := auth.NewOIDC(o.Permissions)
	svc, err := auth.NewService(o.IssuerSeed, o.XKeySeed, authz, metrics.Observe)
	if err != nil {
		return err
	}
	log.Info().Str("issuer", svc.IssuerPublicKey()).Msg("callout issuer")

	nc, err := nats.Connect(o.NatsURL,
		nats.Name("nats-auth-callout"),
		nats.UserInfo(o.AuthUser, o.AuthPassword),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) { log.Warn().Err(err).Msg("nats disconnected") }),
		nats.ReconnectHandler(func(c *nats.Conn) { log.Info().Str("url", c.ConnectedUrl()).Msg("nats reconnected") }),
	)
	if err != nil {
		return fmt.Errorf("connect nats: %w", err)
	}
	defer nc.Close()

	// Default queue group spreads requests across replicas.
	ms, err := micro.AddService(nc, micro.Config{
		Name:        "nats-auth-callout",
		Version:     Version,
		Description: "Authorize NATS clients with OIDC access tokens",
		Endpoint:    &micro.EndpointConfig{Subject: AuthSubject, Handler: svc},
	})
	if err != nil {
		return fmt.Errorf("register callout service: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", health.Liveness())
	mux.Handle("/readyz", health.Readiness(3*time.Second, map[string]health.Check{
		"nats": func(context.Context) error {
			if !nc.IsConnected() {
				return errors.New("not connected")
			}
			return nil
		},
		"oidc": authz.Ready,
	}))
	mux.Handle("/metrics", metrics.Handler())
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	ln := o.Listener
	if ln == nil {
		if ln, err = net.Listen("tcp", o.Listen); err != nil {
			return fmt.Errorf("listen %s: %w", o.Listen, err)
		}
	}
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.Serve(ln) }()
	log.Info().Str("addr", ln.Addr().String()).Str("nats", o.NatsURL).Msg("callout running")

	select {
	case <-ctx.Done():
	case err = <-srvErr:
	}

	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	errs := []error{err}
	errs = append(errs, ms.Stop(), nc.Drain(), srv.Shutdown(shutdown), metrics.Shutdown(shutdown))
	return errors.Join(errs...)
}
