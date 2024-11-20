package main

import (
	"net/http"
	"net/url"

	"github.com/alecthomas/kong"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/micro"
	"github.com/pflege-de/nats-oidc-auth/internal/auth"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type cliOpts struct {
	NatsURL          url.URL `long:"nats-url" default:"nats://localhost:4222" env:"NATS_SERVER_URL"`
	ClientID         string  `long:"client-id" env:"CLIENT_ID"`
	ClientSecret     string  `long:"client-scecret" env:"CLIENT_SECRET"`
	AuthUser         string  `long:"auth-user" env:"AUTH_USER" required:"true"`
	AuthUserPassword string  `long:"auth-password" env:"AUTH_PASSWORD" required:"true"`
	IssuerKey        []byte  `long:"issuer-key" env:"ISSUER_NKEY"`
	Debug            bool    `long:"debug" default:"false"`
	Provider         url.URL `long:"oidc-url" env:"OIDC_URL"`
}

var cli cliOpts

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	ktx := kong.Parse(&cli)
	_ = ktx

	if cli.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	log.Info().Msgf("Connecting to NATS at %s", cli.NatsURL.String())

	c, err := nats.Connect(cli.NatsURL.String(), nats.Name("auth-service"), nats.UserInfo(cli.AuthUser, cli.AuthUserPassword))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to nats")
	}
	defer c.Close()

	verifier, err := auth.NewOIDC(cli.Provider.String(), cli.ClientID)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create oidc verifier")
	}

	auth, err := auth.NewService(cli.IssuerKey, verifier)

	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize service")
	}

	svc, err := micro.AddService(c, micro.Config{
		Name:        "oidc-auth",
		Version:     "0.0.1",
		Description: "Handle authorization of oidc jwts",
		Endpoint: &micro.EndpointConfig{
			Subject: "$SYS.REQ.USER.AUTH",
			Handler: auth,
		},
	})

	if err != nil {
		log.Fatal().Err(err)
	}

	_ = svc

	http.ListenAndServe(":8088", nil)
}
