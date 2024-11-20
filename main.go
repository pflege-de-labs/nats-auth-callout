package main

import (
	"net/http"
	"net/url"

	"github.com/alecthomas/kong"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type cliOpts struct {
	NatsURL          url.URL `long:"nats-url" default:"nats://localhost:4222" env:"NATS_SERVER_URL"`
	ClientID         string  `long:"client-id" env:"CLIENT_ID"`
	ClientSecret     string  `long:"client-scecret" env:"CLIENT_SECRET"`
	AuthUser         string  `long:"auth-user" env:"AUTH_USER" required:"true"`
	AuthUserPassword string  `long:"auth-password" env:"AUTH_PASSWORD" required:"true"`
	IssuerKey        string  `long:"issuer-key" env:"ISSUER_NKEY"`
	Debug            bool    `long:"debug" default:"false"`
}

var cli cliOpts

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	ktx := kong.Parse(&cli)
	_ = ktx

	if cli.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	jwt.DecodeAuthorizationRequestClaims("xxx")

	log.Info().Msg(cli.NatsURL.String())
	log.Info().Msgf("Connecting to NATS at %s", cli.NatsURL.String())
	c, err := nats.Connect(cli.NatsURL.String(), nats.Name("auth-service"), nats.UserInfo(cli.AuthUser, cli.AuthUserPassword))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to nats")
	}
	_ = c

	http.ListenAndServe(":8088", nil)
}
