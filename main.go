package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
	"github.com/pflege-de-labs/nats-auth-callout/internal/app"
	"github.com/pflege-de-labs/nats-auth-callout/internal/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type cli struct {
	Config kong.ConfigFlag `help:"YAML file with flag values." type:"path"`

	NatsURL          string               `default:"nats://localhost:4222" env:"NATS_URL,NATS_SERVER_URL" help:"NATS server URL."`
	AuthUser         string               `required:"" env:"AUTH_USER" help:"User listed in auth_callout.auth_users."`
	AuthPassword     string               `env:"AUTH_PASSWORD" help:"Password of the auth user."`
	AuthPasswordFile kong.FileContentFlag `env:"AUTH_PASSWORD_FILE" help:"File containing the auth user password."`
	IssuerSeed       string               `env:"ISSUER_NKEY" help:"Account nkey seed signing user JWTs."`
	IssuerSeedFile   kong.FileContentFlag `env:"ISSUER_NKEY_FILE" help:"File containing the issuer seed."`
	XKeySeed         string               `name:"xkey-seed" env:"XKEY" help:"Curve seed for encrypted callout requests."`
	XKeySeedFile     kong.FileContentFlag `name:"xkey-seed-file" env:"XKEY_FILE" help:"File containing the xkey seed."`
	PermissionsFile  string               `required:"" type:"existingfile" env:"PERMISSIONS_FILE" help:"Issuer and role mapping file."`
	Listen           string               `default:":8088" env:"LISTEN" help:"Address for probes and metrics."`
	Debug            bool                 `env:"DEBUG" help:"Enable debug logging."`
}

func main() {
	var c cli
	kong.Parse(&c,
		kong.Description("NATS auth callout service validating OIDC access tokens."),
		kong.Configuration(kongyaml.Loader, "/etc/nats-auth-callout/config.yaml", filepath.Join(configHome(), "nats-auth-callout", "config.yaml")),
	)

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if c.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	if err := run(c); err != nil {
		log.Fatal().Err(err).Msg("callout failed")
	}
}

func run(c cli) error {
	perms, err := config.Load(c.PermissionsFile)
	if err != nil {
		return err
	}
	issuer := secret(c.IssuerSeed, c.IssuerSeedFile)
	if issuer == "" {
		return errors.New("issuer seed required (--issuer-seed or --issuer-seed-file)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, app.Options{
		NatsURL:      c.NatsURL,
		AuthUser:     c.AuthUser,
		AuthPassword: secret(c.AuthPassword, c.AuthPasswordFile),
		IssuerSeed:   []byte(issuer),
		XKeySeed:     []byte(secret(c.XKeySeed, c.XKeySeedFile)),
		Permissions:  perms,
		Listen:       c.Listen,
	})
}

// secret prefers the inline value; files are trimmed because seeds usually end with a newline.
func secret(inline string, file []byte) string {
	if inline != "" {
		return inline
	}
	return strings.TrimSpace(string(file))
}

func configHome() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config")
}
