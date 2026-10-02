# nats-auth-callout

[NATS auth callout](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_callout)
service that lets clients log in with OIDC access tokens (e.g. Keycloak).

Clients send their access token as the NATS connect token (`nats.Token()`, or `nats.TokenHandler()`
for long-running clients so that a reconnect fetches a fresh token). The callout:

1. verifies the token against the issuer's JWKS (`iss`, `aud`, `exp`, signature),
2. maps the realm roles and the `resource_access.<roleClient>` roles to a NATS account and pub/sub permissions,
3. returns a user JWT signed by the issuer account key. The user JWT expires together with the token.

Encrypted callout requests (`auth_callout.xkey`) are supported.

## Configuration

| Flag / env | Purpose |
|---|---|
| `--nats-url` / `NATS_URL` | NATS server |
| `--auth-user`, `--auth-password[-file]` / `AUTH_USER`, `AUTH_PASSWORD[_FILE]` | callout user, must be listed in `auth_users` |
| `--issuer-seed[-file]` / `ISSUER_NKEY[_FILE]` | account seed (`SA…`); public key goes to `auth_callout.issuer` |
| `--xkey-seed[-file]` / `XKEY[_FILE]` | curve seed (`SX…`); public key goes to `auth_callout.xkey` |
| `--permissions-file` / `PERMISSIONS_FILE` | issuers and role mapping, see [example](.devcontainer/callout/permissions.yaml) |
| `--listen` / `LISTEN` | `:8088`, serves `/healthz`, `/readyz` (NATS connected, OIDC discovery loaded), `/metrics` |
| `--config` | YAML file with flag values; defaults to `/etc/nats-auth-callout/config.yaml` or `$XDG_CONFIG_HOME/nats-auth-callout/config.yaml` |

Generate keys with `nsc generate nkey --account` and `nsc generate nkey --curve`.

Per issuer, `discoveryURL` can point to an in-cluster address while `url` stays the public
issuer that appears in the tokens' `iss` claim.

### nats-server (config mode)

```
authorization {
  users: [ { user: auth-callout, password: … }, …existing users… ]
  auth_callout {
    issuer: A…
    xkey: X…
    account: "$G"   # quote it, unquoted $G is a config variable
    auth_users: [ auth-callout, …every static user and nkey, including $SYS users… ]
  }
}
```

Every connection whose user is not listed in `auth_users` goes to the callout. That includes users
of other accounts such as `$SYS`. See the [e2e findings](#e2e-findings).

## Development

> [!WARNING]
> The nkeys, passwords and client secrets under `.devcontainer/` (and those below) are
> **public examples**. Use them only for the devcontainer and the tests, never in a real
> deployment. See [.devcontainer/nkey/README.md](.devcontainer/nkey/README.md).

Example user seeds used in `.devcontainer/nkey/`:

- User nkey (example only): `SUACMAYZT6D72E4OXC2EAKWK4IMLNFJO6XRBARNQJST4QTQYOQ5GPVCGWY`
- Sys user nkey (example only): `SUAK2LGYKMUC7MDWKIPZEEL7LVLXMKYZSWTACSJ5LGA7RQ34LWA5RM5Q5E`

The devcontainer starts NATS (config mirrors the cc-gitops production setup) and Keycloak with the
`test` realm (`alice` with role `events-read`, `bob` without roles, service account `svc-orders`).

```sh
go test -race ./internal/...          # unit tests
go test -tags e2e -count=1 ./e2e/...  # needs Docker or Podman
```

With Podman:

```sh
export DOCKER_HOST=unix://$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}')
export TESTCONTAINERS_RYUK_DISABLED=true
```

The e2e suite runs two deployments: `global` (production/staging style, static users in `$G`) and
`management` (named accounts, MQTT, [testdata](e2e/testdata)). `NATS_IMAGE` and
`NATS_MANAGEMENT_IMAGE` override their nats-server images (defaults: the cc-gitops versions).

### e2e findings

Verified against nats-server 2.12.6 and 2.14.7 in config mode:

- `no_auth_user` still works with auth callout, as long as that user is in `auth_users`. Anonymous
  clients (e.g. NACK) connect as that user without a callout request.
- Callout users can be placed in `$G`. They exchange messages with static users and see the
  streams of the global account.
- `$SYS` users are sent to the callout unless they are listed in `auth_users`.

NATS with named accounts, nats-server 2.14.0:

- `no_auth_user` in a named account (`mqtt` in `MQTT`) keeps working when listed in `auth_users`.
- `auth_callout.account` can be a dedicated account (`AUTH`); token users land in `AUDIT` or `MQTT` per role.
- MQTT clients authenticate with the access token as MQTT password (any username not in `auth_users`).
- MQTT `topic/#` also subscribes to the parent subject, so roles need both `topic` and `topic.>`.
