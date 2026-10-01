//go:build e2e

// Package e2e runs the callout against real nats-server and Keycloak containers,
// using the same config files as the devcontainer.
package e2e

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/pflege-de-labs/nats-auth-callout/internal/app"
	"github.com/pflege-de-labs/nats-auth-callout/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const keycloakImage = "quay.io/keycloak/keycloak:26.8.0"

// natsImage defaults to the cc-gitops production version; override with NATS_IMAGE.
var natsImage = cmp.Or(os.Getenv("NATS_IMAGE"), "nats:2.12.6-alpine")

var devcontainer = filepath.Join("..", ".devcontainer")

var env struct {
	natsURL     string
	keycloakURL string
	// calloutCalls counts requests the server sent to the callout.
	calloutCalls atomic.Int64
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	natsC, err := startNATS(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start nats:", err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(natsC) }()

	kcC, err := startKeycloak(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start keycloak:", err)
		return 1
	}
	defer func() { _ = testcontainers.TerminateContainer(kcC) }()

	readyURL, done, err := startCallout(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start callout:", err)
		return 1
	}
	if err := waitReady(ctx, readyURL); err != nil {
		fmt.Fprintln(os.Stderr, "callout not ready:", err)
		return 1
	}

	spy, err := spyCallout()
	if err != nil {
		fmt.Fprintln(os.Stderr, "spy callout:", err)
		return 1
	}
	code := m.Run()
	spy.Close()
	cancel()
	<-done
	return code
}

func startNATS(ctx context.Context) (testcontainers.Container, error) {
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        natsImage,
			ExposedPorts: []string{"4222/tcp"},
			Cmd:          []string{"-c", "/conf/nats.conf"},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      filepath.Join(devcontainer, "nats", "nats.conf"),
				ContainerFilePath: "/conf/nats.conf",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForLog("Server is ready").WithStartupTimeout(time.Minute),
		},
	})
	if err != nil {
		return c, err
	}
	ep, err := c.PortEndpoint(ctx, "4222/tcp", "nats")
	env.natsURL = ep
	return c, err
}

func startKeycloak(ctx context.Context) (testcontainers.Container, error) {
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        keycloakImage,
			ExposedPorts: []string{"8080/tcp"},
			Env: map[string]string{
				"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
				"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
			},
			Cmd: []string{"start-dev", "--import-realm"},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      filepath.Join(devcontainer, "keycloak", "realm-test.json"),
				ContainerFilePath: "/opt/keycloak/data/import/realm-test.json",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForHTTP("/realms/test/.well-known/openid-configuration").
				WithPort("8080/tcp").
				WithStartupTimeout(3 * time.Minute),
		},
	})
	if err != nil {
		return c, err
	}
	ep, err := c.PortEndpoint(ctx, "8080/tcp", "http")
	env.keycloakURL = ep
	return c, err
}

// startCallout runs the real app wiring in-process with the devcontainer role mapping.
func startCallout(ctx context.Context) (string, <-chan struct{}, error) {
	perms, err := config.Load(filepath.Join(devcontainer, "callout", "permissions.yaml"))
	if err != nil {
		return "", nil, err
	}
	// Tokens are fetched via the mapped port, so that is the issuer they carry.
	perms.Issuers[0].URL = env.keycloakURL + "/realms/test"

	issuer, err := readSeed("issuer.nk")
	if err != nil {
		return "", nil, err
	}
	xkey, err := readSeed("xkey.nk")
	if err != nil {
		return "", nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		err := app.Run(ctx, app.Options{
			NatsURL:      env.natsURL,
			AuthUser:     "auth-callout",
			AuthPassword: "auth-callout",
			IssuerSeed:   issuer,
			XKeySeed:     xkey,
			Permissions:  perms,
			Listener:     ln,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "callout stopped:", err)
		}
	}()
	return "http://" + ln.Addr().String() + "/readyz", done, nil
}

func waitReady(ctx context.Context, u string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// spyCallout observes callout traffic; a plain subscriber gets a copy next to the queue group.
func spyCallout() (*nats.Conn, error) {
	nc, err := nats.Connect(env.natsURL, nats.UserInfo("legacy", "legacy"))
	if err != nil {
		return nil, err
	}
	_, err = nc.Subscribe(app.AuthSubject, func(*nats.Msg) { env.calloutCalls.Add(1) })
	if err == nil {
		err = nc.Flush()
	}
	return nc, err
}

func readSeed(name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(devcontainer, "nkey", name))
	return []byte(strings.TrimSpace(string(b))), err
}

// calloutDelta runs f and returns how many callout requests it caused.
func calloutDelta(t *testing.T, f func()) int64 {
	t.Helper()
	before := env.calloutCalls.Load()
	f()
	// Requests are delivered asynchronously to the spy.
	time.Sleep(200 * time.Millisecond)
	return env.calloutCalls.Load() - before
}

func connect(t *testing.T, opts ...nats.Option) (*nats.Conn, error) {
	t.Helper()
	nc, err := nats.Connect(env.natsURL, append(opts, nats.MaxReconnects(0))...)
	if err == nil {
		t.Cleanup(nc.Close)
	}
	return nc, err
}

func passwordToken(t *testing.T, user, password string) string {
	t.Helper()
	return token(t, url.Values{
		"grant_type": {"password"},
		"client_id":  {"nats"},
		"username":   {user},
		"password":   {password},
	})
}

func serviceToken(t *testing.T) string {
	t.Helper()
	return token(t, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"svc-orders"},
		"client_secret": {"example-secret-do-not-use"},
	})
}

func token(t *testing.T, form url.Values) string {
	t.Helper()
	resp, err := http.PostForm(env.keycloakURL+"/realms/test/protocol/openid-connect/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(body, &tr))
	return tr.AccessToken
}

type connInfo struct {
	Name    string `json:"name"`
	User    string `json:"authorized_user"`
	Account string `json:"account"`
}

// connz asks the system account how a named connection was authorized.
func connz(t *testing.T, name string) connInfo {
	t.Helper()
	sys, err := connect(t, nats.UserInfo("sys", "sys"))
	require.NoError(t, err)
	req, _ := json.Marshal(map[string]any{"auth": true})
	msg, err := sys.Request("$SYS.REQ.SERVER.PING.CONNZ", req, 2*time.Second)
	require.NoError(t, err)

	var resp struct {
		Data struct {
			Conns []connInfo `json:"connections"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(msg.Data, &resp))
	for _, c := range resp.Data.Conns {
		if c.Name == name {
			// CONNZ omits the global account name.
			c.Account = cmp.Or(c.Account, config.GlobalAccount)
			return c
		}
	}
	t.Fatalf("connection %q not found in connz", name)
	return connInfo{}
}

// Open point: does no_auth_user still work (NACK, legacy clients) once auth callout is on?
func TestNoAuthUserBypassesCallout(t *testing.T) {
	var nc *nats.Conn
	calls := calloutDelta(t, func() {
		var err error
		nc, err = connect(t, nats.Name("anonymous"))
		require.NoError(t, err)
	})
	assert.Zero(t, calls, "anonymous connection must not hit the callout")
	ci := connz(t, "anonymous")
	assert.Equal(t, "legacy", ci.User)
	assert.Equal(t, config.GlobalAccount, ci.Account)

	sub, err := nc.SubscribeSync("legacy.ping")
	require.NoError(t, err)
	require.NoError(t, nc.Publish("legacy.ping", []byte("hi")))
	_, err = sub.NextMsg(2 * time.Second)
	assert.NoError(t, err)
}

func TestStaticUsersBypassCallout(t *testing.T) {
	nkeyOpt, err := nats.NkeyOptionFromSeed(filepath.Join(devcontainer, "nkey", "user.nk"))
	require.NoError(t, err)

	for name, opt := range map[string]nats.Option{
		"password": nats.UserInfo("legacy", "legacy"),
		"keycloak": nats.UserInfo("keycloak", "keycloak"),
		"nkey":     nkeyOpt,
	} {
		t.Run(name, func(t *testing.T) {
			calls := calloutDelta(t, func() {
				_, err := connect(t, opt)
				require.NoError(t, err)
			})
			assert.Zero(t, calls)
		})
	}
}

func TestUnknownUserIsSentToCallout(t *testing.T) {
	calls := calloutDelta(t, func() {
		_, err := connect(t, nats.UserInfo("mallory", "secret"))
		assert.ErrorIs(t, err, nats.ErrAuthorization)
	})
	assert.EqualValues(t, 1, calls)
}

// Open point: can callout users be placed in $G next to existing users and streams?
func TestTokenUserJoinsGlobalAccount(t *testing.T) {
	ctx := context.Background()
	legacy, err := connect(t, nats.UserInfo("legacy", "legacy"))
	require.NoError(t, err)
	js, err := jetstream.New(legacy)
	require.NoError(t, err)
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: "EVENTS", Subjects: []string{"events.>"}})
	require.NoError(t, err)

	asyncErr := make(chan error, 1)
	var alice *nats.Conn
	calls := calloutDelta(t, func() {
		alice, err = connect(t,
			nats.Name("alice"),
			nats.Token(passwordToken(t, "alice", "alice")),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { asyncErr <- err }),
		)
		require.NoError(t, err)
	})
	assert.EqualValues(t, 1, calls)
	assert.Equal(t, config.GlobalAccount, connz(t, "alice").Account)

	t.Run("receives messages from static users", func(t *testing.T) {
		sub, err := alice.SubscribeSync("events.created")
		require.NoError(t, err)
		require.NoError(t, alice.Flush())
		require.NoError(t, legacy.Publish("events.created", []byte("1")))
		_, err = sub.NextMsg(2 * time.Second)
		assert.NoError(t, err)
	})

	t.Run("sees streams of the global account", func(t *testing.T) {
		ajs, err := jetstream.New(alice)
		require.NoError(t, err)
		_, err = ajs.Stream(ctx, "EVENTS")
		assert.NoError(t, err)
	})

	t.Run("cannot publish outside its role", func(t *testing.T) {
		require.NoError(t, alice.Publish("orders.new", []byte("x")))
		select {
		case err := <-asyncErr:
			assert.ErrorIs(t, err, nats.ErrPermissionViolation)
		case <-time.After(2 * time.Second):
			t.Fatal("expected permissions violation")
		}
	})
}

func TestServiceAccountPublishes(t *testing.T) {
	legacy, err := connect(t, nats.UserInfo("legacy", "legacy"))
	require.NoError(t, err)
	sub, err := legacy.SubscribeSync("orders.new")
	require.NoError(t, err)
	require.NoError(t, legacy.Flush())

	svc, err := connect(t, nats.Token(serviceToken(t)))
	require.NoError(t, err)
	require.NoError(t, svc.Publish("orders.new", []byte("order")))
	_, err = sub.NextMsg(2 * time.Second)
	assert.NoError(t, err)
}

func TestRejectedTokens(t *testing.T) {
	valid := passwordToken(t, "alice", "alice")
	for name, tok := range map[string]string{
		"no roles":         passwordToken(t, "bob", "bob"),
		"forged signature": valid[:strings.LastIndex(valid, ".")+1] + "AAAA",
		"not a jwt":        "garbage",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := connect(t, nats.Token(tok))
			assert.True(t, errors.Is(err, nats.ErrAuthorization), "got %v", err)
		})
	}
}
