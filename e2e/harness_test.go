//go:build e2e

// Package e2e runs the callout against real nats-server and Keycloak containers.
// Each deployment is one NATS server constellation and gets its own callout instance.
package e2e

import (
	"cmp"
	"context"
	"encoding/json"
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
	"github.com/pflege-de-labs/nats-auth-callout/internal/app"
	"github.com/pflege-de-labs/nats-auth-callout/internal/config"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const keycloakImage = "quay.io/keycloak/keycloak:26.8.0"

var devcontainer = filepath.Join("..", ".devcontainer")

// deployment is one nats-server plus the callout serving it.
type deployment struct {
	image     string
	conf      string
	perms     string
	withMQTT  bool
	natsURL   string
	mqttURL   string
	callouts  atomic.Int64
	container testcontainers.Container
}

var (
	keycloakURL string

	// global: static users in the global account ($G).
	global = &deployment{
		image: cmp.Or(os.Getenv("NATS_IMAGE"), "nats:2.12.6-alpine"),
		conf:  filepath.Join(devcontainer, "nats", "nats.conf"),
		perms: filepath.Join(devcontainer, "callout", "permissions.yaml"),
	}
	// accounts: named accounts, MQTT, no_auth_user in a named account.
	accounts = &deployment{
		image:    cmp.Or(os.Getenv("NATS_ACCOUNTS_IMAGE"), "nats:2.14.0-alpine"),
		conf:     filepath.Join("testdata", "nats-accounts.conf"),
		perms:    filepath.Join("testdata", "permissions-accounts.yaml"),
		withMQTT: true,
	}
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kc, err := startKeycloak(ctx)
	defer terminate(kc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start keycloak:", err)
		return 1
	}

	var stops []<-chan struct{}
	for _, d := range []*deployment{global, accounts} {
		err := d.start(ctx)
		defer terminate(d.container)
		if err != nil {
			fmt.Fprintf(os.Stderr, "start %s: %v\n", d.conf, err)
			return 1
		}
		done, err := d.startCallout(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "callout for %s: %v\n", d.conf, err)
			return 1
		}
		stops = append(stops, done)
	}

	code := m.Run()
	cancel()
	for _, done := range stops {
		<-done
	}
	return code
}

func terminate(c testcontainers.Container) {
	if c != nil {
		_ = testcontainers.TerminateContainer(c)
	}
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
	keycloakURL, err = c.PortEndpoint(ctx, "8080/tcp", "http")
	return c, err
}

func (d *deployment) start(ctx context.Context) error {
	ports := []string{"4222/tcp"}
	if d.withMQTT {
		ports = append(ports, "1883/tcp")
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        d.image,
			ExposedPorts: ports,
			Cmd:          []string{"-c", "/conf/nats.conf"},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      d.conf,
				ContainerFilePath: "/conf/nats.conf",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForLog("Server is ready").WithStartupTimeout(time.Minute),
		},
	})
	d.container = c
	if err != nil {
		return err
	}
	if d.natsURL, err = c.PortEndpoint(ctx, "4222/tcp", "nats"); err != nil {
		return err
	}
	if d.withMQTT {
		d.mqttURL, err = c.PortEndpoint(ctx, "1883/tcp", "tcp")
	}
	return err
}

// startCallout runs the real app wiring in-process and waits until it is ready.
func (d *deployment) startCallout(ctx context.Context) (<-chan struct{}, error) {
	perms, err := config.Load(d.perms)
	if err != nil {
		return nil, err
	}
	// Tokens are fetched via the mapped port, so that is the issuer they carry.
	perms.Issuers[0].URL = keycloakURL + "/realms/test"

	issuer, err := readSeed("issuer.nk")
	if err != nil {
		return nil, err
	}
	xkey, err := readSeed("xkey.nk")
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		err := app.Run(ctx, app.Options{
			NatsURL:      d.natsURL,
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
	if err := waitReady(ctx, "http://"+ln.Addr().String()+"/readyz"); err != nil {
		return done, err
	}
	return done, d.spyCallout()
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

// spyCallout counts callout requests; a plain subscriber gets a copy next to the queue group.
// It connects as the callout user because requests are published in the callout account.
func (d *deployment) spyCallout() error {
	nc, err := nats.Connect(d.natsURL, nats.UserInfo("auth-callout", "auth-callout"))
	if err != nil {
		return err
	}
	if _, err := nc.Subscribe(app.AuthSubject, func(*nats.Msg) { d.callouts.Add(1) }); err != nil {
		return err
	}
	return nc.Flush()
}

func readSeed(name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(devcontainer, "nkey", name))
	return []byte(strings.TrimSpace(string(b))), err
}

// calloutDelta runs f and returns how many callout requests it caused.
func (d *deployment) calloutDelta(t *testing.T, f func()) int64 {
	t.Helper()
	before := d.callouts.Load()
	f()
	// Requests are delivered asynchronously to the spy.
	time.Sleep(200 * time.Millisecond)
	return d.callouts.Load() - before
}

func (d *deployment) connect(t *testing.T, opts ...nats.Option) (*nats.Conn, error) {
	t.Helper()
	nc, err := nats.Connect(d.natsURL, append(opts, nats.MaxReconnects(0))...)
	if err == nil {
		t.Cleanup(nc.Close)
	}
	return nc, err
}

type connInfo struct {
	Name    string `json:"name"`
	User    string `json:"authorized_user"`
	Account string `json:"account"`
}

// connz asks the system account how a named connection was authorized.
func (d *deployment) connz(t *testing.T, name string) connInfo {
	t.Helper()
	sys, err := d.connect(t, nats.UserInfo("sys", "sys"))
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
	resp, err := http.PostForm(keycloakURL+"/realms/test/protocol/openid-connect/token", form)
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
