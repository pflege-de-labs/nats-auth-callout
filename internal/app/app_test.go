package app

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/pflege-de-labs/nats-auth-callout/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func options(t *testing.T) Options {
	t.Helper()
	akp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	seed, _ := akp.Seed()
	return Options{
		// Nothing listens here; RetryOnFailedConnect keeps the app running.
		NatsURL:    "nats://127.0.0.1:1",
		AuthUser:   "auth-callout",
		IssuerSeed: seed,
		Permissions: &config.Config{
			Issuers: []config.Issuer{{URL: "http://127.0.0.1:1/realms/x", Audience: "nats"}},
			Roles:   map[string]config.Role{"r": {}},
		},
	}
}

func get(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url) // #nosec G107 -- test URL
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestRunServesProbesAndShutsDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	o := options(t)
	o.Listener = ln

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, o) }()

	base := "http://" + ln.Addr().String()
	require.Eventually(t, func() bool {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
		}
		return err == nil && resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond)
	assert.Equal(t, http.StatusServiceUnavailable, get(t, base+"/readyz"))
	assert.Equal(t, http.StatusOK, get(t, base+"/metrics"))

	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRunRejectsBadSeed(t *testing.T) {
	o := options(t)
	o.IssuerSeed = []byte("nope")
	assert.ErrorContains(t, Run(context.Background(), o), "issuer seed")
}

func TestRunRejectsBadListen(t *testing.T) {
	o := options(t)
	o.Listen = "not-an-address"
	assert.ErrorContains(t, Run(context.Background(), o), "listen")
}
