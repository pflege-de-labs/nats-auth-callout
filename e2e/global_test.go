//go:build e2e

package e2e

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/pflege-de-labs/nats-auth-callout/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Open point: does no_auth_user still work (anonymous and legacy clients) once auth callout is on?
func TestNoAuthUserBypassesCallout(t *testing.T) {
	var nc *nats.Conn
	calls := global.calloutDelta(t, func() {
		var err error
		nc, err = global.connect(t, nats.Name("anonymous"))
		require.NoError(t, err)
	})
	assert.Zero(t, calls, "anonymous connection must not hit the callout")
	ci := global.connz(t, "anonymous")
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
			calls := global.calloutDelta(t, func() {
				_, err := global.connect(t, opt)
				require.NoError(t, err)
			})
			assert.Zero(t, calls)
		})
	}
}

func TestUnknownUserIsSentToCallout(t *testing.T) {
	calls := global.calloutDelta(t, func() {
		_, err := global.connect(t, nats.UserInfo("mallory", "secret"))
		assert.ErrorIs(t, err, nats.ErrAuthorization)
	})
	assert.EqualValues(t, 1, calls)
}

// Open point: can callout users be placed in $G next to existing users and streams?
func TestTokenUserJoinsGlobalAccount(t *testing.T) {
	ctx := context.Background()
	legacy, err := global.connect(t, nats.UserInfo("legacy", "legacy"))
	require.NoError(t, err)
	js, err := jetstream.New(legacy)
	require.NoError(t, err)
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: "EVENTS", Subjects: []string{"events.>"}})
	require.NoError(t, err)

	asyncErr := make(chan error, 1)
	var alice *nats.Conn
	calls := global.calloutDelta(t, func() {
		alice, err = global.connect(t,
			nats.Name("alice"),
			nats.Token(passwordToken(t, "alice", "alice")),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { asyncErr <- err }),
		)
		require.NoError(t, err)
	})
	assert.EqualValues(t, 1, calls)
	assert.Equal(t, config.GlobalAccount, global.connz(t, "alice").Account)

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
	legacy, err := global.connect(t, nats.UserInfo("legacy", "legacy"))
	require.NoError(t, err)
	sub, err := legacy.SubscribeSync("orders.new")
	require.NoError(t, err)
	require.NoError(t, legacy.Flush())

	svc, err := global.connect(t, nats.Token(serviceToken(t)))
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
			_, err := global.connect(t, nats.Token(tok))
			assert.True(t, errors.Is(err, nats.ErrAuthorization), "got %v", err)
		})
	}
}

func shortLivedToken() (string, error) {
	return fetchToken(url.Values{
		"grant_type": {"password"},
		"client_id":  {"nats-short"},
		"username":   {"alice"},
		"password":   {"alice"},
	})
}

// The user JWT expires with the access token, so NATS drops the connection at that point.
func TestConnectionEndsWhenTokenExpires(t *testing.T) {
	tok, err := shortLivedToken()
	require.NoError(t, err)

	closed := make(chan struct{})
	start := time.Now()
	_, err = global.connect(t,
		nats.Token(tok),
		nats.ClosedHandler(func(*nats.Conn) { close(closed) }),
	)
	require.NoError(t, err)

	select {
	case <-closed:
		assert.Greater(t, time.Since(start), 2*time.Second, "closed before the token expired")
	case <-time.After(20 * time.Second):
		t.Fatal("connection still open after the token expired")
	}
}

// A token handler fetches a fresh token for every (re)connect, so expiry only causes a reconnect.
func TestTokenHandlerReconnectsWithFreshToken(t *testing.T) {
	var calls atomic.Int64
	reconnected := make(chan struct{}, 1)
	nc, err := nats.Connect(global.natsURL,
		nats.TokenHandler(func() string {
			calls.Add(1)
			tok, _ := shortLivedToken()
			return tok
		}),
		nats.ReconnectWait(200*time.Millisecond),
		nats.MaxReconnects(-1),
		nats.ReconnectHandler(func(*nats.Conn) { reconnected <- struct{}{} }),
	)
	require.NoError(t, err)
	t.Cleanup(nc.Close)

	select {
	case <-reconnected:
	case <-time.After(20 * time.Second):
		t.Fatal("client did not reconnect after its token expired")
	}
	assert.GreaterOrEqual(t, calls.Load(), int64(2))
	assert.True(t, nc.IsConnected())
}

// Browser clients use the websocket listener; the token travels in the same connect options.
func TestTokenOverWebsocket(t *testing.T) {
	var nc *nats.Conn
	calls := global.calloutDelta(t, func() {
		var err error
		nc, err = nats.Connect(global.wsURL, nats.Name("browser"), nats.Token(passwordToken(t, "alice", "alice")), nats.MaxReconnects(0))
		require.NoError(t, err)
		t.Cleanup(nc.Close)
	})
	assert.EqualValues(t, 1, calls)
	assert.Equal(t, config.GlobalAccount, global.connz(t, "browser").Account)

	sub, err := nc.SubscribeSync("events.ws")
	require.NoError(t, err)
	require.NoError(t, nc.Flush())
	static, err := global.connect(t, nats.UserInfo("legacy", "legacy"))
	require.NoError(t, err)
	require.NoError(t, static.Publish("events.ws", []byte("x")))
	_, err = sub.NextMsg(2 * time.Second)
	assert.NoError(t, err)
}
