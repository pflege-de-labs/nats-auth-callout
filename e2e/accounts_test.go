//go:build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountsNoAuthUserStaysInMQTTAccount(t *testing.T) {
	calls := accounts.calloutDelta(t, func() {
		_, err := accounts.connect(t, nats.Name("anonymous"))
		require.NoError(t, err)
	})
	assert.Zero(t, calls, "anonymous connection must not hit the callout")
	ci := accounts.connz(t, "anonymous")
	assert.Equal(t, "mqtt", ci.User)
	assert.Equal(t, "MQTT", ci.Account)
}

func TestAccountsStaticUsersBypassCallout(t *testing.T) {
	for _, user := range []string{"mqtt", "audit", "sys"} {
		t.Run(user, func(t *testing.T) {
			calls := accounts.calloutDelta(t, func() {
				_, err := accounts.connect(t, nats.UserInfo(user, user))
				require.NoError(t, err)
			})
			assert.Zero(t, calls)
		})
	}
}

func TestAccountsAuditReader(t *testing.T) {
	ctx := context.Background()
	audit, err := accounts.connect(t, nats.UserInfo("audit", "audit"))
	require.NoError(t, err)
	ajs, err := jetstream.New(audit)
	require.NoError(t, err)
	_, err = ajs.CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: "AUDIT", Subjects: []string{"AUDIT.>"}})
	require.NoError(t, err)
	_, err = ajs.Publish(ctx, "AUDIT.login", []byte("alice logged in"))
	require.NoError(t, err)

	asyncErr := make(chan error, 1)
	carol, err := accounts.connect(t,
		nats.Name("carol"),
		nats.Token(passwordToken(t, "carol", "carol")),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { asyncErr <- err }),
	)
	require.NoError(t, err)
	assert.Equal(t, "AUDIT", accounts.connz(t, "carol").Account)

	t.Run("reads the AUDIT stream", func(t *testing.T) {
		js, err := jetstream.New(carol)
		require.NoError(t, err)
		s, err := js.Stream(ctx, "AUDIT")
		require.NoError(t, err)
		cons, err := s.OrderedConsumer(ctx, jetstream.OrderedConsumerConfig{})
		require.NoError(t, err)
		msgs, err := cons.Fetch(1, jetstream.FetchMaxWait(2*time.Second))
		require.NoError(t, err)
		var got []string
		for m := range msgs.Messages() {
			got = append(got, string(m.Data()))
		}
		assert.NoError(t, msgs.Error())
		assert.Equal(t, []string{"alice logged in"}, got)
	})

	t.Run("cannot delete streams", func(t *testing.T) {
		js, err := jetstream.New(carol)
		require.NoError(t, err)
		assert.Error(t, js.DeleteStream(ctx, "AUDIT"))
		_, err = ajs.Stream(ctx, "AUDIT")
		assert.NoError(t, err, "stream must still exist")
	})

	t.Run("cannot write audit events", func(t *testing.T) {
		require.NoError(t, carol.Publish("AUDIT.fake", []byte("x")))
		select {
		case err := <-asyncErr:
			assert.ErrorIs(t, err, nats.ErrPermissionViolation)
		case <-time.After(2 * time.Second):
			t.Fatal("expected permissions violation")
		}
	})
}

func mqttClient(t *testing.T, password string) (mqtt.Client, error) {
	t.Helper()
	// Any username not listed in auth_users; the password carries the token.
	return mqttClientAs(t, "token", password)
}

func mqttClientAs(t *testing.T, user, password string) (mqtt.Client, error) {
	t.Helper()
	opts := mqtt.NewClientOptions().
		AddBroker(accounts.mqttURL).
		SetClientID("e2e-" + t.Name()).
		SetUsername(user).
		SetPassword(password).
		SetAutoReconnect(false).
		SetConnectRetry(false)
	c := mqtt.NewClient(opts)
	tok := c.Connect()
	if !tok.WaitTimeout(5 * time.Second) {
		return c, context.DeadlineExceeded
	}
	if tok.Error() == nil {
		t.Cleanup(func() { c.Disconnect(100) })
	}
	return c, tok.Error()
}

func mqttWait(t *testing.T, tok mqtt.Token) {
	t.Helper()
	require.True(t, tok.WaitTimeout(5*time.Second), "mqtt operation timed out")
	require.NoError(t, tok.Error())
}

func TestAccountsMQTTWithToken(t *testing.T) {
	static, err := accounts.connect(t, nats.UserInfo("mqtt", "mqtt"))
	require.NoError(t, err)
	sub, err := static.SubscribeSync("devices.>")
	require.NoError(t, err)
	other, err := static.SubscribeSync("other.>")
	require.NoError(t, err)
	require.NoError(t, static.Flush())

	var client mqtt.Client
	calls := accounts.calloutDelta(t, func() {
		client, err = mqttClient(t, passwordToken(t, "dave", "dave"))
		require.NoError(t, err)
	})
	assert.EqualValues(t, 1, calls, "MQTT password must be sent to the callout as token")

	t.Run("publishes into the MQTT account", func(t *testing.T) {
		mqttWait(t, client.Publish("devices/hello", 0, false, "hi"))
		msg, err := sub.NextMsg(2 * time.Second)
		require.NoError(t, err)
		assert.Equal(t, "devices.hello", msg.Subject)
	})

	t.Run("receives with QoS 1", func(t *testing.T) {
		got := make(chan string, 1)
		mqttWait(t, client.Subscribe("devices/#", 1, func(_ mqtt.Client, m mqtt.Message) { got <- m.Topic() }))
		require.NoError(t, static.Publish("devices.from-nats", []byte("x")))
		select {
		case topic := <-got:
			assert.Equal(t, "devices/from-nats", topic)
		case <-time.After(5 * time.Second):
			t.Fatal("no MQTT message received")
		}
	})

	t.Run("cannot publish outside its role", func(t *testing.T) {
		_ = client.Publish("other/topic", 0, false, "x").WaitTimeout(time.Second)
		_, err := other.NextMsg(time.Second)
		assert.ErrorIs(t, err, nats.ErrTimeout)
	})
}

func TestAccountsRejects(t *testing.T) {
	t.Run("MQTT with invalid token", func(t *testing.T) {
		_, err := mqttClient(t, "garbage")
		assert.Error(t, err)
	})
	t.Run("token without a mapped role", func(t *testing.T) {
		// alice only has events-read, which this deployment does not map.
		_, err := accounts.connect(t, nats.Token(passwordToken(t, "alice", "alice")))
		assert.ErrorIs(t, err, nats.ErrAuthorization)
	})
}

func TestAccountsSelectedByUser(t *testing.T) {
	token := passwordToken(t, "erin", "erin")

	t.Run("token alone is rejected for roles in two accounts", func(t *testing.T) {
		_, err := accounts.connect(t, nats.Token(token))
		require.Error(t, err)
	})
	for _, account := range []string{"AUDIT", "MQTT"} {
		t.Run("nats user "+account, func(t *testing.T) {
			_, err := accounts.connect(t, nats.Name("erin-"+account), nats.UserInfo(account, token))
			require.NoError(t, err)
			assert.Equal(t, account, accounts.connz(t, "erin-"+account).Account)
		})
	}
	t.Run("mqtt user MQTT", func(t *testing.T) {
		client, err := mqttClientAs(t, "MQTT", token)
		require.NoError(t, err)
		mqttWait(t, client.Publish("devices/erin", 0, false, "hi"))
	})
}
