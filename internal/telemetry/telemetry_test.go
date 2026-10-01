package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pflege-de-labs/nats-auth-callout/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsExposed(t *testing.T) {
	m, err := New()
	require.NoError(t, err)
	m.Observe(context.Background(), auth.ResultDenied, 20*time.Millisecond)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	assert.Contains(t, body, `auth_callout_requests_total{otel_scope_name="github.com/pflege-de-labs/nats-auth-callout"`)
	assert.Contains(t, body, `result="denied"`)
	assert.Contains(t, body, "auth_callout_duration_seconds_bucket")
	assert.NoError(t, m.Shutdown(context.Background()))
}
