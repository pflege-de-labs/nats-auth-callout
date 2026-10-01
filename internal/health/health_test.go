package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func serve(h http.Handler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec
}

func TestLiveness(t *testing.T) {
	assert.Equal(t, http.StatusOK, serve(Liveness()).Code)
}

func TestReadiness(t *testing.T) {
	ok := func(context.Context) error { return nil }
	fail := func(context.Context) error { return errors.New("down") }

	assert.Equal(t, http.StatusOK, serve(Readiness(time.Second, map[string]Check{"a": ok})).Code)

	rec := serve(Readiness(time.Second, map[string]Check{"a": ok, "nats": fail}))
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "nats: down")
}
